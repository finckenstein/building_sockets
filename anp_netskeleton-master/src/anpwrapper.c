/*
 * Copyright [2020] [Animesh Trivedi]
 *
 * This code is part of the Advanced Network Programming (ANP) course
 * at VU Amsterdam.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

//XXX: _GNU_SOURCE must be defined before including dlfcn to get RTLD_NEXT symbols
#define _GNU_SOURCE

#include <dlfcn.h>
#include "systems_headers.h"
#include "linklist.h"
#include "anpwrapper.h"
#include "init.h"

#include "subuff.h"
#include "ip.h"
#include "config.h"
#include "ethernet.h"
#include "anp_netdev.h"
#include "route.h"
#include "arp.h"
#include "utilities.h"
#include <pthread.h>
#include <string.h>
#include <time.h>

static int (*__start_main)(int (*main) (int, char * *, char * *), int argc, \
                           char * * ubp_av, void (*init) (void), void (*fini) (void), \
                           void (rtld_fini) (void), void ( stack_end));

static ssize_t (*_send)(int fd, const void *buf, size_t n, int flags) = NULL;
static ssize_t (*_recv)(int fd, void *buf, size_t n, int flags) = NULL;

static int (*_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static int (*_socket)(int domain, int type, int protocol) = NULL;
static int (*_close)(int sockfd) = NULL;

pthread_mutex_t mutex_connect = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  condition_connect = PTHREAD_COND_INITIALIZER;

pthread_mutex_t mutex_rcv = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  condition_rcv = PTHREAD_COND_INITIALIZER;

pthread_mutex_t mutex_send = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  condition_send = PTHREAD_COND_INITIALIZER;

pthread_mutex_t mutex_close = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  condition_close = PTHREAD_COND_INITIALIZER;

static struct timespec time_to_wait;

struct list_head* fd_head;
static bool fd_list_initialised = false;

struct tcb* connection_manager;

static int is_socket_supported(int domain, int type, int protocol){
    if (domain != AF_INET){
        return 0;
    }
    if (!(type & SOCK_STREAM)) {
        return 0;
    }
    if (protocol != 0 && protocol != IPPROTO_TCP) {
        return 0;
    }
    printf("supported socket domain %d type %d and protocol %d \n", domain, type, protocol);
    return 1;
}

int generate_fd(){
    int counter = 1010;
    struct list_head* current;
    list_for_each(current, fd_head) {
        counter = counter + 1;
    }
    return counter;
}

bool is_anp_sock(int fd){
    struct list_head* current;
    list_for_each(current, fd_head) {
        if (current->fd == fd) {
            return true;
        }
    }
    return false;
}

struct list_head* fetch_socket(int fd){
    struct list_head* current;
    list_for_each(current, fd_head) {
        if (current->fd == fd) {
            return current;
        }
    }
    return NULL;
}

// TODO: ANP milestone 3 -- implement the socket, and connect calls
int socket(int domain, int type, int protocol) {
    if (!fd_list_initialised) {
        fd_head = malloc(sizeof(struct list_head));
        list_init(fd_head);
        fd_list_initialised = true;
    }

    if (is_socket_supported(domain, type, protocol)) {
        int fd = generate_fd();
        struct list_head* sock = malloc(sizeof(struct list_head));
        sock->domain = domain;
        sock->type = type;
        sock->protocol = protocol;
        sock->fd = fd;

        list_add(sock, fd_head);
        return fd;
    }
    // if this is not what anpnetstack support, let it go, let it go!
    return _socket(domain, type, protocol);
}

void initialize_connection_variables(int sockfd, uint32_t ip_dest, uint16_t dest_port){
    connection_manager->sockfd = sockfd;
    connection_manager->src_port = SRC_PORT;
    connection_manager->dst_port = dest_port;
    connection_manager->ip_dest = ip_dest;
    connection_manager->s_wnd = 60000;

    connection_manager->send_sequ_numb = 1;
    connection_manager->s_una = 1;
    connection_manager->s_nxt = connection_manager->send_sequ_numb + 1;
    connection_manager->iss = 1;
}

void initialize_tcp_hdr(struct tcp* tcp_hdr, int length, int FIN, int SYN, int RST, int PSH, int ACK, int URG){
    tcp_hdr->source_port = htons(connection_manager->src_port);
    tcp_hdr->dest_port = htons(connection_manager->dst_port);
    tcp_hdr->ack_numb = htonl(connection_manager->r_nxt);
    tcp_hdr->seq_numb = htonl(connection_manager->send_sequ_numb);
    tcp_hdr->data_offset = 5;
    tcp_hdr->FIN = FIN;
    tcp_hdr->SYN = SYN;
    tcp_hdr->RST = RST;
    tcp_hdr->PSH = PSH;
    tcp_hdr->ACK = ACK;
    tcp_hdr->URG = URG;
    tcp_hdr->window = 60000;
    tcp_hdr->checksum = do_tcp_csum((uint8_t*)tcp_hdr, TCP_HDR_LEN+length, IPP_TCP, htonl(167772164), htonl(connection_manager->ip_dest));
    tcp_hdr->urgent_ptr = 0;
    tcp_hdr->reserved_1 = 0;
    tcp_hdr->reserved_2 = 0;
}
int tcp_rx(struct subuff* sub){
    struct tcp* tcp_hdr = TCP_HDR_FROM_SUB(sub);
    struct iphdr* ip_hdr = IP_HDR_FROM_SUB(sub);

    if(tcp_hdr->ACK == 1 && tcp_hdr->SYN == 1 && ntohl(tcp_hdr->ack_numb) == 2 && connection_manager->state == "SYN-SENT"){
        free(sub);

        connection_manager->rcv_sequ_numb = ntohl(tcp_hdr->seq_numb);
        connection_manager->r_wnd = tcp_hdr->window;
        connection_manager->r_nxt = ntohl(tcp_hdr->seq_numb) + 1;
        connection_manager->irs = ntohl(tcp_hdr->seq_numb);

        struct subuff* new_sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        sub_reserve(new_sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        new_sub->protocol = IPP_TCP;

        connection_manager->send_sequ_numb = connection_manager->s_nxt;

        struct tcp* new_tcp = (struct tcp *) sub_push(new_sub, TCP_HDR_LEN);
        initialize_tcp_hdr(new_tcp, 0, 0,0,0,0,1,0);
        ip_output(ip_hdr->saddr, new_sub);

        //Signal connect() that it can return from connect call.
        pthread_cond_signal(&condition_connect);
    }
    else if((IP_PAYLOAD_LEN(ip_hdr) - tcp_hdr->data_offset * 4) > 0 && connection_manager->r_nxt == ntohl(tcp_hdr->seq_numb) && connection_manager->r_wnd1 != 0){
        int data_length = IP_PAYLOAD_LEN(ip_hdr) - tcp_hdr->data_offset * 4;

        connection_manager->r_nxt = ntohl(tcp_hdr->seq_numb) + data_length;
        connection_manager->send_sequ_numb = connection_manager->s_nxt;

        memcpy(connection_manager->buf + connection_manager->r_byte_count, TCP_PAYLOAD_FROM_SUB(sub), data_length);

        connection_manager->r_byte_count = connection_manager->r_byte_count + data_length;
        connection_manager->rcv_sequ_numb = ntohl(tcp_hdr->seq_numb);

        struct subuff* new_sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        sub_reserve(new_sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        new_sub->protocol = IPP_TCP;

        struct tcp* new_tcp = (struct tcp *) sub_push(new_sub, TCP_HDR_LEN);
        initialize_tcp_hdr(new_tcp, 0, 0,0,0,0,1,0);
        ip_output(connection_manager->ip_dest, new_sub);

        if(tcp_hdr->PSH == 1 || connection_manager->r_byte_count >= connection_manager->r_wnd1){
            pthread_cond_signal(&condition_rcv);
        }
    }
    else if(ntohl(tcp_hdr->ack_numb) == connection_manager->s_una && connection_manager->state == "ESTABLISHED"){
        pthread_cond_signal(&condition_send);
    }
    else if(tcp_hdr->FIN == 1 && tcp_hdr->ACK == 1 && connection_manager->state == "FIN-WAIT-1"){
        connection_manager->state = "TIME-WAIT";
        pthread_cond_signal(&condition_close);
    }
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen){
    if(is_anp_sock(sockfd)){
        struct subuff* sub;
        struct sockaddr_in* addr_in = (struct sockaddr_in*) addr;
        struct tcp *tcp_hdr;
        uint32_t ip_dest = ntohl((uint32_t)addr_in->sin_addr.s_addr);
        connection_manager = calloc(1, sizeof(struct tcb));
        connection_manager->buf = calloc(60000, sizeof(ssize_t));

        initialize_connection_variables(sockfd, ip_dest, ntohs(addr_in->sin_port));

        int numOfTries = 0;
        int ip_return = 0;
        do{
            sub = alloc_sub(ETH_HDR_LEN+IP_HDR_LEN+TCP_HDR_LEN);
            sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
            sub->protocol = IPP_TCP;

            tcp_hdr = (struct tcp *) sub_push(sub, TCP_HDR_LEN);
            initialize_tcp_hdr(tcp_hdr, 0, 0,1,0,0,0,0);
            ip_return = ip_output(ip_dest, sub);
            sleep(1);
            ++numOfTries;
            free(sub);
        }while(numOfTries < 3 && ip_return == -11);

        if(numOfTries >= 3){
            free(connection_manager);
            return ENETUNREACH;
        }
        else{
            connection_manager->state = "SYN-SENT";
            //Wait for [S.] packet to arrive. Once signaled, 3-way handshake is complete.
            time_to_wait.tv_sec = time(NULL) + 5;
            int error_handling = pthread_cond_timedwait(&condition_connect, &mutex_connect, &time_to_wait);
            if(error_handling == 0){
                connection_manager->state = "ESTABLISHED";
                return 0;
            }
            else{ return -1; }
        }
    }
    // the default path
    return _connect(sockfd, addr, addrlen);
}

int determine_length(int len){
    if(len > ANP_MTU_15_MAX_SIZE){
        return (ANP_MTU_15 - (ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN));
    }
    else if(connection_manager->r_wnd < len){
        return connection_manager->r_wnd;
    }
    else{
        return len;
    }
}

// TODO: ANP milestone 5 -- implement the send, recv, and close calls
ssize_t send(int sockfd, const void *buf, size_t len, int flags){

    if(is_anp_sock(sockfd) && connection_manager->state == "ESTABLISHED") {
        int length = determine_length(len);
        if(connection_manager->s_wnd1 < len){
            connection_manager->s_wnd1 = len;
        }
        int error_handling = -1;
        int numOfTries = 0;
        struct subuff* sub;
        uint8_t* temp_buf;
        struct tcp* tcp_hdr;

        do{
            sub = alloc_sub(ANP_MTU_15);
            sub->protocol = IPP_TCP;
            sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN + length);

            temp_buf = (uint8_t*)sub_push(sub, length);
            memcpy(temp_buf, buf, length);

            connection_manager->send_sequ_numb = connection_manager->s_nxt;
            connection_manager->s_nxt = connection_manager->send_sequ_numb + length;
            connection_manager->s_una = connection_manager->s_nxt;

            tcp_hdr = (struct tcp *) sub_push(sub, TCP_HDR_LEN);

            if((connection_manager->s_nxt - connection_manager->iss) >= connection_manager->s_wnd1){
                initialize_tcp_hdr(tcp_hdr, length, 0,0,0,1,1,0);
            }
            else{ initialize_tcp_hdr(tcp_hdr, length, 0,0,0,0,1,0); }

            ip_output(connection_manager->ip_dest, sub);
            ++numOfTries;
            time_to_wait.tv_sec = time(NULL) + 5;
            error_handling = pthread_cond_timedwait(&condition_send, &mutex_send, &time_to_wait);

        }while(error_handling != 0 && numOfTries < 3);

        connection_manager->s_una = NULL;

        if(numOfTries >=3){
            return -1;
        }
        return length;
    }
    // the default path
    return _send(sockfd, buf, len, flags);
}

ssize_t recv (int sockfd, void *buf, size_t len, int flags){
    if(is_anp_sock(sockfd) && connection_manager->state == "ESTABLISHED") {
        printf("WE ARE IN THE RECV FUNCTION\n");
        printf("RECEIVE LENGTH: %d\n", len);

        connection_manager->r_wnd1 = len;

        time_to_wait.tv_sec = time(NULL) + 10;
        int error_handling = pthread_cond_timedwait(&condition_rcv, &mutex_rcv, &time_to_wait);

        if(error_handling != 0){
            return -1;
        }

        memcpy(buf, connection_manager->buf, connection_manager->r_byte_count);

        printf("RETURN FROM RECV: %d\n\n", connection_manager->r_byte_count);
        int temp_bytes = connection_manager->r_byte_count;
        connection_manager->r_byte_count = 0;
        connection_manager->r_wnd1 = 0;
        return temp_bytes;
    }
    // the default path
    return _recv(sockfd, buf, len, flags);
}

int close (int sockfd){
    if(is_anp_sock(sockfd)) {

        struct subuff* sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        sub->protocol = IPP_TCP;

        struct tcp* tcp_hdr = (struct tcp *) sub_push(sub, TCP_HDR_LEN);
        initialize_tcp_hdr(tcp_hdr, 0, 1,0,0,0,1,0);
        ip_output(connection_manager->ip_dest, sub);

        connection_manager->state = "FIN-WAIT-1";

        time_to_wait.tv_sec = time(NULL) + 5;
        int error_handling = pthread_cond_timedwait(&condition_close, &mutex_close, &time_to_wait);

        if(error_handling != 0){
            return -1;
        }
        connection_manager->send_sequ_numb = connection_manager->send_sequ_numb + 1;
        connection_manager->s_nxt = connection_manager->send_sequ_numb + 1;

        sub = alloc_sub(ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN);
        sub->protocol = IPP_TCP;

        tcp_hdr = (struct tcp *) sub_push(sub, TCP_HDR_LEN);
        initialize_tcp_hdr(tcp_hdr, 0, 0,0,0,0,1,0);
        ip_output(connection_manager->ip_dest, sub);

        free(connection_manager);
        list_del(fetch_socket(sockfd));

        return 0;
    }
    // the default path
    return _close(sockfd);
}

void _function_override_init()
{
    __start_main = dlsym(RTLD_NEXT, "_libc_start_main");
    _socket = dlsym(RTLD_NEXT, "socket");
    _connect = dlsym(RTLD_NEXT, "connect");
    _send = dlsym(RTLD_NEXT, "send");
    _recv = dlsym(RTLD_NEXT, "recv");
    _close = dlsym(RTLD_NEXT, "close");
}
