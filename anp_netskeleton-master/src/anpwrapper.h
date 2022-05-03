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

#include "subuff.h"
#include "ethernet.h"
#include "ip.h"

struct tcb{
    int sockfd;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t ip_dest;
    uint8_t *buf;
    char* state;

    uint32_t send_sequ_numb;
    uint32_t s_una; //send unacknowledged
    uint32_t s_nxt; //send next
    uint32_t s_wnd; //send window
    uint32_t s_wnd1;
    uint32_t iss; //initial send sequence number

    uint32_t rcv_sequ_numb;
    uint32_t r_nxt; //receive next
    uint32_t r_wnd; //receive window
    uint32_t r_wnd1;
    uint32_t irs; //initial receive sequence number
    int r_byte_count;
};

struct tcp{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_numb;
    uint32_t ack_numb;
    uint8_t reserved_1 : 4;
    uint8_t data_offset : 4;
    uint8_t FIN : 1;
    uint8_t SYN : 1;
    uint8_t RST : 1;
    uint8_t PSH : 1;
    uint8_t ACK : 1;
    uint8_t URG : 1;
    uint8_t reserved_2 : 2;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} __attribute__((packed));

#ifndef ANPNETSTACK_ANPWRAPPER_H
#define ANPNETSTACK_ANPWRAPPER_H
#define TCP_HDR_LEN sizeof(struct tcp)
#define TCP_HDR_FROM_SUB(_sub) (struct tcp*) (_sub->head + ETH_HDR_LEN + IP_HDR_LEN)
#define SRC_PORT 999
#define TCP_PAYLOAD_FROM_SUB(_sub) (uint8_t*) (_sub->head + ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN)

void _function_override_init();
int tcp_rx(struct subuff* sub);

#endif //ANPNETSTACK_ANPWRAPPER_H
