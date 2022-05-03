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
#include<stdio.h>
#include "icmp.h"
#include "ip.h"
#include "utilities.h"
#include "systems_headers.h"

void icmp_rx(struct subuff *sub) {
    //FIXME: implement your ICMP packet processing implementation here
    //figure out various type of ICMP packets, and implement the ECHO response type (icmp_reply)

    struct iphdr *hdr = IP_HDR_FROM_SUB(sub);
    struct icmp *icmp = (struct icmp *) hdr->data; //find ICMP header location in the IP packet

    uint16_t in_pkt_csum = icmp->checksum;
    icmp->checksum = 0;
    int icmp_length = IP_PAYLOAD_LEN(hdr);// find ICMP data size
    uint16_t calc_csum = do_csum(icmp, icmp_length, 0);

    if(in_pkt_csum == calc_csum){
        printf("TYPE: %d, CODE: %d \n", icmp->type, icmp->code);
        switch(icmp->type){
            case 0:
                printf("ECHO response");
                icmp_reply(sub);
            case 8:
                printf("ECHO REQUEST \n");
                icmp->type = 0;
                icmp->code = 0;
                icmp->checksum = 0;
                icmp_reply(sub);
                break;
            case 3:
                printf("Destination Unreachable \n");
                break;
            case 4:
                printf("Source Quench \n");
                break;
            case 5:
                printf("Redirect \n");
                break;
            case 11:
                printf("Time Exceeded \n");
                break;
            case 12:
                printf("Parameter Problem \n");
                break;
            case 13:
                printf("Timestamp \n");
                icmp_reply(sub);
                break;
            case 14:
                printf("Timestamp Reply \n");
                break;
            case 15:
                printf("Information Request \n");
                break;
            case 16:
                printf("Information Reply \n");
                icmp_reply(sub);
                break;
        }
    }
    else{
        printf("Error: invalid checksum, dropping packet");
        //goto drop_pkt;
    }

    free_sub(sub);
}

void icmp_reply(struct subuff *sub) {
    //FIXME: implement your ICMP reply implementation here
    // preapre an ICMP response buffer
    // send it out on ip_ouput(...)

    struct iphdr *hdr = IP_HDR_FROM_SUB(sub);
    struct icmp *icmp = (struct icmp *) hdr->data; //find ICMP header location in the IP packet

    printf("OUTGOING ICMP PACKET");

    sub_reserve(sub, ETH_HDR_LEN + IP_HDR_LEN + IP_PAYLOAD_LEN(hdr));
    sub_push(sub, IP_PAYLOAD_LEN(hdr));

    sub->protocol = 1;

    int icmp_length = IP_PAYLOAD_LEN(hdr);// find ICMP data size
    icmp->checksum = do_csum(icmp, icmp_length, 0);

    ip_output(hdr->saddr, sub);

}