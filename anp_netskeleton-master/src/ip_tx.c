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

#include "systems_headers.h"
#include "ip.h"
#include "utilities.h"
#include "route.h"
#include "subuff.h"
#include "anp_netdev.h"
#include "arp.h"

#include "anpwrapper.h"

void debug_route_cache(struct rtentry* rt){
    printf("ROUTE (dst: %hhu.%hhu.%hhu.%hhu, gateway: %hhu.%hhu.%hhu.%hhu, netmask: %hhu.%hhu.%hhu.%hhu, flags: %d\n", rt->dst >> 24, rt->dst >> 16, rt->dst >> 8, rt->dst >> 0, rt->gateway >> 24, rt->gateway >> 16, rt->gateway >> 8, rt->gateway >> 0, rt->netmask >> 24, rt->netmask >> 16, rt->netmask >> 8, rt->netmask >> 0, rt->flags);
}

void debug_anp_netdev(struct anp_netdev* dev){
    printf("ANP_NETDEV (addr: %hhu.%hhu.%hhu.%hhu, addr_len: %d, hwadd: %.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx:%.2hhx, mtu: %d\n", dev->addr >> 24, dev->addr >> 16, dev->addr >> 8, dev->addr >> 0, dev->addr_len, dev->hwaddr[0], dev->hwaddr[1], dev->hwaddr[2], dev->hwaddr[3], dev->hwaddr[4], dev->hwaddr[5], dev->mtu);
}

void ip_send_check(struct iphdr *ihdr)
{
    uint32_t csum = do_csum(ihdr, ihdr->ihl * 4, 0);
    ihdr->csum = csum;
}

int dst_neigh_output(struct subuff *sub)
{
    struct iphdr *iphdr = IP_HDR_FROM_SUB(sub);
    struct anp_netdev *anp_netdev = sub->dev;
    struct rtentry *rt = sub->rt;
    uint32_t dst_addr = ntohl(iphdr->daddr);
    uint32_t src_addr = ntohl(iphdr->saddr);

    uint8_t *target_dst_mac;

    if (rt->flags & RT_GATEWAY) {
        // in case, we are not briged but NAT'ed with a gateway
        //printf("DST_ADDR CHANGED FROM: %hhu.%hhu.%hhu.%hhu TO: %hhu.%hhu.%hhu.%hhu\n", dst_addr >> 24, dst_addr >> 16, dst_addr >> 8, dst_addr >> 0, rt->gateway >> 24, rt->gateway >> 16, rt->gateway >> 8, rt->gateway >> 0);
        dst_addr = rt->gateway;
    }
    target_dst_mac = arp_get_hwaddr(dst_addr);
    debug_route_cache(rt);
    debug_anp_netdev(anp_netdev);

    //printf("target_dst_mac :%.2hhx:\n", target_dst_mac);

    if (target_dst_mac) {
        //printf("CALLING netdev_transmit FROM dst_neigh_output\n");
        return netdev_transmit(sub, target_dst_mac, ETH_P_IP);
    } else {
        //printf("CALLING arp_request FROM dst_neigh_output\n");
        //printf("src_addr: %hhu.%hhu.%hhu.%hhu, dst_addr: %hhu.%hhu.%hhu.%hhu\n", src_addr >> 24, src_addr >> 16, src_addr >> 8, src_addr >> 0, dst_addr >> 24, dst_addr >> 16, dst_addr >> 8, dst_addr >> 0);
        arp_request(src_addr, dst_addr, anp_netdev);
        return -EAGAIN;
    }
}

int ip_output(uint32_t dst_ip_addr, struct subuff *sub)
{
    struct rtentry *rt;
    struct iphdr *ihdr = IP_HDR_FROM_SUB(sub);

    rt = route_lookup(dst_ip_addr);

    if (!rt) {
        printf("IP output route lookup failed \n");
        return -1;
    }

    sub->dev = rt->dev;
    sub->rt = rt;

    sub_push(sub, IP_HDR_LEN);

    ihdr->version = IPP_NUM_IP_in_IP;
    ihdr->ihl = 0x05;
    ihdr->tos = 0;
    ihdr->len = sub->len;
    ihdr->id = ihdr->id;
    ihdr->frag_offset = 0x4000;
    ihdr->ttl = 64;
    ihdr->proto = sub->protocol;
    ihdr->saddr = sub->dev->addr;
    ihdr->daddr = dst_ip_addr;
    ihdr->csum = 0;

    debug_ip_hdr("out", ihdr);

    ihdr->len = htons(ihdr->len);
    ihdr->id = htons(ihdr->id);
    ihdr->daddr = htonl(ihdr->daddr);
    ihdr->saddr = htonl(ihdr->saddr);
    ihdr->csum = htons(ihdr->csum);
    ihdr->frag_offset = htons(ihdr->frag_offset);

    ip_send_check(ihdr);
    return dst_neigh_output(sub);
}

