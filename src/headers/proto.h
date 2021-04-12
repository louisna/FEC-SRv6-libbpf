/*
 * Copyright (c) 2015 PLUMgrid, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __BCC_PROTO_H
#define __BCC_PROTO_H

//#include <uapi/linux/if_ether.h>
//#include <linux/if_ether.h>

#define BPF_PACKET_HEADER __attribute__((packed)) //__attribute__((deprecated("packet")))

struct ethernet_t {
  unsigned long long  dst:48;
  unsigned long long  src:48;
  __u32        type:16;
} BPF_PACKET_HEADER;

struct dot1q_t {
  __u16 pri:3;
  __u16 cfi:1;
  __u16 vlanid:12;
  __u16 type;
} BPF_PACKET_HEADER;

struct arp_t {
  __u16      htype;
  __u16      ptype;
  __u8       hlen;
  __u8       plen;
  __u16      oper;
  unsigned long long  sha:48;
  unsigned long long  spa:32;
  unsigned long long  tha:48;
  __u32        tpa;
} BPF_PACKET_HEADER;

struct ip_t {
  __u8   ver:4;           // byte 0
  __u8   hlen:4;
  __u8   tos;
  __u16  tlen;
  __u16  identification; // byte 4
  __u16  ffo_unused:1;
  __u16  df:1;
  __u16  mf:1;
  __u16  foffset:13;
  __u8   ttl;             // byte 8
  __u8   nextp;
  __u16  hchecksum;
  __u32    src;            // byte 12
  __u32    dst;            // byte 16
} BPF_PACKET_HEADER;

struct icmp_t {
  __u8   type;
  __u8   code;
  __u16  checksum;
} BPF_PACKET_HEADER;

struct ip6_t {
  __u32        ver:4;
  __u32        priority:8;
  __u32        flow_label:20;
  __u16      payload_len;
  __u8       next_header;
  __u8       hop_limit;
  unsigned long long  src_hi;
  unsigned long long  src_lo;
  unsigned long long  dst_hi;
  unsigned long long  dst_lo;
} BPF_PACKET_HEADER;

struct ip6_addr_t {
  __u8       addr[16];
} BPF_PACKET_HEADER;

struct ip6_opt_t {
  __u8  next_header;
  __u8  ext_len;
  __u8  pad[6];
} BPF_PACKET_HEADER;

struct icmp6_t {
  __u8   type;
  __u8   code;
  __u16  checksum;
} BPF_PACKET_HEADER;

struct udp_t {
  __u16 sport;
  __u16 dport;
  __u16 length;
  __u16 crc;
} BPF_PACKET_HEADER;

struct tcp_t {
  __u16  src_port;   // byte 0
  __u16  dst_port;
  __u32    seq_num;    // byte 4
  __u32    ack_num;    // byte 8
  __u8   offset:4;    // byte 12
  __u8   reserved:4;
  __u8   flag_cwr:1;
  __u8   flag_ece:1;
  __u8   flag_urg:1;
  __u8   flag_ack:1;
  __u8   flag_psh:1;
  __u8   flag_rst:1;
  __u8   flag_syn:1;
  __u8   flag_fin:1;
  __u16  rcv_wnd;
  __u16  cksum;      // byte 16
  __u16  urg_ptr;
} BPF_PACKET_HEADER;

struct tcp2_t {
  __u16 src_port;
  __u16 dst_port;
  __u32    seq_num;    // byte 4
  __u32    ack_num;    // byte 8
  __u8   offset:4;    // byte 12
  __u8   reserved:4;
  __u8   flags;
  __u16  rcv_wnd;
  __u16  cksum;      // byte 16
  __u16  urg_ptr;
} BPF_PACKET_HEADER;

struct vxlan_t {
  __u32 rsv1:4;
  __u32 iflag:1;
  __u32 rsv2:3;
  __u32 rsv3:24;
  __u32 key:24;
  __u32 rsv4:8;
} BPF_PACKET_HEADER;

struct vxlan_gbp_t {
  __u32 gflag:1;
  __u32 rsv1:3;
  __u32 iflag:1;
  __u32 rsv2:3;
  __u32 rsv3:1;
  __u32 dflag:1;
  __u32 rsv4:1;
  __u32 aflag:1;
  __u32 rsv5:3;
  __u32 tag:16;
  __u32 key:24;
  __u32 rsv6:8;
} BPF_PACKET_HEADER;

struct ip6_srh_t {
  __u8 nexthdr;
  __u8 hdrlen;
  __u8 type;
  __u8 segments_left;
  __u8 first_segment;
  __u8 flags;
  __u16 tag;
	
  struct ip6_addr_t segments[0];
} BPF_PACKET_HEADER;


struct sr6_tlv_t {
    __u8 type;
    __u8 len;
    __u8 value[0];
} BPF_PACKET_HEADER;

struct sr6_tlv_128 {
    __u8 type;
    __u8 len;
    __u8 reserved;
    __u8 flags;
    __u8 value[16];
} BPF_PACKET_HEADER;

struct sr6_tlv_hmac {
    __u8 type;
    __u8 len;
    __u16 reserved;
    __u32 keyid;
    __u8 hmac[32];
} BPF_PACKET_HEADER;

#define SR6_FLAG_PROTECTED (1 << 6)
#define SR6_FLAG_OAM (1 << 5)
#define SR6_FLAG_ALERT (1 << 4)
#define SR6_FLAG_HMAC (1 << 3)

#define SR6_TLV_INGRESS 1
#define SR6_TLV_EGRESS 2
#define SR6_TLV_OPAQ 3
#define SR6_TLV_PADDING 4
#define SR6_TLV_HMAC 5
#define SR6_TLV_NSH 6


static __attribute__((always_inline)) struct ip6_srh_t *get_srh(struct __sk_buff *skb);
#endif
