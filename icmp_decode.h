#ifndef __ICMP_DECODE_H__
#define __ICMP_DECODE_H__
#include <stdio.h>
#include <pcap.h>
#include "udp_decode.h"

void icmp_packet_decode(const struct pcap_pkthdr *h,const u_char *p,uint16_t strid);

#endif
