#ifndef __ICMP_DECODE_H__
#define __ICMP_DECODE_H__
#include <stdio.h>
#include <pcap.h>
#include "udp_decode.h"

#define ICMP_TIMEOUT 300
#define ICMP_TIME 60

void icmp_packet_decode(const struct pcap_pkthdr *h,const u_char *p,char *strid);

#endif
