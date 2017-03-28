#ifndef __UDP_DECODE_H__
#define __UDP_DECODE_H__
#include <stdio.h>
#include <pcap.h>

#define INCR_100
#define UDP_TIMEOUT 300
#define UDP_TIME 60
#define ICMP_TIME 60

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;


void udp_packet_decode(const struct pcap_pkthdr *h,const u_char *p);

void* ExistConnCount(void *arg);

#endif
