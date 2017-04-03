#ifndef __UDP_DECODE_H__
#define __UDP_DECODE_H__
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h> 
#include <netinet/udp.h>
#include "strintmap.h"
#include "strmap.h"
#include "sessionmap.h"

#define INCR 100
#define UDP_TIMEOUT 300
#define UDP_TIME 60
#define IP_OFFSET 14
#define MAXMAP 1000000000
#define DETECTED_PROTO_NUM 80000 

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;

void  add_ipdata_pro(u_int32_t ip, u_int64_t size, u_int16_t protoid, int flag);
void  add_ipdata_acc(u_int32_t ip, u_int64_t size, u_int16_t protoid, int flag);
void  add_ipdata_exist_num(u_int32_t ip, u_int16_t protoid,unsigned int exist_num);
void  SetExistconn(unsigned int key,IPSession value,const void *obj);
void* ExistConnCount(void *arg);
void  udp_packet_decode(const struct pcap_pkthdr *h,const u_char *p);

#endif
