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
#define TIMEOUT 300
#define IP_OFFSET 14
#define MAXMAP 1000000000
#define DETECTED_PROTO_NUM 80000 

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;

void  sessions_realloc(IPSession *tmpipses);
void  sessions_calloc(IPSession *tmpipses);
void  add_session(uint32_t ip,session_info *info,uint64_t len,uint16_t protoid,int flag,SessionMap *map);
void  detect_sessions(IPSession *tmpipses,session_info *tmpinfo);
void  GetExistconn(unsigned int key,IPSession value,const void *obj);
void* ExistConnCount(void *arg);
void  udp_packet_decode(const struct pcap_pkthdr *h,const u_char *p,uint16_t proid);

#endif
