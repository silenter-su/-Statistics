#ifndef	__TCP_DECODE_H__
#define __TCP_DECODE_H__

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <unistd.h>
#include "decode_head.h"

#define IP_HEADER_LEN		20			//IP数据包头长度
#define TCP_HEADER_LEN		20			//TCP数据包头长度
#define UDP_HEADER_LEN		8
#define ICMP_HEADER_LEN		4
#define	ICMP_NORMAL_LEN		8

#define SNAP_LEN			1518		//以太网帧最大长度
#define SIZE_ETHERNET		14			//以太网包头长度 mac:6*2 type:2
//#define ETHER_ADDR_LEN		6			//mac地址长度

#define IP_RF		0x8000
#define IP_DF		0x4000
#define IP_MF		0x2000
#define OFFMASK		0x1fff

#define ENTHERNET_TYPE_IP	0x0800

//these are bits in th_flags:
#if 0
#define	TH_FIN		0x01
#define TH_SYN		0X02
#define TH_RST		0x04
#define TH_PUSH		0x08
#define TH_ACK		0x10
#define TH_URG		0x20
#define	TH_ECH		0x40
#define TH_CWR		0x80
#endif

#define IP_HL(ip)		(((ip)->ip_verhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_verhl) >> 4)
#define TH_OFF(th)		(((th)->offx2 & 0xf0 ) >> 4)

//#define FILE_PATH		"/tmp/protocol"
//#define FILE_NAME		"tcpcount"

typedef unsigned char		uint8_t;
typedef unsigned short		uint16_t;
typedef unsigned int		uint32_t;

//数据包类型及大小结构体
struct packet_statistic{
	uint8_t		connect;		//标识数据包是否为tcp新连接数据包：1-新连接，0-正常数据包
	uint8_t		close;			//标识数据包是滞为tcp断开连接数据包：1-断开连接，0-正常数据包
	uint16_t	packet_size;	//数据包的大小
};

void tcp_packet_decode(const uint8_t *packet,uint64_t packet_len);

#endif
