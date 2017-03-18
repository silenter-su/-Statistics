#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>
#include "tcp_decode.h"


extern StrMap *proIdMap;
extern StrMap *idProMap;
extern StrMap *ipPortMap;
extern StrintMap *ipdataMap;


/*************
 * Function:		check_new_connect	
 * Description:		
 *		检测是否是tcp新连接	
 *	Parameters:
 *		tcphead		tcp头指针 
 *	Returns:
 *		0		不是新连接	
 *		1		新连接	
 *
 * ***********/
static int check_new_connect(struct tcphdr *tcphead)
{
	if(tcphead == NULL)
	  return 0;
	if(tcphead->syn && tcphead->ack){
		return 1;
	}
	return 0;
}

/*************
 * Function:		check_close_connect
 * Description:		
 *		检测是否是tcp断开连接	
 *	Parameters:
 *		tcphead		tcp头指针 
 *	Returns:
 *		0		正常数据包
 *		1		断开连接	
 *
 * ***********/

static int check_close_connect(struct tcphdr *tcphead)
{
	if(tcphead == NULL){
		return 0;
	}
	if(tcphead->ack && tcphead->fin){
		return 1;
	}
	return 0;
}

/**************
 *	Function:		add_ipdata
 *	Description:
 *		统计每个IP地址发送，接收的数据包大小，建立的连接数，存在的连接数，并以ip地址作为key将每个ip地址的统计信息添加到hash表中
 *	Parameters:
 *		ip			ip地址
 *		stat		统计信息结构体
 *		protoid		协议对应的下标ID
 *		flag		标识接收或发送端(0:发送端，1:接收端)
 *	Returns:		void
 *
 * *************/
void add_ipdata(uint32_t ip,struct packet_statistic stat,uint16_t protoid,int flag)
{
	struct IPData ipstats;

	if(ip == 0){
		return ;
	}
	memset(&ipstats,0,sizeof(struct IPData));
	if(smint_get(ipdataMap,ip,&ipstats) != 1){
		if(flag == 0){
			ipstats.stats[protoid].sendsize = stat.packet_size;
			ipstats.stats[protoid].accesstimes = 1;
			if(stat.connect){
				ipstats.stats[protoid].newconn = 1;
				ipstats.stats[protoid].existconn = 1;
			}
			if(stat.close){
				ipstats.stats[protoid].existconn = 0;
			}
		}else if(flag == 1){
			ipstats.stats[protoid].recvsize = stat.packet_size;
			if(stat.connect){
				ipstats.stats[protoid].newconn = 1;
				ipstats.stats[protoid].existconn = 1;
			}
			
		}
	}else{
		if(flag == 0){
			ipstats.stats[protoid].sendsize += stat.packet_size;
			ipstats.stats[protoid].accesstimes += 1;
			if(stat.connect){
				ipstats.stats[protoid].newconn += 1;
				ipstats.stats[protoid].existconn += 1;
			}
			if(stat.close){
				if(ipstats.stats[protoid].existconn > 0){
					ipstats.stats[protoid].existconn -= 1;
				}else{
					ipstats.stats[protoid].existconn = 0 ;
				}
			}
		}else if(flag == 1){
			ipstats.stats[protoid].recvsize += stat.packet_size;
			if(stat.connect){
				ipstats.stats[protoid].newconn += 1;
				ipstats.stats[protoid].existconn += 1;
			}
		}	
	}
	ipstats.stats[protoid].protoid = protoid;
	smint_put(ipdataMap,ip,ipstats);
	return;

}

/**************
 *	Function:		tcp_packet_decode
 *	Description:
 *		tcp数据包解码及统计入口函数		
 *	Parameters:
 *		packet		原始数据包	
 *		packet_len	数据包大小
 *	Returns:		void
 * *************/

void tcp_packet_decode(const uint8_t *packet,uint64_t packet_len)
{
	//uint16_t sport,dport;
	uint32_t srcip,dstip;
	struct iphdr *ip;
	struct tcphdr *tcphead;
	char strid[8];
	struct packet_statistic statist;

	if(packet == NULL || packet_len <= 0)
	  return;
	
	ip = (struct iphdr *)(packet + SIZE_ETHERNET);
	tcphead = (struct tcphdr *)(packet + SIZE_ETHERNET +((ip->ihl)*4));
	srcip = ntohl(ip->saddr);
	dstip = ntohl(ip->daddr);
	//sport = ntohs(tcphead->th_sport);
	//dport = ntohs(tcphead->th_dport);

	memset(&statist,0,sizeof(struct packet_statistic));
	if(check_new_connect(tcphead)){
		statist.connect = 1;	
	}else{
		statist.connect = 0;
	}
	if(check_close_connect(tcphead)){
		statist.close = 1;
	}else{
		statist.close = 0;
	}
	statist.packet_size = packet_len;

	add_ipdata(srcip,statist,0,0);
	add_ipdata(dstip,statist,0,1);
	if(sm_get(proIdMap,"tcp",strid,sizeof(strid)) == 1){
		add_ipdata(srcip,statist,atoi(strid),0);
		add_ipdata(dstip,statist,atoi(strid),1);
	}
}

