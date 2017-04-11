#if 0
#include <arpa/inet.h>
#include <netinet/ip.h> 
#include <linux/icmp.h>
#include "strintmap.h"
#include "strmap.h"
#include "sessionmap.h"
#endif

#include "icmp_decode.h"

extern StrMap *proIdMap;
extern StrMap *idProMap;
extern StrMap *ipPortMap;
extern StrintMap *ipdataMap;
extern SessionMap *UDPstatusMap;
extern SessionMap *ICMPstatusMap;

/**************
 *	Function:		icmp_packet_decode
 *	Description:
 *		icmp数据包解码及统计入口函数		
 *	Parameters:
 *		packet		原始数据包	
 *		packet_len	数据包大小
 *	Returns:		void
 * *************/

void icmp_packet_decode(const struct pcap_pkthdr *h, const u_char *p,char *strid)
{
	const struct ip *ip;
	const struct icmphdr *icmp;
	uint32_t srcip,dstip;

	ip = (const struct ip *)(p+IP_OFFSET);
	uint64_t size;
	size = h->len;
	srcip = ntohl(*(uint32_t *) (&ip->ip_src));
	dstip = ntohl(*(uint32_t *) (&ip->ip_dst));

	icmp = (struct icmphdr *)(ip+1);
	icmp = (struct icmphdr *) ( ((char *)icmp) + ((ip->ip_hl-5)*4) );

	session_info *tmpinfo;
	tmpinfo = (session_info*)calloc(1,sizeof(session_info));
	if(!tmpinfo){
		printf("Packetcallback swich ICMP protocol calloc tmpinfo failed!%s(%d)\n",__FILE__,__LINE__);
		return;
	}
	tmpinfo->srcip = srcip;
	tmpinfo->dstip = dstip;
	tmpinfo->ts = h->ts;

	IPSession tmpipses;
	memset(&tmpipses,0,sizeof(IPSession));
	/* 源IP做key查询 */
	if(ssm_get(ICMPstatusMap,srcip,&tmpipses) != 1) {  /* 用源IP去UPD状态表里面查询,如果没有的话执行下面的语句块 */
		tmpipses.sessions = (session_info*)calloc(INCR,sizeof(session_info));/* 给这个IP分配会话数组空间 可以封装 */
		if(!tmpipses.sessions){
			printf("Packetcallback swich ICMP protocol calloc sessions failed!%s(%d)\n",__FILE__,__LINE__);
			return;
		}
		tmpipses.sessions_flag = (int*)calloc(INCR,sizeof(int));
		if(!tmpipses.sessions_flag){
			printf("Packetcallback swich ICMP protocol calloc sessions_flag failed!%s(%d)\n",__FILE__,__LINE__);
			return;
		}

		tmpipses.capacity = INCR;//把当前的ip和这个ip的会话放入value,执行到最下面时将会把这个ip做key,然后把Value放入ICMP状态哈希;
		tmpipses.sessions[0] = *tmpinfo;
		tmpipses.session_count++;
		add_ipdata_pro(tmpinfo->srcip, h->caplen, atoi(strid), 0);//增加新链接计数
		add_ipdata_pro(tmpinfo->dstip, h->caplen, atoi(strid), 1);

	}else{  //找到了这个ip,说明这个ip已经存在了
		if((tmpipses.session_count) == tmpipses.capacity) { //如果这个ip的会话数组已经满了,给它增长容量
			tmpipses.sessions = (session_info*)realloc(tmpipses.sessions,tmpipses.session_count + INCR);
			if(!tmpipses.sessions){
				printf("Packetcallback swich ICMP protocol realloc sessions failed!%s(%d)\n",__FILE__,__LINE__);
				return;
			}
			tmpipses.sessions_flag = (int*)realloc(tmpipses.sessions_flag,tmpipses.session_count + INCR); 
			if(!tmpipses.sessions_flag){
				printf("Packetcallback swich ICMP protocol realloc sessions_flag failed!%s(%d)\n",__FILE__,__LINE__);
				return;
			}
			tmpipses.capacity += INCR;
		}
		int i;
		int flag = 0;//找到这个四元组后置1
		for(i = 0; i < tmpipses.session_count; i++) { //遍历这个ip的所有会话
			if(!memcmp((tmpipses.sessions + i),tmpinfo,12)){//如果这个会话已经存在
				flag = 1;
				if((tmpinfo->ts.tv_sec - tmpipses.sessions[i].ts.tv_sec) > ICMP_TIMEOUT) {     //超时,虽然找到了,但原来的连接状态已经超时了,这一个算新连接,把连接计数+1
					add_ipdata_pro(tmpinfo->srcip, h->caplen, atoi(strid), 0);
					add_ipdata_pro(tmpinfo->dstip, h->caplen, atoi(strid), 1);
					tmpipses.sessions[i].ts.tv_sec = tmpinfo->ts.tv_sec;//这里是把时间更新
				}else {//如果这个会话没有超时,那么把最新的时间记录下来
					tmpipses.sessions[i].ts.tv_sec = tmpinfo->ts.tv_sec;//更新时间
					add_ipdata_acc(tmpinfo->srcip,h->caplen,atoi(strid),0);//只增加访问次数
					add_ipdata_acc(tmpinfo->dstip,h->caplen,atoi(strid),1);
				}
				break;
			}

			}//遍历完
			if(flag == 0) {//遍历完后没有找到,那么这是一个新的会话,把它放入这个IP的会话数组,把会话数加1
				int i;
				int flag = 0; /* 如果填补了超时链接的位置就置为1 */
				for(i = 0; i < tmpipses.session_count; i++) /* 先寻找一下会话数组内有没有已经超时的链接 */
				{
					if(*(tmpipses.sessions_flag + i)) {
						flag = 1;
						break;
					}
				}
				
				tmpipses.sessions[i] = *tmpinfo;
				tmpipses.sessions_flag[i] = 0;
				if(!flag) /* 当没有填补时 */
					tmpipses.session_count++;

				add_ipdata_pro(tmpinfo->srcip,h->caplen,atoi(strid),0);
				add_ipdata_pro(tmpinfo->dstip,h->caplen,atoi(strid),1);
			}
		}

		ssm_put(ICMPstatusMap,srcip,tmpipses);
		free(tmpinfo);
}
