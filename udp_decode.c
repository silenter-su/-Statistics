#include <arpa/inet.h>
#include <netinet/ip.h> 
#include <linux/udp.h>
#include "strintmap.h"
#include "strmap.h"
#include "sessionmap.h"
#include "udp_decode.h"

extern StrMap *proIdMap;
extern StrMap *idProMap;
extern StrMap *ipPortMap;
extern StrintMap *ipdataMap;
extern SessionMap *UDPstatusMap;

#define IP_OFFSET 14
#define INCR 100

/*************
 * Function:		add_ipdata_pro
 * Description:		
 *		增加IPData表中相应协议的计数.
 *	Parameters:
 *		ip		当前ip.
 *		size	当前数据帧大小.
 *		protoid	当前协议.
 *		flag	标识源ip还是目的ip.
 *	Returns:	void.
 * ***********/
void  add_ipdata_pro(u_int32_t ip, u_int64_t size, u_int16_t protoid, int flag)
{
	struct IPData ipstats;
	memset(&ipstats, 0, sizeof(struct IPData));

	if (smint_get(ipdataMap, ip, &ipstats) != 1) {
		if (flag == 0) {
			ipstats.stats[protoid].sendsize += size;
			ipstats.stats[protoid].newconn ++;
			ipstats.stats[protoid].accesstimes ++;
		}
		if (flag == 1) {
			ipstats.stats[protoid].recvsize += size;
			ipstats.stats[protoid].newconn ++;
			ipstats.stats[protoid].accesstimes ++;
		}
	} else {
		if (flag == 0) {
			ipstats.stats[protoid].sendsize += size;
			ipstats.stats[protoid].accesstimes++;
		}
		if (flag == 1) {
			ipstats.stats[protoid].recvsize += size;
			ipstats.stats[protoid].accesstimes ++;
		}

	}
	ipstats.stats[protoid].protoid = protoid;

	smint_put(ipdataMap, ip, ipstats); 

	return ;
}

/**************
 *	Function:		add_ipdata_acc
 *	Description:
 *		增加ipdata中ip的访问次数.
 *	Parameters:
 *		ip		当前ip.
 *		size	当前数据帧大小.
 *		protoid	当前协议id号.
 *		flag	区分源ip目的ip.
 *	Returns:		void
 * *************/

void  add_ipdata_acc(u_int32_t ip, u_int64_t size, u_int16_t protoid, int flag)
{
	struct IPData ipstats;
	memset(&ipstats, 0, sizeof(struct IPData));

	if (smint_get(ipdataMap, ip, &ipstats) != 1) {
		if (flag == 0) {
			ipstats.stats[protoid].sendsize += size;
			ipstats.stats[protoid].accesstimes ++;
		}
		if (flag == 1) {
			ipstats.stats[protoid].recvsize += size;
			ipstats.stats[protoid].accesstimes ++;
		}
	} else {
		if (flag == 0) {
			ipstats.stats[protoid].sendsize += size;
			ipstats.stats[protoid].accesstimes++;
		}
		if (flag == 1) {
			ipstats.stats[protoid].recvsize += size;
			ipstats.stats[protoid].accesstimes ++;
		}

	}
	ipstats.stats[protoid].protoid = protoid;
	smint_put(ipdataMap, ip, ipstats); 
	return ;
}

/**************
 *	Function:		add_ipdata_exist_num	
 *	Description:
 *		设置IPData当前ip的已存在链接数.
 *	Parameters:
 *		ip			源IP.
 *		protoid		解析后的协议号(stats[]数组下标).
 *		exit_num	已存在的链接数.
 *	Returns:		void
 * *************/

void  add_ipdata_exist_num(u_int32_t ip, u_int16_t protoid,unsigned int exist_num)
{
	struct IPData ipstats;
	memset(&ipstats, 0, sizeof(struct IPData));
	if (smint_get(ipdataMap, ip, &ipstats)) {
		ipstats.stats[protoid].existconn = exist_num;
		struct in_addr cip;
		memset(&cip,0,sizeof(struct in_addr));
		cip.s_addr = ntohl(ip);
		
		printf("Now IP:%s exist UDP connction number is %d!\n",inet_ntoa(cip),exist_num);
	}
	return ;
}

/**************
 *	Function:		SetExistconn	
 *	Description:
 *		检查当前ip当前存在的链接数
 *	Parameters:
 *		key		当前的源IP
 *		value	当前源IP的会话数组
 *		obj		协议字符串
 *	Returns:		void
 * *************/

void SetExistconn(unsigned int key,IPSession value,const void *obj)
{
	unsigned int exist_num = 0;
	int i = 0;
	struct timeval tv;
	const char *protocol = obj;
	char strid[8];

	gettimeofday(&tv,NULL);

	for(i = 0; i < value.session_count; i++){
		if((tv.tv_sec - ((*(value.sessions + i)).ts.tv_sec)) < UDP_TIMEOUT){
			exist_num++;
		}
	}
	if (!sm_get(proIdMap, protocol, strid, sizeof(strid))) {
		printf("UDP protocol not enable!\n");
	}
	add_ipdata_exist_num(key, atoi(strid),exist_num);
}

/**************
 *	Function:	ExistConnCount	
 *	Description:
		统计每个IP地址上已经存在的连接数.
 *	Parameters:
 *		arg		当前协议	
 *	Returns:		void
 * *************/

void* ExistConnCount(void *arg) {
	char *str = (char*)arg;
	int i = 0;
	printf("In function ExistconnCount!\n");
	while(1){
		i++;
		printf("In loop of ExistConnCount,now is loop %d!\n",i);
		sleep(UDP_TIME);
		int ret = 0;
		if(!(ret = ssm_enum(UDPstatusMap,SetExistconn,arg))){
			printf("SetExistconn error!\n");
		}
	}
}

/**************
 *	Function:		udp_packet_decode
 *	Description:
 *		udp数据包解码及统计入口函数		
 *	Parameters:
 *		packet		原始数据包	
 *		packet_len	数据包大小
 *	Returns:		void
 * *************/

void udp_packet_decode(const struct pcap_pkthdr *h, const u_char *p)
{
	const struct ip *ip;
	const struct udphdr *udp;
	uint16_t sport,dport;
	uint32_t srcip,dstip;
	char strid[8];

	ip = (const struct ip *)(p+IP_OFFSET);
	uint64_t size;
	size = h->len;
	srcip = ntohl(*(uint32_t *) (&ip->ip_src));
	dstip = ntohl(*(uint32_t *) (&ip->ip_dst));

	udp = (struct udphdr *)(ip+1);
	udp = (struct udphdr *) ( ((char *)udp) + ((ip->ip_hl-5)*4) );

	sport = ntohs(udp->source);
	dport = ntohs(udp->dest);

	session_info *tmpinfo;
	tmpinfo = (session_info*)calloc(1,sizeof(session_info));
	if(!tmpinfo){
		printf("Packetcallback swich UDP protocol calloc tmpinfo failed!\n"); /* 写日志 */
		return;
	}
	tmpinfo->srcip = srcip;
	tmpinfo->dstip = dstip;
	tmpinfo->srcport = sport;
	tmpinfo->dstport = dport;
	tmpinfo->ts = h->ts;

	IPSession tmpipses;
	memset(&tmpipses,0,sizeof(IPSession));
	/* 源IP做key查询 */
	if(ssm_get(UDPstatusMap,srcip,&tmpipses) != 1) {  //用源IP去UPD状态表里面查询,如果没有的话执行下面的语句块
		tmpipses.sessions = (session_info*)calloc(INCR,sizeof(session_info));//给这个IP分配会话数组空间
		if(!tmpipses.sessions){
			printf("Packetcallback swich UDP protocol calloc sessions failed!\n"); /* 写日志 */
			return;
		}
		tmpipses.capacity = INCR;//把当前的ip和这个ip的会话放入value,执行到最下面时将会把这个ip做key,然后把Value放入UDP状态哈希;
		tmpipses.sessions[0] = *tmpinfo;
		tmpipses.session_count++;
		add_ipdata_pro(tmpinfo->srcip, h->caplen, atoi(strid), 0);//增加新链接计数
		add_ipdata_pro(tmpinfo->dstip, h->caplen, atoi(strid), 1);

	}else{  //找到了这个ip,说明这个ip已经存在了
		if((tmpipses.session_count) == tmpipses.capacity) { //如果这个ip的会话数组已经满了,给它增长容量
			tmpipses.sessions = (session_info*)realloc(tmpipses.sessions,tmpipses.session_count + INCR);
			if(!tmpipses.sessions){
				printf("Packetcallback swich UDP protocol realloc sessions failed!\n"); /* 写日志 */
				return;
			}
			tmpipses.capacity += INCR;
		}
		int i;
		int flag = 0;//找到这个四元组后置1
		for(i = 0; i < tmpipses.session_count; i++) { //遍历这个ip的所有会话
			if(!memcmp((tmpipses.sessions + i),tmpinfo,12)){//如果这个会话已经存在
				flag = 1;
				if((tmpinfo->ts.tv_sec - tmpipses.sessions[i].ts.tv_sec) > UDP_TIMEOUT) {     //超时,虽然找到了,但原来的连接状态已经超时了,这一个算新连接,把连接计数+1
					add_ipdata_pro(tmpinfo->srcip, h->caplen, atoi(strid), 0);
					add_ipdata_pro(tmpinfo->dstip, h->caplen, atoi(strid), 1);
					tmpipses.sessions[i].ts.tv_sec = tmpinfo->ts.tv_sec;//这里是把时间更新
				}else {//如果这个会话没有超时,那么把最新的时间记录下来
					tmpipses.sessions[i].ts.tv_sec = tmpinfo->ts.tv_sec;//更新时间
					add_ipdata_acc(tmpinfo->srcip,h->caplen,atoi(strid),0);//只增加访问次数
					add_ipdata_acc(tmpinfo->dstip,h->caplen,atoi(strid),1);
				}
			}

			}//遍历完
			if(flag == 0) {//遍历完后没有找到,那么这是一个新的会话,把它放入这个IP的会话数组,把会话数加1
				tmpipses.sessions[tmpipses.session_count] = *tmpinfo;
				tmpipses.session_count++;
				add_ipdata_pro(tmpinfo->srcip,h->caplen,atoi(strid),0);
				add_ipdata_pro(tmpinfo->dstip,h->caplen,atoi(strid),1);
			}
		}

		ssm_put(UDPstatusMap,srcip,tmpipses);
		free(tmpinfo);
}
