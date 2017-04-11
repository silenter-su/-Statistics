#include "udp_decode.h"

extern StrMap *proIdMap;
extern StrMap *idProMap;
extern StrMap *ipPortMap;
extern StrintMap *ipdataMap;
extern SessionMap *UDPstatusMap;
extern SessionMap *ICMPstatusMap;
time_t timev;

/*************
 * Function:	detect_sessions
 * Description:		
 *		检测tmpipsess下的会话数组,并处理相应的数据
 *	Parameters:
 *		tmpipses	临时IPSession结构体	
 *		tmpinfo		临时会话四元组信息结构体
 *	Returns:	void.
 * ***********/

void detect_sessions(IPSession *tmpipses,session_info *tmpinfo)
{
	int exist = 0,i;
	for(i = 0; i < tmpipses->session_count; i++) { 
		if(!memcmp((tmpipses->sessions + i),tmpinfo,12)){/* 如果这个会话已经存在 */
			exist = 1;
			if((tmpinfo->ts.tv_sec - tmpipses->sessions[i].ts.tv_sec) > TIMEOUT) { /* 超时 */
				tmpipses->sessions[i].ts.tv_sec = tmpinfo->ts.tv_sec;/* 更新时间 */
				tmpipses->newconn++; /* 算是一个新链接 */
				tmpipses->accesstimes++;
				tmpipses->sessions_flag[i] = 0; /* 将这个链接标示为有效链接 */
			}else { /* 未超时 */
				tmpipses->sessions[i].ts.tv_sec = tmpinfo->ts.tv_sec;/* 更新时间 */
				tmpipses->accesstimes++;
				tmpipses->sessions_flag[i] = 0; /* 将这个链接标示为有效链接 */
			}
			break;
		}

	} /* 遍历完成 */
	if(exist == 0) {/* 遍历完后没有找到,那么这是一个新的会话,把它放入这个IP的会话数组,把新连接计数+1,访问次数+1 */
		int i;
		int flag = 0; /* 如果找到了无效链接的位置就置为1 */
		for(i = 0; i < tmpipses->session_count; i++) /* 先寻找一下会话数组内有没有无效的链接 */
		{
			if(tmpipses->sessions_flag[i]) {
				flag = 1;
				break;
			}
		}
		tmpipses->sessions[i] = *tmpinfo;
		tmpipses->sessions_flag[i] = 0;
		tmpipses->newconn++;
		tmpipses->accesstimes++;
		if(!flag) /* 如果没有填补超时连接时,将会话计数++ */
			tmpipses->session_count++;
	}
}

/*************
 * Function:	sessions_reallc	
 * Description:		
 *		为tmpipses结构体内的sessions扩大内存空间
 *	Parameters:
 *		tmpipses	临时IPSession结构体	
 *	Returns:	void.
 * ***********/
void  sessions_realloc(IPSession *tmpipses)
{
	tmpipses->sessions = (session_info*)realloc(tmpipses->sessions,tmpipses->session_count + INCR);
	if(!tmpipses->sessions){
		printf("Packetcallback swich UDP protocol realloc sessions failed!%s(%d)\n",__FILE__,__LINE__);
		return;
	}
	tmpipses->sessions_flag = (int*)realloc(tmpipses->sessions_flag,tmpipses->session_count + INCR); 
	if(!tmpipses->sessions_flag){
		printf("Packetcallback swich UDP protocol realloc sessions_flag failed!%s(%d)\n",__FILE__,__LINE__);
		return;
	}
	tmpipses->capacity += INCR;
}
/*************
 * Function:	sessions_callc	
 * Description:		
 *		为tmpipses结构体内的sessions申请内存空间
 *	Parameters:
 *		tmpipses	临时IPSession结构体	
 *	Returns:	void.
 * ***********/
void  sessions_calloc(IPSession *tmpipses)
{		
	tmpipses->sessions = (session_info*)calloc(INCR,sizeof(session_info));/* 给这个IP分配会话数组空间 */
	if(!tmpipses->sessions){
		printf("Packetcallback swich UDP protocol calloc sessions failed!%s(%d)\n",__FILE__,__LINE__);
		return;
	}
	tmpipses->sessions_flag = (int*)calloc(INCR,sizeof(int));
	if(!tmpipses->sessions_flag){
		printf("Packetcallback swich UDP protocol calloc sessions_flag failed!%s(%d)\n",__FILE__,__LINE__);
		return;
	}
	tmpipses->capacity = INCR;
}
/*************
 * Function:	add_session	
 * Description:		
 *		增加session会话表中相应的计数,例如UDP ICMP建立的会话计数map.
 *	Parameters:
 *		ip		当前ip.
 *		info	session会话结构体
 *		len		当前数据帧大小.
 *		protoid	当前协议.
 *		flag	标识源ip还是目的ip.
 *		map		要查询的map
 *	Returns:	void.
 * ***********/

void  add_session(uint32_t ip,session_info *info,uint64_t len,uint16_t protoid,int flag,SessionMap *map)
{
	IPSession tmpipses;
	memset(&tmpipses,0,sizeof(IPSession));	
	
	if(ssm_get(map,ip,&tmpipses) != 1){
			sessions_calloc(&tmpipses);
			tmpipses.sessions[0] = *info;
			tmpipses.session_count++;
			tmpipses.newconn++;
			tmpipses.accesstimes++;
			
	}else{
		if((tmpipses.session_count) == tmpipses.capacity) /* 如果这个ip的会话数组已经满了,给它增长容量 */
			sessions_realloc(&tmpipses); 
		detect_sessions(&tmpipses,info); /* 检测会话,并做相应处理 */
	}

	if(flag == 0) {
		tmpipses.sendsize+=len;
	} else if(flag == 1) {
		tmpipses.recvsize+=len;
	}
	tmpipses.protoid = protoid;

	ssm_put(map,ip,tmpipses);
	return;
}

/**************
 *	Function:	ClearValue	
 *	Description:
 *		清除所有IP上一分钟的计数
 *	Parameters:
 *		key		当前的源IP
 *		value	当前源IP的会话数组
 *		obj		协议字符串
 *	Returns:		void
 * *************/
void ClearValue(unsigned int key,IPSession value,const void *obj)
{
	value.sendsize = 0;
	value.recvsize = 0;
	value.newconn = 0;
	value.existconn = 0;
	value.accesstimes = 0;

	char *prostr = (char*)obj;
	if(strstr(prostr,"udp")) {
		ssm_put(UDPstatusMap,key,value);
	}
	if(strstr(prostr,"icmp")) {
		ssm_put(ICMPstatusMap,key,value);
	}
	return;
}

void print_value(IPSession *value,int i)
{
	printf("Now i value is %d\n",i);
	printf("sip%lu\n"
				"dip%lu\n"
				"sport%d\n"
				"dport%d\n"
				"ts%lu\n"
				,value->sessions[i].srcip
				,value->sessions[i].dstip
				,value->sessions[i].srcport
				,value->sessions[i].dstport
				,value->sessions[i].ts.tv_sec);
	printf("当前的协议ID是: %d\n",value->protoid);

}

/**************
 *	Function:		GetExistconn	
 *	Description:
 *		设置当前ip当前存在的链接数
 *	Parameters:
 *		key		当前的源IP
 *		value	当前源IP的会话数组
 *		obj		协议字符串
 *	Returns:		void
 * *************/

void GetExistconn(unsigned int key,IPSession value,const void *obj)
{
	unsigned int exist_num = 0;
	int i = 0;
	struct timeval tv;
	const char *protocol = obj;
	char strid[8];

	gettimeofday(&tv,NULL);

	for(i = 0; i < value.session_count; i++){
		//print_value(&value,i);
		if((tv.tv_sec - value.sessions[i].ts.tv_sec) < TIMEOUT){
			exist_num++;
		} else {
			value.sessions_flag[i] = 1; /* 已经超时的连接,现在把它的flag置为1,如果有了新连接,将会填补它 */
		}
	}
	value.existconn = exist_num;

	/* 先把一分钟之内统计的结果传给ipdatamap */
	if (!sm_get(proIdMap, protocol, strid, sizeof(strid))) {
		printf("UDP protocol not enable!%s(%d)\n",__FILE__,__LINE__);
	}
	uint16_t protoid = atoi(strid);
	struct IPData tmpstats;
	memset(&tmpstats,0,sizeof(struct IPData));
	if(smint_get(ipdataMap,key,&tmpstats) != 1) {

		tmpstats.stats[0].sendsize += value.sendsize;
		tmpstats.stats[0].recvsize += value.recvsize;
		tmpstats.stats[0].newconn += value.newconn;
		tmpstats.stats[0].existconn += value.existconn;
		tmpstats.stats[0].accesstimes += value.accesstimes;

		tmpstats.stats[protoid].sendsize = value.sendsize;
		tmpstats.stats[protoid].recvsize = value.recvsize;
		tmpstats.stats[protoid].newconn = value.newconn;
		tmpstats.stats[protoid].existconn = value.existconn;
		tmpstats.stats[protoid].accesstimes = value.accesstimes;
		tmpstats.stats[protoid].protoid = protoid;

	} else {

		tmpstats.stats[0].sendsize += value.sendsize;
		tmpstats.stats[0].recvsize += value.recvsize;
		tmpstats.stats[0].newconn += value.newconn;
		tmpstats.stats[0].existconn += value.existconn;
		tmpstats.stats[0].accesstimes += value.accesstimes;

		tmpstats.stats[protoid].sendsize += value.sendsize;
		tmpstats.stats[protoid].recvsize += value.recvsize;
		tmpstats.stats[protoid].newconn += value.newconn;
		tmpstats.stats[protoid].existconn += value.existconn;
		tmpstats.stats[protoid].accesstimes += value.accesstimes;
		tmpstats.stats[protoid].protoid = protoid;

	}
	//tmpstats.stats[0].protoid += value.protoid;
	//tmpstats.stats[protoid].protoid = value.protoid;
	smint_put(ipdataMap,key,tmpstats);
	return;
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
		int ret = 0;
		char *protocol = (char*)arg;
		if(strstr(protocol,"udp")){
			if(!(ret = ssm_enum(UDPstatusMap,GetExistconn,arg))){
				printf("GetExistconn error!%s(%d)\n",__FILE__,__LINE__);
			}
			/* 清除一分钟之间的计数 */
			if(!(ret = ssm_enum(UDPstatusMap,ClearValue,arg))){
				printf("ClearValue error!%s(%d)\n",__FILE__,__LINE__);
			}
			
		}
		if(strstr(protocol,"icmp")){
			if(!(ret = ssm_enum(ICMPstatusMap,GetExistconn,arg))){
				printf("GetExistconn error!%s(%d)\n",__FILE__,__LINE__);
			}
			/* 清除一分钟之间的计数 */
			if(!(ret = ssm_enum(ICMPstatusMap,ClearValue,arg))){
				printf("ClearValue error!%s(%d)\n",__FILE__,__LINE__);
			}
		}
		/* 查看目前UDP哈希表占用多少内存,如果超过范围,就将哈希表删除,重新建立哈希表 */
		int pairnum = 0;
		pairnum = ssm_get_count(UDPstatusMap);
		if((pairnum * sizeof(PairSession)) > MAXMAP) {
			ssm_delete(UDPstatusMap); 
			UDPstatusMap =  ssm_new(DETECTED_PROTO_NUM); 
		}	
		pairnum = ssm_get_count(ICMPstatusMap);
		if((pairnum * sizeof(PairSession)) > MAXMAP) {
			ssm_delete(ICMPstatusMap); 
			ICMPstatusMap =  ssm_new(DETECTED_PROTO_NUM); 
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

void udp_packet_decode(const struct pcap_pkthdr *h, const u_char *p,uint16_t proid)
{
	const struct ip *ip;
	const struct udphdr *udp;
	uint16_t sport,dport;
	uint32_t srcip,dstip;

	ip = (const struct ip *)(p+IP_OFFSET);
	uint64_t size;
	size = h->len;
	srcip = ntohl(*(uint32_t *) (&ip->ip_src));
	dstip = ntohl(*(uint32_t *) (&ip->ip_dst));

	udp = (struct udphdr *)(ip+1);
	udp = (struct udphdr *) ( ((char *)udp) + ((ip->ip_hl-5)*4) );

	sport = ntohs(udp->source);
	dport = ntohs(udp->dest);

	session_info tmpinfo;
	memset(&tmpinfo,0,sizeof(session_info));

	tmpinfo.srcip = srcip;
	tmpinfo.dstip = dstip;
	tmpinfo.srcport = sport;
	tmpinfo.dstport = dport;
	tmpinfo.ts = h->ts;

	add_session(tmpinfo.srcip,&tmpinfo,h->caplen,proid,0,UDPstatusMap);
	add_session(tmpinfo.dstip,&tmpinfo,h->caplen,proid,1,UDPstatusMap);
}
