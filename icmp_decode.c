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

void icmp_packet_decode(const struct pcap_pkthdr *h, const u_char *p,uint16_t proid)
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


	session_info tmpinfo;
	memset(&tmpinfo,0,sizeof(session_info));

	tmpinfo.srcip = srcip;
	tmpinfo.dstip = dstip;
	tmpinfo.ts = h->ts;

	add_session(tmpinfo.srcip,&tmpinfo,h->caplen,proid,0,ICMPstatusMap);
	add_session(tmpinfo.dstip,&tmpinfo,h->caplen,proid,1,ICMPstatusMap);
}
