/*
 * =====================================================================================
 *
 *       Filename:  statmain.c
 *
 *    Description:  This is the frame file of the program.
 *
 *        Version:  1.0
 *        Created:  2017-03-03 14:28:28
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  xuhongping, xhp@chinabluedon.cn
 *        Company:  Bluedon
 *
 * =====================================================================================
 */
#define _GNU_SOURCE
#include <strings.h>
#include <stdlib.h>
#include <pthread.h>
#include <bits/pthreadtypes.h>
#include "statmain.h"
#include "tcp_decode.h"
#include "udp_decode.h"
#define MEMFILE  "/var/run/.memfile" 
#define STATS_DIR "/var/log/protostats/minute/"
#define DETECTED_PROTO_NUM 80000 

#if 1
StrMap *ipPortMap ;
StrMap *proIdMap ;
StrMap *idProMap ;
StrintMap *ipdataMap ;
SessionMap *UDPstatusMap ;
SessionMap *ICMPstatusMap ;
#endif

char net_range[64];
uint32_t ipstart;
uint32_t ipend;
char ifname[256];
char *ifdevice[32];
int proto_num;
int g_daemon ;
char *configfile; 
int configflag;
int gflag;
int ip0flag;
time_t timev;

#define DEVICE_NUM_MAX 32

#if 1
struct proto_port {
	char protoname[64];
	int protowithport;
	char port[128];
};
struct Stats ip0[16];

struct proto_port pport[256];
#endif

static pcap_t *pd;

#if 1
struct ipport_pro {
	char ipport[12];
	char proto[16];
};
#endif

int DataLink;
int IP_Offset;

int parse_confile()
{
	FILE *fp;
	if ((fp = fopen(configfile, "r")) == NULL) 
		return -1;

		printf("statemain:line:%d\n",__LINE__);
	char buf[64];
	char *str_proto;
	char *str_flag;
	char *str_proto1;
	char *str_flag1;
	char *str1, *str2;
	int i = 0;
	while (fgets(buf, 64, fp) != NULL) {
		/*
		if (strcasestr(buf, "proto") == NULL) {
			str_proto1 = strtok(buf, "="); 
			str_flag1 = strtok(NULL, "\n"); 
		}
		*/
		if (strcasestr(buf, "port") == NULL) {
			str_proto = strtok(buf, "="); 
			str_flag = strtok(NULL, "\n"); 


			if (str_proto != NULL) {
				if (strcmp(str_proto, "NETWORK") == 0) {
					strcpy(net_range, str_flag);
					char *tmp;
					if (strchr(net_range, '-')) {
						tmp = strtok(net_range, "-");
						ipstart = ntohl(inet_addr(tmp));
						while (tmp != NULL) {
							tmp = strtok(NULL, "-");
							if (tmp != NULL) {
								ipend = ntohl(inet_addr(tmp));
							}
						}
					}
					i--;
				}

				if (strcmp(str_proto, "INTERFACE") == 0) {
					i--;
					strcpy(ifname, str_flag);
					printf("ifname: %s\n", ifname);
				}
			}

			if (str_flag != NULL) {
				//printf("##str_proto: %s\n", str_proto);
				//printf("##str_flag: %s\n", str_flag);
				if (strncasecmp(str_flag, "on", 2) == 0) {
					strcpy(pport[i].protoname, str_proto);
					char proid[16] = {'\0'};
					sprintf(proid, "%d", i+1);
					sm_put(proIdMap, str_proto, proid);
					sm_put(idProMap, proid, str_proto);
					memset(&pport[i].port, 0, 128);

					char *tmp1 = strtok(str_flag, "=");
					while (tmp1 != NULL) {
						tmp1 = strtok(NULL, "=");
						if (tmp1 != NULL) {
							if (strcmp(tmp1 , "tcp") == 0) 
								pport[i].protowithport = 6;
							else if (strcmp(tmp1 , "udp") == 0) 
								pport[i].protowithport = 17;
								
						}
					}
					proto_num ++;
				}
			}
		} else {
			str1 = strtok(buf, " "); 
			str2 = strtok(NULL, "\n"); 
			str_proto = strtok(str1, "="); 
			str_flag = strtok(NULL, " "); 

			char *str3= strchr(str2, '=');


				printf("###########strflag: %s\n", str_flag);
				printf("###########str_1: %s\n", str1);
				printf("############str_2: %s\n", str2);
			if (strncasecmp(str_flag, "on", 2) == 0) {
				strcpy(pport[i].port , str3 +1);
				printf("str_proto: %s\n", str_proto); 
				printf("sizeof: %d\n", sizeof(str_proto));
				strcpy(pport[i].protoname, str_proto);
				char proid[16] = {'\0'};
				sprintf(proid, "%d", i+1);
				sm_put(proIdMap, str_proto, proid);
				sm_put(idProMap, proid, str_proto);



				char *tmp1 = strtok(str2, " ");
				/*
				char *tmp2 = strtok(tmp1, "=");
						printf("tmp2############: %s\n", tmp2);
						*/
				while (tmp1 != NULL) {
					char *tmp2;
					if ((tmp2 = strcasestr(tmp1, "proto")) != NULL) {
						printf("tmp2############: %s\n", tmp2);
						char *tmp3 = strtok(tmp2, "=");
						while (tmp3) { 
							tmp3 = strtok(NULL, "=");
							if (tmp3 != NULL) {
								if (strcmp(tmp3 , "tcp") == 0) 
									pport[i].protowithport = 6;
								else if (strcmp(tmp3 , "udp") == 0) 
									pport[i].protowithport = 17;
							}
						}
					}

					tmp1 = strtok(NULL, " ");
				}

				proto_num ++;
			}
		}
		i++;
	}
	printf("proto_num:%d\n",proto_num);
	return 0;
}

void funciter(char *key, char *value, void *data)
{
	printf("key: %s, \tvalue: %s\n", key, value);
}

char* intoaV4(unsigned int addr, char* buf, u_short bufLen)
{

	char *cp, *retStr;
	uint byte;
	int n;

	cp = &buf[bufLen];
	*--cp = '\0';

	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if(byte > 0) {
			*--cp = byte % 10 + '0';
			byte /= 10;
			if(byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while (--n > 0);

	retStr = (char*)(cp+1);

	return(retStr);
}

char file[256]; 
	int filen;
char *check_file()
{
	int i;
	char istr[8];
	for (i=0; i<10; i++) {
		memset(file, 0, sizeof(file));

		memset(istr, 0, sizeof(istr));
		strcpy(file, STATS_DIR);
		sprintf(istr, "%d", i);
		strcat(file, istr);

		if (access(file, F_OK) == 0) {
			if (i == 9) {
				memset(file, 0, sizeof(file));
				strcpy(file, STATS_DIR);
				char buf[8];
				if (filen > 9)
					filen = 0;
				sprintf(buf, "%d", filen);
				strcat(file, buf);
				filen ++;
				/*
				   int j;
				   char tmp1[256];
				   char cmdrm[256];
				   char tmpj[8];
				   for (j = 0; j<10; j++) {
				   strcpy(tmp1, STATS_DIR);
				   sprintf(tmpj, "%d", j);
				   strcat(tmp1, tmpj);
				   strcpy(cmdrm, "rm -f ");
				   strcat(cmdrm, tmp1);
				   printf("cmdrm: %s\n", cmdrm);
				   system(cmdrm);
				   }
				   */
			}

			continue;
		} else {
			return file;
		}
	}

	return file;
}

void smint_iter(const StrintMap *map)
{
	check_file();
		printf("file: %s\n", file);

	FILE *fp = fopen(file, "w");
	if (fp == NULL)
		return ;
	unsigned int i, j, n, m;
	Bucketint *bucket;
	Pairint *pair;


	fprintf(fp, "%ld|", timev );
	fprintf(fp, "0.0.0.0|");

	int k;

	for (k=0; k<proto_num+1; k++) {
		fprintf(fp, "%llu|", ip0[k].recvsize);
		fprintf(fp, "%llu|", ip0[k].sendsize);
	}

	fprintf(fp, "\n");

	if (map == NULL) {
		return ;
	}
	char ippname[16]={'\0'};
	bucket = map->buckets;
	n = map->count;
	i=0;
	while (i < n) {
		pair = bucket->pairs;
		m = bucket->count;
		j = 0;
		while (j < m) {
			if(pair->key == 0) 
				break;
			strcpy(ippname, intoaV4(pair->key, ippname, 16));

			char strid[8];

			fprintf(fp, "%ld|", timev );
			fprintf(fp, "%s|", ippname);
			//printf( "%s", ippname);

			for (k=0; k<proto_num+1; k++) {
				char tmp[8], pname[8] ;
				sprintf(tmp, "%d", pair->value.stats[k].protoid);

					//printf("recv :%llu|", pair->value.stats[0].recvsize);
					//printf("send :%llu|", pair->value.stats[0].sendsize);
				sm_get(idProMap, tmp, pname, sizeof(pname));

				/*
				   sm_enum(idProMap, funciter, NULL);
				   printf("xxxxxxxxxxxxxx\n");
				   */

				/*
				if (smint_get(ipdataMap, ip, &ipstats) != 1) {

				}
				*/
				//if (sm_exists());
				if (pair->value.stats[k].protoid == 0) {
					fprintf(fp, "%llu|", pair->value.stats[k].recvsize);
					fprintf(fp, "%llu|", pair->value.stats[k].sendsize);
					fprintf(fp, "%llu|", pair->value.stats[k].newconn);
					fprintf(fp, "%llu|", pair->value.stats[k].existconn);
					//add by njl
					//pair->value.stats[k].recvsize = 0;
					//pair->value.stats[k].sendsize = 0;
					//fprintf(fp, "%s", pname);

					continue;
				}

				//printf("tmp: %s\n", tmp);
				fprintf(fp, "%llu|", pair->value.stats[k].recvsize);
				fprintf(fp, "%llu|", pair->value.stats[k].sendsize);
				fprintf(fp, "%llu|", pair->value.stats[k].newconn);
				fprintf(fp, "%llu|", pair->value.stats[k].existconn);
				fprintf(fp, "%llu|", pair->value.stats[k].accesstimes);
				//add by njl
				pair->value.stats[k].recvsize = 0;
				pair->value.stats[k].sendsize = 0;
				pair->value.stats[k].newconn = 0;
				pair->value.stats[k].accesstimes = 0;
				if(pair->value.stats[k].existconn == 0){
					bucket->count -= 1;
					memset(pair,0,sizeof(Pairint));
					//free(pair);
				}
				//fprintf(fp, "%s", pname);

				/*for debug*/
				/*
				printf("|%llu|", pair->value.stats[k].sendpkts );
				printf("%llu|", pair->value.stats[k].recvpkts);
				printf("%llu|", pair->value.stats[k].sendsize);
				printf("%llu|", pair->value.stats[k].recvsize);
				printf("%s", pname);
				*/
			}
			fprintf(fp, "%s", "\n");
			//printf("%s", "\n");
			pair++;
			j++;
		}
		bucket++;
		i++;
	}
	fclose(fp);
	return ;
}

void *write_stats(void *data) 
{
	while (1) {
		usleep(10000);
		timev = time(NULL);
		if (timev%60 !=  0)
			continue;
		gflag = 1;
		smint_iter(ipdataMap);
		sleep(60);
	}
}

void mapiter(char *key, char *value, void *data)
{
	printf("key:%s,\tvalue:%s\n", key, value);
}



void init_ipdataMap ()
{
	memset(ipdataMap->buckets, 0, ipdataMap->count * sizeof(Bucketint));
}

void PacketCallback(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	const struct ip *ip;
	uint32_t srcip;
	uint32_t dstip;

	//p += IP_Offset; 
	ip = (const struct ip *)(p+IP_Offset);

	uint64_t size;
	size = h->len;
	//ntohs(ip->ip_len);


	if (ip->ip_v != 4) 
		return;

	if (gflag == 1) {
		printf("11111\n");
     	//memset(ipdataMap->buckets, 0, ipdataMap->count * sizeof(Bucketint));
		ip0flag = 1;
		gflag = 0;
	} 

	srcip = ntohl(*(uint32_t *) (&ip->ip_src));
	dstip = ntohl(*(uint32_t *) (&ip->ip_dst));


	char strid[8];


	if ((srcip < ipstart || srcip > ipend) && (dstip < ipstart || dstip >ipend)) 
		return;

	const struct tcphdr *tcp;
	const struct udphdr *udp;

	uint16_t  sport, dport;

	switch(ip->ip_p) {
		case 6:    
			if (sm_get(proIdMap, "tcp", strid, sizeof(strid)) ==1) {
				//todo:
			//	printf("fun:%s,line:%d,strid:%s\n",__FUNCTION__,__LINE__,strid);
				tcp_packet_decode(p,h->len);
			}

			break;
		case 17:
			if (sm_get(proIdMap, "udp", strid, sizeof(strid)) ==1) {
				// todo: 
				udp_packet_decode(h,p);
			}
			break;
		case 1: 
			if (sm_get(proIdMap, "icmp", strid, sizeof(strid)) ==1) {
				//todo:
				icmp_packet_decode(h,p);
			}
			break;
		default:
			if (sm_get(proIdMap, "unknown", strid, sizeof(strid)) ==1) {
				//todo:
			}

	}
}

int parse_args(int argc, char **argv)
{

	int opt = 0;

	while ((opt = getopt(argc, argv, "dc:h")) != -1) {

		switch (opt) {
			case 'd':
				g_daemon = 1;
				break;
			case 'c':
				configfile = strdup(optarg);
				configflag = 1;
				break;
			case 'h':
			case '?':
				return -1;
			default:
				printf("Invalid parameters.\n");
				return -1;
		}
	}

	return 0;
}

void usage(void )
{
	printf("Usage: ./packetStats [OPTIONS...]\n"
			"        -d                Run as a daemon.\n"
			"        -c <config file>  load a configure file.\n"
			"        -h                Show this help.\n");

}

/****************************************************************************
 *
 * Function: main(int argc, char** argv)
 *
 * Purpose:  entry of the program
 *
 * Arguments: argc -> the number of cmdline argument 
 *			  argv -> cmdline argument
 *
 * Returns: 0  => success
 *			-1 => fail
 *
 ****************************************************************************/
int main(int argc, char **argv)
{

	if (parse_args(argc, argv) < 0) {
		usage();
		return -1;
	}

	if (configflag == 0) {
		usage();
		return -1;
	}

	if (g_daemon == 1) 
		daemon(1,0);

	ipPortMap = sm_new(DETECTED_PROTO_NUM );
	proIdMap = sm_new(256);
	idProMap = sm_new(256);
	ipdataMap = smint_new(DETECTED_PROTO_NUM); 
	UDPstatusMap = ssm_new(DETECTED_PROTO_NUM);
	ICMPstatusMap = ssm_new(DETECTED_PROTO_NUM);
	
	int res;
	parse_confile();

	pthread_t pth_id,udp_exist_conn,icmp_exist_conn;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);


	if (pthread_create(&pth_id, NULL, (void*)write_stats, NULL) != 0) {
		printf("create thread error!%s(%d)\n",__FILE__,__LINE__);
		return -1;
	}
	if (pthread_create(&udp_exist_conn,&attr,ExistConnCount, "udp") != 0) {
		printf("create ExistConnCount error!%s(%d)\n",__FILE__,__LINE__);
		return -1;
	}
	if (pthread_create(&icmp_exist_conn,&attr,ExistConnCount, "icmp") != 0) {
		printf("create ExistConnCount error!%s(%d)\n",__FILE__,__LINE__);
		return -1;
	}

	struct bpf_program fcode;
	u_char *pcap_userdata = 0;
	pcap_if_t *Devices;
	char Error[PCAP_ERRBUF_SIZE];
	char *_ifdevice = NULL;

	pcap_findalldevs(&Devices, Error);

	int i=0;
	if (strchr(ifname, ',')) {
		_ifdevice = strtok(ifname, ",");
		while (_ifdevice != NULL ) {
			ifdevice[i] = _ifdevice;
			_ifdevice = strtok(NULL, ",");
			i++;
		}
	}


	int n=i;
	char *interface = ifname;
	while(Devices) {
		//printf("Description: %s\nName: \"%s\"\n\n", Devices->description, Devices->name);
		for (i=0; i<n; i++) {
			if (strcasecmp(Devices->name, ifdevice[i]) == 0) {
				strcpy(interface, ifdevice[i]);
				goto TODO;
			}
		}

		Devices = Devices->next;
	}
	
TODO:
	pd = pcap_open_live(interface, 100, 1, 1000, Error);
	if (pd == NULL) {
		printf( "%s", Error);
		exit(0);
	}

	if (pcap_compile(pd, &fcode, "ip", 1, 0) < 0) {
		pcap_perror(pd, "Error");
		printf("Malformed libpcap filter string in bandwidthd.conf\n");
		exit(1);
	}

	if (pcap_setfilter(pd, &fcode) < 0)
		pcap_perror(pd, "Error");

	switch (DataLink = pcap_datalink(pd)) {
		default:
			printf( "Unkown datalink type, defaulting to ethernet");
		case DLT_EN10MB:
			IP_Offset = 14; 
			break;	
	}

	if (pcap_loop(pd, -1, PacketCallback, pcap_userdata) < 0) {
		printf( "pcap_loop: %s",  pcap_geterr(pd));
		exit(1);
	}

	pcap_close(pd);

	return -1;        
}

