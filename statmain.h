#ifndef _PACKETSTATS_H_
#define _PACKETSTATS_H_
#define _GNU_SOURCE  
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <pcap.h>
#include <signal.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>
#include <dirent.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <pthread.h>
#include "strintmap.h"
#include "strmap.h"
#include "sessionmap.h"

/*
struct Stats {
	uint64_t	sendpkts;
	uint64_t	recvpkts;
	uint64_t	sendsize;
	uint64_t	recvsize;
	uint16_t    protoid;
};

struct IPData {
	uint32_t	ipaddr;
	struct Stats stats[16];
};
*/

/*
struct HashStruct {
	uint32_t  ipaddr;
	struct Stats stats[16];
	UT_hash_handle hh;
};
*/
#endif
