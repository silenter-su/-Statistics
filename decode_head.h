#ifndef __DECODE_HEAD_H__
#define __DECODE_HEAD_H__

#include "strintmap.h"
#include "strmap.h"

StrMap *ipPortMap;
StrMap *proIdMap;
StrMap *idProMap;
//StrintMap *ipdataMap = NULL;
StrintMap *ipdataMap;
//StrintMap *ipdataMap1 = NULL;

#define DETECTED_PROTO_NUM  80000

struct proto_port {
	char protoname[64];
	int protowithport;
	char port[128];
};

struct Stats ip0[16];
struct proto_port pport[256];

struct ipport_pro{
	char ipport[12];
	char proto[16];
};

#endif
