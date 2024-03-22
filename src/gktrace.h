#ifndef _GKRACE_GKTRACE_H_
#define _GKRACE_GKTRACE_H_

#include "tcanetpp.h"


#define SEQINTERVAL_MS  1000
#define SEQTIMEOUT      1
#define MAXSEQCOUNT     100
#define MAXHOPSLOST     3
#define MAXHOPS         30
#define DEFAULT_SIZE    48
#define MAX_BUFFER_SIZE 2048
#define PORT_ID_MASK    5995
#define TR_PORT_MASK    33434
#define TR_PORT_SRC     33655


namespace gktrace {


struct data_ts {
    uint32_t  secs;
    uint32_t  usecs;
};


struct PathData {
    uint16_t  hop;
    uint16_t  proto;
    uint32_t  ipaddr;
    uint32_t  seq;
    uint32_t  cnt;
    float     rtt;
    float     rtt_min;
    float     rtt_max;
    float     rtt_total;
    float     rtd;
    float     rtd_min;
    float     rtd_max;
    float     rtd_total;
    uint32_t  secs;
    uint32_t  usecs;

    PathData() 
        : hop(0), 
          proto(SOCKET_UDP), 
          ipaddr(0), 
          seq(0), 
          cnt(0), 
          rtt(0.0), 
          rtt_min(0.0), rtt_max(0.0), rtt_total(0.0),
          rtd(0.0), 
          rtd_min(0.0), rtd_max(0.0), rtd_total(0.0),
          secs(0), 
          usecs(0)
    {}
};

typedef std::vector<PathData> PathVector;
typedef std::set<int>         HopIndex;


struct IcmpResponse {
    netip_h    iph;
    neticmp_h  icmph;
};

} // namespace

#endif  // _GKTRACE_GKTRACE_H_