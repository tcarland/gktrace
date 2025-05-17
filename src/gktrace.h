/**
  * Copyright (c) 2010-2025 Timothy Charlton Arland <tcarland@gmail.com>
  *
  * This file is part of gktrace.
  *
  * gktrace is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as
  * published by the Free Software Foundation, either version 3 of
  * the License, or (at your option) any later version.
  *
  * gktrace is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public
  * License along with gktrace.
  * If not, see <http://www.gnu.org/licenses/>.
 **/
#ifndef _GKRACE_GKTRACE_H_
#define _GKRACE_GKTRACE_H_

#include "tcanetpp.h"

#define GKTRACE_SEQINTERVAL_MS  1000
#define GKTRACE_SEQTIMEOUT      1
#define GKTRACE_MAXSEQCOUNT     100
#define GKTRACE_MAXHOPSLOST     3
#define GKTRACE_MAXHOPS         30
#define GKTRACE_HOP_RETRIES      3
#define GKTRACE_DEFAULT_SIZE    48
#define GKTRACE_MAX_BUFFER_SIZE 2048
#define GKTRACE_PORT_ID_MASK    5995
#define GKTRACE_TR_PORT_MASK    33434
#define GKTRACE_TR_PORT_SRC     33655


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
