/*
 * GkTrace - A continuous traceroute providing per-hop loss, latency and jitter
 * statistics.
 *
 * Author: tcarland@gmail.com
 * Created: March 19, 2010
 */
#define _GKPF_GKTRACE_CPP_


extern "C" {
#include <signal.h>
#ifndef WIN32
# include <unistd.h>
# include <sys/time.h>
#endif
#include <math.h>
#include <getopt.h>
}

#include <cstdlib>
#include <iostream>
#include <iomanip>
#include <vector>
#include <set>
#include <algorithm>

#include "tcanetpp_ip.h"
#include "tcanetpp_random.h"
#include "Socket.h"
#include "EventManager.h"
#include "IpAddr.h"
#include "AddrInfo.h"
#include "StringUtils.h"
#include "Serializer.h"
#include "CircularBuffer.h"
#include "LogFacility.h"
using namespace tcanetpp;


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


const char* Version = "v0.28";
bool        Alarm   = false;
int         Pid     = 0;


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
        : hop(0), proto(SOCKET_UDP), ipaddr(0), seq(0), cnt(0), 
          rtt(0.0), rtt_min(0.0), rtt_max(0.0), rtt_total(0.0),
          rtd(0.0), rtd_min(0.0), rtd_max(0.0), rtd_total(0.0),
          secs(0), usecs(0)
    {}
};

typedef std::vector<PathData> PathVector;
typedef std::set<int>         HopIndex;


struct IcmpResponse {
    netip_h    iph;
    neticmp_h  icmph;
};



void version()
{
    std::cout << "gktrace " << Version
              << ", Copyright (C) 2010, Charlton Technology, LLC" << std::endl
              << "  by Timothy C. Arland (tcarland@gmail.com)" << std::endl << std::endl;
}

void usage()
{
    version();
    std::cout << "Usage: gktrace [-cdhiInmpstV] <host|ip>" << std::endl
              << "    -c | --count  <num>  : Number of test iterations" << std::endl
              << "    -d | --debug         : Enable debug output" << std::endl
              << "    -h | --help          : Print help info and exit" << std::endl
              << "    -i | --interval <ms> : milliseconds between test iterations" << std::endl
              << "                            (default = 1000 ms or 1 second)" << std::endl
              << "    -I | --icmp          : Use icmp only (for faster path discovery)" << std::endl
              << "    -n | --nodns         : Do not resolve the results" << std::endl
              << "    -m | --maxhops <n>   : Number of consecutive dead hops before stopping discovery" 
              << std::endl
              << "                            ( default is 3 hops )" << std::endl
              << "    -p | --port <num>    : Port number mask (dst) for probes. (Default is " 
              << TR_PORT_MASK << ")" << std::endl
              << "    -s | --size <bytes>  : Number of bytes to use as payload size" << std::endl
              << "    -t | --timeout <s>   : Seconds before hop is considered non-responsive" << std::endl
              << "                            (minimum is 1 second. Increase for long or bad paths)" 
              << std::endl
              << "    -V | --version       : Print version info and exit" << std::endl << std::endl;
    exit(0);
}

void errorOut ( const std::string & err )
{
    std::cerr << "Error: " << err << std::endl;
    exit(-1);
}

void sigHandler ( int signal )
{
    if ( signal == SIGINT || signal == SIGTERM ) {
        Alarm = true;
    }

    return;
}

void sleep_ms ( int ms )
{
#   ifdef WIN32
    ::Sleep(ms);
#   else
    ::usleep(ms * 1000);
#   endif
    return;
}


#ifndef WIN32
void dropPriv()
{
    uid_t  uid;
    gid_t  gid;

    if ( geteuid() != 0 )
        return;

    uid  = ::getuid();
    gid  = ::getgid();
    ::setegid(gid);
    ::seteuid(uid);

    if ( ::geteuid() != uid )
        throw Exception("dropPrivileges() failed");

    return;
}
#endif


ssize_t readIPHeader ( CircularBuffer * buff, netip_h * iph )
{
    size_t len  = sizeof(netip_h);

    if ( buff->readAvailable() < len )
        return -1;

    return buff->read(iph, len);
}


ssize_t readIcmpHeader ( CircularBuffer * buff, neticmp_h * icmph )
{
    size_t len = sizeof(neticmp_h);

    if ( buff->readAvailable() < len )
        return -1;

    return buff->read(icmph, len);
}


ssize_t readIcmpResponse ( CircularBuffer * buff, IcmpResponse & response )
{
    ssize_t   rd;

    rd   = readIPHeader(buff, &response.iph);
    if ( rd <= 0 )
        return rd;

    rd   = readIcmpHeader(buff, &response.icmph);

    if ( rd <= 0 ) {
        std::cout << "Invalid header" << std::endl;
        return -1;
    }

    return rd;
}


ssize_t readUdpHeader ( CircularBuffer * buff, netudp_h * udph )
{
    size_t len = sizeof(netudp_h);

    if ( buff->readAvailable() < len )
        return -1;

    return buff->read(udph, len);
}


void initDataBlock ( std::string & data, size_t length )
{
    uint32_t  val;
    double    range = 255.0;
    int       dsize = length;

    tcanet_seed();
    data.clear();

    for ( int i = 0; i < dsize; i++ )
    {
        val = tcanet_randomValue(range);
        data.push_back( (char)(*((uint8_t*)&val)) );
    }

    return;
}


void printStatHeader()
{
    std::cout << std::endl
              << std::setw(3) << "hop"
              << std::setw(15) << " address" 
              << std::setw(4) << "   seq" 
              << std::setw(10) << " rtt(ms)" 
              << std::setw(10) << " avg(ms)"
              << std::setw(10) << " ipdv"
              << std::setw(6) << "   type"
              << std::endl
              << "----------------------------------------------------------------"
              << std::endl;
}



int main ( int argc, char ** argv )
{
    char      optChar;
    char    * target;
    int       optindx   = 0;
    int       retry     = 0;
    int       interval  = SEQINTERVAL_MS;
    int       count     = MAXSEQCOUNT;
    uint16_t  mhoploss  = MAXHOPSLOST;
    uint16_t  mhoptime  = SEQTIMEOUT;
    uint16_t  dstportm  = TR_PORT_MASK;
    bool      debug     = false;
    bool      resolve   = true;
    bool      icmp      = false;
    size_t    size      = DEFAULT_SIZE;

    timeval   tvin, tvo, tv;


    static struct option l_opts[] = { {"debug", no_argument, 0, 'd'},
                                      {"count", required_argument, 0, 'c'},
                                      {"nodns", no_argument, 0, 'n'},
                                      {"interval", required_argument, 0, 'i'},
                                      {"icmp", no_argument, 0, 'I'},
                                      {"help", no_argument, 0, 'h'},
                                      {"maxhops", required_argument, 0, 'm'},
                                      {"port", required_argument, 0, 'p'},
                                      {"size", required_argument, 0, 's'},
                                      {"timeout", required_argument, 0, 't'},
                                      {"version", no_argument, 0, 'V'},
                                      {0,0,0,0}
                                    };

    if ( argc < 2 )
        usage();

    while ( (optChar = getopt_long(argc, argv, "c:dhIi:nm:p:s:t:V", l_opts, &optindx)) != EOF )
    {
        switch ( optChar ) {
            case 'c':
                count = StringUtils::fromString<int>(optarg);
                break;
            case 'd':
                debug = true;
                break;
            case 'I':
                icmp = true;
                break;
            case 'i':
                interval = StringUtils::fromString<int>(optarg);
                break;
            case 'h':
                usage();
                break;
            case 'n':
                resolve = false;
                break;
            case 'm':
                mhoploss = StringUtils::fromString<int>(optarg);
                break;
            case 'p':
                dstportm = StringUtils::fromString<uint16_t>(optarg);
                break;
            case 's':
                size = StringUtils::fromString<size_t>(optarg);
                break;
            case 't':
                mhoptime = StringUtils::fromString<int>(optarg);
                break;
            case 'V':
                version();
                exit(0);
                break;
            default:
                break;
        }
    }

    target  = ::strdup(argv[argc-1]);
    std::string host = target;
    ::free(target);

#   ifdef WIN32
    WSADATA wsaData;
    static int wsastartup = 0;

    if ( wsastartup == 0 ) {
        if ( WSAStartup(MAKEWORD(2,2), &wsaData) != 0 )
            return 0;
        wsastartup=1;
    }
#   else
    Pid  = ::getpid() & 0xFFFF;
    ::signal(SIGPIPE, SIG_IGN);
    ::signal(SIGINT,  &sigHandler);
#   endif

    ::memset(&tvin, 0, sizeof(tvin));
    ::memset(&tvo, 0, sizeof(tvo));
    ::memset(&tv, 0, sizeof(tv));

    ipv4addr_t  dstaddr = AddrInfo::GetHostAddr(host);
    std::string dstname = IpAddr::ntop(dstaddr);

    if ( dstaddr == 0 ) {
        std::cout << std::endl << "Invalid target " << host << std::endl << std::endl;
        usage();
    }

    if ( mhoptime < SEQTIMEOUT ) {
        mhoptime = SEQTIMEOUT;
        std::cout << "Invalid hop timeout, using default of " << mhoptime << " ms" << std::endl;
    }

    if ( mhoploss < 2 ) {
        std::cout << "Dead hop count must be > 1, using default" << std::endl;
        mhoploss = MAXHOPSLOST;
    }

    if ( dstportm < 1024 ) {
        std::cout << "Ignoring dest port value; considered invalid (<1024)" << std::endl;
        dstportm = TR_PORT_MASK;
    }

    // init rand data block
    std::string  dataf = "";
    if ( size > MAX_BUFFER_SIZE )
        size  = (MAX_BUFFER_SIZE - sizeof(netudp_h) - 4);
    size += Serializer::PadLen(size);
    initDataBlock(dataf, size);
 
    // ----

    Socket * udps  = new Socket(dstaddr, SOCKET_UDP, SOCKTYPE_RAW, SOCKET_UDP);
    Socket * icmps = new Socket(dstaddr, SOCKET_ICMP, SOCKTYPE_RAW, SOCKET_ICMP);

    udps->init(false);
    icmps->init(false);
    udps->setSocketOption(SocketOption::SetNoFragment(0));

#   ifndef WIN32
    dropPriv();
#   endif

    /* init buffers */
    sockaddr_t    csock;
    netudp_h      udph;

    PathData    * udata   = NULL;
    char        * wptr    = NULL;
    bool          send    = true;
    bool          timeout = false;
    bool          pathd   = false;
    size_t        sz, buflen, idsz;
    ssize_t       wt, rd;

    uint16_t port = dstportm;    // port mask for ttl counting
    uint16_t srcp = TR_PORT_SRC;
    buflen        = MAX_BUFFER_SIZE;
    idsz          = sizeof(netudp_h) + size;

    CircularBuffer * rbuff = new CircularBuffer(buflen);
    CircularBuffer * wbuff = new CircularBuffer(buflen);

    udph.srcport = htons(srcp);
    udph.dstport = 0;
    udph.length  = htons(idsz);
    udph.chksum  = 0;

    if ( icmp )
        std::cout << "Sending ICMP datagrams to ";
    else
        std::cout << "Sending UDP datagrams (" << size << " bytes) to ";

    std::cout << dstname << ". count = " << count << " interval = " << interval
              << " milliseconds" << std::endl;

    uint16_t    ttl     = 0;
    uint16_t    maxhops = 30;
    uint16_t    phops   = maxhops;

    PathVector  pathseq(maxhops);
    HopIndex    lostq;

    printStatHeader();

    while ( ! Alarm )
    {
        if ( send || timeout ) 
        {
            if ( timeout )
                ttl--;
            if ( ttl > pathseq.size() )
                ttl = 0;

            if ( pathd && ttl == phops ) {
                ttl = 0;
                if ( udata && (udata->seq + 1) > (uint16_t) count )
                    break;
                if ( debug )
                    std::cout << "Sleep " << interval << " ms" << std::endl;
                sleep_ms(interval);
                printStatHeader();
            }

            if ( lostq.size() > mhoploss ) {
                HopIndex::iterator hIter = lostq.begin();
                phops   = (*hIter) - 1;
                ttl     = 0;
                timeout = false;
                send    = true;
                pathd   = true;
                lostq.clear();

                if ( debug )
                    std::cout << "Timeout limit reached at hop " << phops << std::endl;

                printStatHeader();
                continue;
            }

            PathData & pdata = pathseq.at(ttl++);

            EventManager::GetTimeOfDay(&tvin);

            pdata.secs  = tvin.tv_sec;
            pdata.usecs = tvin.tv_usec;

            if ( pathd )
                pdata.seq++;

            if ( icmp && pdata.proto == SOCKET_UDP )
                pdata.proto = SOCKET_ICMP;

            udata = &pdata;

            if ( timeout || pdata.proto == SOCKET_ICMP ) 
            {
                if ( timeout ) {
                    lostq.insert(ttl);
                    tvo.tv_sec = tvin.tv_sec;
                    timeout    = false;
                    send       = true;

                    if ( pathd )  // count as lost
                        continue;

                    if ( pdata.proto == SOCKET_ICMP ) 
                    {
                        if ( retry < 2 ) {
                            ttl--;
                            retry++;
                            continue;
                        }

                        // disable the hop
                        pdata.proto = 0; 
                        retry       = 0;
                        pdata.hop   = ttl;
                        
                        if ( debug )
                            std::cout << "  Hop " << ttl << " timed out." << std::endl;
                        
                        continue;
                    }
                    else 
                    { 
                        if ( retry < 3 ) {
                            if ( retry == 0 ) {
                                std::cout << std::setw(2) << ttl << ": "
                                    << std::setw(15) << IpAddr::ntop(pdata.ipaddr)
                                    << "  <" << pdata.seq << ">"
                                    << std::setw(10) << "*" << std::flush;
                            } else { 
                                std::cout << std::setw(10) << "*" << std::flush;
                            }

                            ttl--;
                            retry++;
                            continue;
                        }
                        
                        std::cout << std::setw(4) << "   !<u>" << std::endl;
                        pdata.proto = SOCKET_ICMP;
                        retry       = 0;
                    }
                }

                neticmp_h  req;
                req.type   = ICMP_ECHO;
                req.code   = 0;
                req.chksum = 0;
                req.id     = port + ttl;
                req.seq    = 0;
                req.chksum = Socket::IpChkSum(((uint16_t*)&req), sizeof(neticmp_h));

                if ( icmps->setSocketOption(IPPROTO_IP, IP_TTL, ttl) < 0 )
                    errorOut("ICMP setsockopt failed: " + udps->getErrorString());

                wt = icmps->write(&req, sizeof(neticmp_h));
            } 
            else if ( pdata.proto == SOCKET_UDP )
            {
                udph.dstport = htons(port+ttl);
                udph.chksum  = 0;

                if ( udps->setSocketOption(IPPROTO_IP, IP_TTL, ttl) < 0 )
                    errorOut("UDP setsockopt failed: " + udps->getErrorString());

                wbuff->reset();
                wbuff->write((void*)&udph, sizeof(netudp_h));
                wbuff->write((void*)dataf.data(), dataf.length());

                size_t rd   = idsz;
                char * rptr = wbuff->getReadPtr(&rd);

                wt = udps->write(rptr, rd);
                wbuff->setReadPtr(wt);
            }
            else  // skipped hop
            {
                send       = true;
                tvo.tv_sec = tvin.tv_sec;
                std::cout << std::setw(2) << pdata.hop << ": "
                          << std::setw(15) << IpAddr::ntop(pdata.ipaddr)
                          << "  <" << pdata.seq << ">"
                          << std::setw(10) << "*"
                          << std::setw(10) << "*"
                          << std::setw(10) << "*" << std::endl;
                continue;
            }

            tvo.tv_sec = tvin.tv_sec;
            send       = false;
            timeout    = false;
        }


        IcmpResponse  response;

        // read
        rbuff->reset();
        sz   = rbuff->writePtrAvailable();
        wptr = rbuff->getWritePtr(&sz);
        rd   = icmps->readFrom(wptr, sz, csock);

        if ( rd < 0 )
            errorOut("ICMP read failed: " + icmps->getErrorString());
        rbuff->setWritePtr(rd);

        if ( rd > 0 )
            rd = readIcmpResponse(rbuff, response);

        EventManager::GetTimeOfDay(&tvin);

        if ( rd > 0 && (response.icmph.type == ICMP_TIME_EXCEEDED
                     || response.icmph.type == ICMP_ECHOREPLY
                     || response.icmph.type == ICMP_DEST_UNREACH) )
        {
            netip_h   iph;
            neticmp_h icmph;
            netudp_h  udphr;
            uint16_t  hop = 0;
            float     rtt = 0.0;
            float     rtd = 0.0;
            float     avg = 0.0;

            sz   = rbuff->readAvailable();
           
            if ( response.icmph.type == ICMP_ECHOREPLY )
            {
                hop = response.icmph.id - port;
                lostq.erase(hop);
                if ( response.iph.srcaddr == dstaddr ) {  // echo reply from dst
                    pathd  = true;
                    phops  = hop;
                }

                iph = response.iph;
            }
            else 
            {
                if ( ! readIPHeader(rbuff, &iph) )
                    continue;

                if ( iph.dstaddr != dstaddr )  // not our packet
                    continue;

                if ( iph.protocol == SOCKET_ICMP ) {
                    if ( ! readIcmpHeader(rbuff, &icmph) )
                        continue;
                    hop = icmph.id - port;   // unmask hop id
                    lostq.clear();
                } else if ( iph.protocol == SOCKET_UDP ) {
                    if ( ! readUdpHeader(rbuff, &udphr) )
                        continue;
                    hop  = ntohs(udphr.dstport) - port; // unmask hop id
                    if ( response.icmph.type  == ICMP_DEST_UNREACH &&
                         response.iph.srcaddr == dstaddr )
                    {
                        pathd = true;
                        phops = hop;
                    }
                }
            }

            if ( hop == 0 )
                continue;

            if ( hop >= pathseq.size() ) {  // should never happen
                std::cout << " Invalid ttl " << hop
                    << " from " << IpAddr::ntop(iph.dstaddr) << std::endl;
                continue;
            }
                
            // path vector
            PathData & pdata = pathseq.at(hop-1);

            if ( pdata.seq == 0 || pdata.hop == 0 ) {
                pdata.hop    = hop;   
                pdata.ipaddr = response.iph.srcaddr;
            } else {
                if ( hop == phops && ! pathd )
                    phops++;
            }

            tv.tv_sec  = pdata.secs;
            tv.tv_usec = pdata.usecs;

            rtt = EventManager::TimevalDiffMs(&tvin, &tv);

            if ( pathd && pdata.seq > 0 )  // calc
            {
                if ( pdata.rtt > 0.0 )
                    rtd = ::fabs(rtt - pdata.rtt);

                if ( rtt < pdata.rtt_min || pdata.rtt_min == 0 )
                    pdata.rtt_min = rtt;
                if ( rtt > pdata.rtt_max )
                    pdata.rtt_max = rtt;

                if ( rtd > 0.0 )  {
                    pdata.rtd = rtd;
                    if ( rtd > pdata.rtd_max )
                        pdata.rtd_max = rtd;
                    if ( rtd < pdata.rtd_min || pdata.rtd_min == 0 )
                        pdata.rtd_min = rtd;
                    pdata.rtd_total += rtd;
                }

                pdata.rtt        = rtt;
                pdata.rtt_total += rtt;
                pdata.proto      = iph.protocol;
                pdata.cnt++;

                avg = (pdata.rtt_total / pdata.cnt);
            }

            std::cout << std::setw(2) << hop << ": " 
                << std::setw(15) << IpAddr::ntop(response.iph.srcaddr) 
                << "  <" << pdata.seq << ">"
                << std::setw(10) << std::setprecision(5) << rtt
                << std::setw(10) << std::setprecision(5) << avg
                << std::setw(10) << std::setprecision(5) << rtd;

            if ( iph.protocol == SOCKET_ICMP )
                std::cout << std::setw(4) << "    <i>";
            else
                std::cout << std::setw(4) << "    <u>";
            std::cout << std::endl;

            send  = true;
        } 
        else 
        { 
            sleep_ms(1);
        }

        if ( tvo.tv_sec == 0 || send  )
            tvo.tv_sec = tvin.tv_sec;
        else if ( (tvin.tv_sec - tvo.tv_sec) > mhoptime )
            timeout = true;
    }

    // finished; display results 
    std::cout << std::endl << std::endl << std::endl;
    std::cout << "Destination: " << IpAddr::ntop(dstaddr);
    if ( resolve )
        std::cout << " <" << AddrInfo::GetHostName(dstaddr) << ">  ";
    std::cout << " Hop count: " << phops << std::endl;

    std::cout << std::endl;
    std::cout << std::setw(3) << " hop" 
              << std::setw(15) << "       address     " 
              << std::setw(10) << "    loss%   " 
              << std::setw(8)  << "rtt (ms)" 
              << std::setw(8) << "min" 
              << std::setw(8) << "max" << " |" 
              << std::setw(10) << "  ipdv"
              << std::setw(10) << "min"
              << std::setw(10) << "max";

    if ( resolve )
        std::cout << "      dns";

    std::cout << std::endl
        << "------------------------------------------------------------------------------------------";
    if ( resolve )
        std::cout << "---------------------------";
    std::cout << std::endl;

    PathVector::iterator  pIter;
    for ( pIter = pathseq.begin(); pIter != pathseq.end(); ++pIter )
    {
        float        loss, rttavg, rtdavg;
        std::string  hopname;

        PathData   & pdata = *pIter;

        if ( pdata.hop == 0 || pdata.hop > phops )
            break;

        loss    = ( 100.0 - ( ((float)pdata.cnt / pdata.seq) * 100.0) );
        rttavg  = ( pdata.rtt_total / pdata.cnt );
        rtdavg  = ( pdata.rtd_total / (float) (pdata.cnt - 1) );
        hopname = IpAddr::ntop(pdata.ipaddr);

        std::cout << std::setw(3)  << pdata.hop << ": " 
                  << std::setw(15) << std::setiosflags(std::ios_base::right) <<  hopname 
                  << std::setw(8)  << loss << "% (" << pdata.cnt << "/" << pdata.seq << ")"
                  << std::setw(8) << std::setprecision(5) << rttavg
                  << std::setw(8) << std::setprecision(5) << pdata.rtt_min
                  << std::setw(8) << std::setprecision(5) << pdata.rtt_max << " |"
                  << std::setw(10) << std::setprecision(5) << rtdavg
                  << std::setw(10) << std::setprecision(5) << pdata.rtd_min
                  << std::setw(10) << std::setprecision(5) << pdata.rtd_max;
        if ( resolve )
            std::cout << "    <" << AddrInfo::GetHostName(pdata.ipaddr) << "> ";
        
        std::cout << std::endl;
    }

    delete udps;
    delete icmps;
    delete rbuff;
    delete wbuff;

    std::cout << "Finished." << std::endl;

#   ifdef WIN32
    WSACleanup();
#   endif

    return 0;
}



