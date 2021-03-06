/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_PRIVATE_H
#define FALGNFQ_PRIVATE_H

#include <signal.h>
#include <stdio.h>
#include <string.h>


// Logging

#define message_with_prefix(prefix, ...) \
    fputs (prefix, stdout); printf (__VA_ARGS__); putchar ('\n')

#ifndef NDEBUG
# define debug(...)      \
    if (falgnfq_debug) { \
        message_with_prefix ("DEBUG:    ", __VA_ARGS__); \
    }
# define if_debug(level) if (falgnfq_debug >= (level))
#else
# define debug(...)
# define if_debug(level) if (0)
#endif

#define message(...)     printf (__VA_ARGS__); putchar ('\n')
#define warning(...)     message_with_prefix ("\033[1;33mWARNING\033[m:  ", __VA_ARGS__)
#define critical(...)    message_with_prefix ("\033[1;33mCRITICAL\033[m: ", __VA_ARGS__)
#define error(...)       message_with_prefix ("\033[1;31mERROR\033[m:    ", __VA_ARGS__)

// DO NOT USE this variable directly!
// Please use above debug and if_debug macro instead.
extern unsigned int falgnfq_debug;


// Exit

extern volatile sig_atomic_t falgnfq_exit;


// Casting macros

#define IPHDR(x)         ((struct iphdr*)(x))
#define IP6_HDR(x)       ((struct ip6_hdr*)(x))
#define TCPHDR           ((struct tcphdr*)(x))
#define UDPHDR           ((struct udphdr*)(x))
#define SOCKADDR(x)      ((struct sockaddr*)(x))
#define SOCKADDR_IN(x)   ((struct sockaddr_in*)(x))
#define SOCKADDR_IN6(x)  ((struct sockaddr_in6*)(x))


// Error message (thread-safe)

#define ERRMSG_INIT      char errbuf[256]; size_t errlen = sizeof (errbuf)
#define ERRMSG           errmsg (errno, errbuf, errlen)

static inline char* errmsg (int errnum, char *errbuf, size_t errlen) {
#ifndef STRERROR_R_CHAR_P // POSIX
    if (strerror_r (errnum, errbuf, errlen) != 0) {
        snprintf (errbuf, errlen, "Unknown error %d", errnum);
    }
    return errbuf;
#else
    return strerror_r (errnum, errbuf, errlen);
#endif
}


// Packet info

#ifdef USE_PKT_INFO

#include <stdint.h>
#define PKT_INFO(x) ((struct pkt_info*)(x))

struct pkt_buff;
typedef struct pkt_info {
    uint32_t            id;
    uint32_t            mark;
    struct pkt_buff*    pktb;
    void*               network_header;
    void*               transport_header;
} PktInfo;

#endif // USE_PKT_INFO


// TCP or IP packet in the sending queue

#ifdef USE_QUEUED_PKT

#include <stddef.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef struct queued_pkt {
    struct sockaddr_storage addr;
    socklen_t               addr_len;
    size_t                  len;
    char                    data[];
} QueuedPkt;

#endif // USE_QUEUED_PKT

#endif /* FALGNFQ_PRIVATE_H */
