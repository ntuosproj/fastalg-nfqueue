/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_PRIVATE_H
#define FALGNFQ_PRIVATE_H

#include <stdint.h>
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

extern volatile int falgnfq_exit;


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

#define PKT_INFO(x) ((struct pkt_info*)(x))

struct pkt_buff;
typedef struct pkt_info {
    uint32_t            id;
    uint32_t            mark;
    struct pkt_buff*    pktb;
    void*               transport_header;
} PktInfo;

#endif /* FALGNFQ_PRIVATE_H */
