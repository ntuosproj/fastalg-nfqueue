/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_PRIVATE_H
#define FALGNFQ_PRIVATE_H

#include <stdio.h>
#include <string.h>


// Logging

#define message_with_prefix(prefix, ...) \
    fputs (prefix, stdout); printf (__VA_ARGS__); putchar ('\n')

#ifndef NDEBUG
# define debug(...)      \
    if (!falgnfq_ndebug) { \
        message_with_prefix ("DEBUG: ", __VA_ARGS__); \
    }
#else
# define debug(...)
#endif

#define message(...)     printf (__VA_ARGS__); putchar ('\n')
#define warning(...)     message_with_prefix ("\033[1;33mWARNING\033[m: ", __VA_ARGS__)
#define critical(...)    message_with_prefix ("\033[1;33mCRITICAL\033[m: ", __VA_ARGS__)
#define error(...)       message_with_prefix ("\033[1;31mERROR\033[m: ", __VA_ARGS__)

extern int falgnfq_ndebug;


// Exit

extern int falgnfq_exit;


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

#endif /* FALGNFQ_PRIVATE_H */
