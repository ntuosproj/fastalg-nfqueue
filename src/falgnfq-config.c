/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgnfq-config.h"
#include "falgnfq-private.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <glib.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

// Casting macros
#define SOCKADDR(x)      ((struct sockaddr*)(x))
#define SOCKADDR_IN(x)   ((struct sockaddr_in*)(x))
#define SOCKADDR_IN6(x)  ((struct sockaddr_in6*)(x))

#define set_error(...) \
    if (error != NULL) { \
        char* g_error = g_strdup_printf (__VA_ARGS__); \
        *error = strdup (g_error); \
        g_free (g_error); \
    }

#define IPV4_RECOMMENDED    "ipv4"
static const char *ipv4_value[] =
    { IPV4_RECOMMENDED, "IPV4",  "ip",  "inet",  "AF_INET",  "PF_INET",  NULL };

#define IPV6_RECOMMENDED    "ipv6"
static const char *ipv6_value[] =
    { IPV6_RECOMMENDED, "IPV6", "ip6", "inet6", "AF_INET6", "PF_INET6", NULL };


static int parse_number (const char *str, unsigned long *result) {
    int errno_save, rval;
    unsigned long ulres;
    char* endptr;

    errno_save = errno;
    errno = 0, rval = 0;

    ulres = strtoul (str, &endptr, 10);
    if (str == endptr || errno != 0) {
        rval = -1;
    } else {
        *result = ulres;
    }

    errno = errno_save;
    return rval;
}

static void show_config (FalgnfqConfig *config) {
    FalgprotoTransport transport = falgproto_get_transport (config->protocol);

    debug ("Config OK!");
    debug ("  family = %s",
        config->family == AF_INET  ? IPV4_RECOMMENDED :
        config->family == AF_INET6 ? IPV6_RECOMMENDED : "unknown");
    debug ("  transport = %s",
        transport == FALGPROTO_TRANSPORT_TCP ? "TCP" :
        transport == FALGPROTO_TRANSPORT_UDP ? "UDP" : "unknown");
    debug ("  queue_num = %" PRIu16, config->queue_num);
    debug ("  protocol = %s", falgproto_get_description (config->protocol));
    debug ("  default_mark = %" PRIu32, config->default_mark);
    for (size_t i = 0; i < config->maps_len; i++) {
        debug ("  maps[%zu].param = %s", i, config->maps[i].param);
        debug ("  maps[%zu].mark = %" PRIu32, i, config->maps[i].mark);

        switch (config->family) {
            case AF_INET: {
                char ipv4_str[INET_ADDRSTRLEN];
                inet_ntop (config->family,
                    &SOCKADDR_IN (config->maps[i].addr)->sin_addr,
                    ipv4_str, INET_ADDRSTRLEN);
                debug ("  maps[%zu].host = %s", i, ipv4_str);
                debug ("  maps[%zu].port = %" PRIu16, i,
                    ntohs (SOCKADDR_IN (config->maps[i].addr)->sin_port));
            } break;

            case AF_INET6: {
                char ipv6_str[INET6_ADDRSTRLEN];
                inet_ntop (config->family,
                    &SOCKADDR_IN6 (config->maps[i].addr)->sin6_addr,
                    ipv6_str, INET6_ADDRSTRLEN);
                debug ("  maps[%zu].host = %s", i, ipv6_str);
                debug ("  maps[%zu].port = %" PRIu16, i,
                    ntohs (SOCKADDR_IN6 (config->maps[i].addr)->sin6_port));
            } break;
        }
    }
}

FalgnfqConfig* falgnfq_config_new_from_arg (
        int argc, char *argv[], bool param_dup, char** error) {

    ERRMSG_INIT;

    debug ("FalgnfqConfig new");

    if (argc < 5) {
        set_error ("Too few arguments");
        goto free_nothing;
    } else if ((argc - 5) % 4) {
        set_error ("Missing mark number for `%s\'", argv[argc - 1]);
        goto free_nothing;
    }

    int family;
    bool family_set = false;
    for (int i = 0; !family_set && ipv4_value[i] != NULL; i++) {
        if (strcmp (argv[1], ipv4_value[i]) == 0) {
            family = AF_INET;
            family_set = true;
        }
    }
    for (int i = 0; !family_set && ipv6_value[i] != NULL; i++) {
        if (strcmp (argv[1], ipv6_value[i]) == 0) {
            family = AF_INET6;
            family_set = true;
        }
    }
    if (!family_set) {
        set_error ("Familiy `%s\' is unknown. Possible values are `"
            IPV4_RECOMMENDED "\' and `" IPV6_RECOMMENDED "\'.", argv[1]);
        goto free_nothing;
    }

    unsigned long queue_num_ulong;
    uint16_t queue_num;
    if (parse_number (argv[2], &queue_num_ulong) < 0) {
        set_error ("Queue number `%s\' is not a number", argv[2]);
        goto free_nothing;
    } else {
        queue_num = (uint16_t)queue_num_ulong;
    }

    int protocol = falgproto_get_protocol (argv[3]);
    if (protocol < 0) {
        set_error ("Protocol `%s\' not supported", argv[3]);
        goto free_nothing;
    }

    uint32_t default_mark;
    unsigned long default_mark_ulong;
    if (parse_number (argv[4], &default_mark_ulong) < 0) {
        set_error ("Default mark `%s\' is not a number", argv[4]);
        goto free_nothing;
    } else {
        default_mark = (uint32_t)default_mark_ulong;
    }

    size_t maps_len = ((unsigned int)argc - 4) / 4;
    size_t maps_ok = 0;
    FalgnfqConfig *config = malloc (
        sizeof (FalgnfqConfig) + sizeof (FalgnfqMap) * (maps_len + 1));

    if (config == NULL) {
        set_error ("malloc: %s", ERRMSG);
        goto free_nothing;
    }
    config->family = family;
    config->queue_num = queue_num;
    config->protocol = protocol;
    config->default_mark = default_mark;
    config->maps_len = maps_len;

    for (size_t i = 5; maps_ok < maps_len; maps_ok++, i += 4) {

        unsigned long mark_ulong;
        if (parse_number (argv[i + 1], &mark_ulong) < 0) {
            set_error ("Mark `%s\' is not a number", argv[i + 1]);
            goto free_maps;
        }
        config->maps[maps_ok].mark = (uint32_t)mark_ulong;
        config->maps[maps_ok].param_dup = param_dup;

        if (param_dup) {
            config->maps[maps_ok].param = strdup (argv[i]);
        } else {
            config->maps[maps_ok].param = argv[i];
        }
        config->maps[maps_ok].param_len = strlen (argv[i]);
        config->maps[maps_ok].addr = NULL;

        struct addrinfo *iter, *result, hints = {
            .ai_family = config->family
        };
        int gai_error = getaddrinfo (argv[i + 2], argv[i + 3], &hints, &result);
        if (gai_error != 0) {
            set_error ("getaddrinfo: host = %s, port = %s, error = %s",
                argv[i + 2], argv[i + 3], gai_strerror (gai_error));
            goto free_maps;
        }

        for (iter = result; iter != NULL; iter = iter->ai_next) {
            struct sockaddr *addr = malloc (iter->ai_addrlen);
            if (addr == NULL) {
                set_error ("malloc: %s", ERRMSG);
                goto free_maps;
            }

            memcpy (addr, iter->ai_addr, iter->ai_addrlen);
            config->maps[maps_ok].addr = addr;
            config->maps[maps_ok].addr_len = iter->ai_addrlen;
        }
    }
    config->maps[maps_ok].param = NULL;

    show_config (config);
    debug ("FalgnfqConfig new -> %p", config);

    return config;

free_maps:
    for (size_t i = 0; i < maps_ok; i++) {
        if (config->maps[i].param_dup) {
            free (config->maps[i].param);
        }
        if (config->maps[i].addr) {
            free (config->maps[i].addr);
        }
    }
free_config:
    free (config);
free_nothing:
    return NULL;
}

FalgnfqConfig* falgnfq_config_new_from_file (
    const char* filename, char** error) {

    set_error ("Function not implemented!");
    return NULL;
}

void falgnfq_config_free (FalgnfqConfig *config) {
    debug ("FalgnfqConfig %p free", config);
    for (size_t i = 0; i < config->maps_len; i++) {
        if (config->maps[i].param_dup) {
            free (config->maps[i].param);
        }
    }
    free (config);
}
