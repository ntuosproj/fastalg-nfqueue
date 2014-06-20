/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgnfq-config.h"
#include "falgnfq-private.h"

#include <errno.h>
#include <inttypes.h>
#include <glib.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

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
    debug ("Config OK!");
    debug ("  family = %s",
        config->family == AF_INET  ? IPV4_RECOMMENDED :
        config->family == AF_INET6 ? IPV6_RECOMMENDED : "unknown");
    debug ("  queue_num = %" PRIu16, config->queue_num);
    debug ("  protocol = %s", falgproto_get_description (config->protocol));
    debug ("  default_mark = %" PRIu32, config->default_mark);
    for (size_t i = 0; i < config->maps_len; i++) {
        debug ("  maps[%zd].param = %s", i, config->maps[i].param);
        debug ("  maps[%zd].mark = %" PRIu32, i, config->maps[i].mark);
    }
}

FalgnfqConfig* falgnfq_config_new_from_arg (
        int argc, char *argv[], bool param_dup, char** error) {

    ERRMSG_INIT;

    debug ("FalgnfqConfig new");

    if (argc < 5) {
        set_error ("Too few arguments");
        goto free_nothing;
    } else if ((argc - 5) % 2) {
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

    size_t maps_len = ((unsigned int)argc - 4) / 2;
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

    for (size_t i = 5; maps_ok < maps_len; maps_ok++, i += 2) {

        unsigned long mark_ulong;
        if (parse_number (argv[i + 1], &mark_ulong) < 0) {
            set_error ("Mark `%s\' is not a number", argv[i + 1]);
            goto free_maps;
        }
        config->maps[maps_ok].mark = (uint32_t)mark_ulong;
        config->maps[maps_ok].dup = param_dup;

        if (param_dup) {
            config->maps[maps_ok].param = strdup (argv[i]);
        } else {
            config->maps[maps_ok].param = argv[i];
        }
        config->maps[maps_ok].param_len = strlen (argv[i]);
    }
    config->maps[maps_ok].param = NULL;

    show_config (config);
    debug ("FalgnfqConfig new -> %p", config);

    return config;

free_maps:
    for (size_t i = 0; i < maps_ok; i++) {
        if (config->maps[i].dup) {
            free (config->maps[i].param);
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
        if (config->maps[i].dup) {
            free (config->maps[i].param);
        }
    }
    free (config);
}
