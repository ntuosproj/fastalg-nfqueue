/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_CONFIG_H
#define FALGNFQ_CONFIG_H

#include <falgproto.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>  // For AF_INET and AF_INET6


typedef struct falgnfq_map {
    uint32_t    mark;
    char*       param;
    size_t      param_len;
    bool        dup;
} FalgnfqMap;

typedef struct falgnfq_config {
    int             family;
    uint16_t        queue_num;
    FalgprotoType   protocol;
    uint32_t        default_mark;
    size_t          maps_len;
    FalgnfqMap      maps[];
} FalgnfqConfig;


FalgnfqConfig*  falgnfq_config_new_from_arg     (int argc,
                                                 char *argv[],
                                                 bool param_dup,
                                                 char** error);

FalgnfqConfig*  falgnfq_config_new_from_file    (const char* filename,
                                                 char** error);

void            falgnfq_config_free             (FalgnfqConfig *config);


#endif /* FALGNFQ_CONFIG_H */
