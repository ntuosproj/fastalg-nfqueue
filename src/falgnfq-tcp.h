/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_TCP_H
#define FALGNFQ_TCP_H

#include <falgproto.h>
#include <stdbool.h>
#include <stdint.h>

struct falgnfq_tcp;
typedef struct falgnfq_tcp FalgnfqTcp;

FalgnfqTcp*     falgnfq_tcp_new         (void);
bool            falgnfq_tcp_client      (FalgnfqTcp *tcp, int rng,
                                         FalgprotoPacket *pkt_first,
                                         FalgprotoPacket *pkt_last);
bool            falgnfq_tcp_server      (FalgnfqTcp *tcp, int rng,
                                         FalgprotoPacket *pkt_first,
                                         FalgprotoPacket *pkt_last);
void            falgnfq_tcp_free        (FalgnfqTcp *tcp);

#endif /* FALGNFQ_LOOP_H */

