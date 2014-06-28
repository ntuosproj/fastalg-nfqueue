/* vim: set sw=4 ts=4 sts=4 et: */
#ifndef FALGNFQ_TCP_H
#define FALGNFQ_TCP_H

#include <glib.h>
#include <falgproto.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>

struct falgnfq_tcp;
typedef struct falgnfq_tcp FalgnfqTcp;

FalgnfqTcp*     falgnfq_tcp_new         (struct sockaddr *addr,
                                         socklen_t addr_len,
                                         GQueue *queue_ip,
                                         GQueue *queue_tcp);
bool            falgnfq_tcp_client      (FalgnfqTcp *tcp, int rng,
                                         FalgprotoPacket *pkt_first,
                                         FalgprotoPacket *pkt_last);
bool            falgnfq_tcp_server      (FalgnfqTcp *tcp, int rng,
                                         FalgprotoPacket *pkt_first,
                                         FalgprotoPacket *pkt_last);
void            falgnfq_tcp_free        (FalgnfqTcp *tcp);

#endif /* FALGNFQ_LOOP_H */

