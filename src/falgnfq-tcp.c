/* vim: set sw=4 ts=4 sts=4 et: */

#define USE_PKT_INFO
#define USE_QUEUED_PKT

#include "config.h"
#include "falgnfq-private.h"
#include "falgnfq-rng.h"
#include "falgnfq-tcp.h"

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    STATE_INITIAL,
    STATE_CLIENT_SYN_RCVD,
    STATE_CLIENT_SYNACK_SENT,
    STATE_CLIENT_ACK_RCVD,
    STATE_SERVER_SYN_SENT,
    STATE_SERVER_SYNACK_RCVD,
    STATE_SERVER_ACK_SENT
};

struct falgnfq_tcp {
    unsigned int        state;

    struct sockaddr*    addr;
    socklen_t           addr_len;
    GQueue*             queue_ip;
    GQueue*             queue_tcp;

    struct pkt_buff*    client_syn;
    struct tcphdr*      client_syn_th;
    struct pkt_buff*    client_ack;
    struct tcphdr*      client_ack_th;

    uint32_t            client_seq;
    uint32_t            our_seq;
};

FalgnfqTcp* falgnfq_tcp_new (
    struct sockaddr *addr, socklen_t addr_len,
    GQueue *queue_ip, GQueue *queue_tcp) {

    FalgnfqTcp *tcp = g_slice_alloc (sizeof (FalgnfqTcp));
    tcp->state = STATE_INITIAL;
    tcp->addr = addr;
    tcp->addr_len = addr_len;
    tcp->queue_ip = queue_ip;
    tcp->queue_tcp = queue_tcp;
    tcp->client_syn = NULL;
    tcp->client_syn_th = NULL;
    tcp->client_ack = NULL;
    tcp->client_ack_th = NULL;

    return tcp;
}

// Please make sure the checksum field is 0 before calling this function
static void tcp_fill_checksum (void *pkt, size_t len) {
    uint16_t *word = pkt;
    struct tcphdr *th = pkt;
    uint32_t checksum = 0;

    for (; len > 1; len -= sizeof (uint16_t)) {
        checksum += (*word);
        word++;
    }
    if (len) {
        checksum += *(uint8_t*)(word);
    }

    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    th->check = ((uint16_t)(~checksum));
    debug ("  %s: checksum is 0x%04" PRIx16 " (%" PRIu16 ")",
        __func__, ntohs (th->check), ntohs (th->check));
}

bool falgnfq_tcp_client (FalgnfqTcp *tcp, int rng,
    FalgprotoPacket *pkt_first, FalgprotoPacket *pkt_last) {

    ERRMSG_INIT;

    switch (tcp->state) {
        case STATE_INITIAL: {
            struct pkt_info *info = pkt_last->data;
            struct tcphdr *th = info->transport_header;

            if (!th->syn) {
                error ("  %s: [SYN] the SYN flag is not set", __func__);
                return false;
            }
            if (th->ack) {
                error ("  %s: [SYN] the ACK flag is set", __func__);
                return false;
            }

            tcp->client_seq = ntohl (th->seq);
            tcp->our_seq = falgnfq_rng_gen (rng);

            debug ("  %s: [SYN] client sequence number is %" PRIu32,
                __func__, tcp->client_seq);
            debug ("  %s: [SYN] our sequence number will be %" PRIu32,
                __func__, tcp->our_seq);
            debug ("  %s: [SYN] preparing to send SYN-ACK", __func__);


            const size_t synack_len = sizeof (struct tcphdr);
            QueuedPkt *tcppkt = malloc (sizeof (QueuedPkt) + synack_len);
            if (tcppkt == NULL) {
                error ("  %s: malloc: %s", __func__, ERRMSG);
                return false;
            }

            struct tcphdr *synack = (void*)(tcppkt->data);

            tcppkt->len = synack_len;
            *synack = (struct tcphdr) {
                .source     = th->dest,
                .dest       = th->source,
                .seq        = htonl (tcp->our_seq),
                .ack_seq    = htonl (tcp->client_seq + 1),
                .doff       = sizeof (struct tcphdr) / 4,
                .ack        = 1,
                .syn        = 1,
                .window     = 0xffff // XXX: use the correct window size
            };

            tcp_fill_checksum (tcppkt->data, tcppkt->len);
            memcpy (&tcppkt->addr, tcp->addr, tcp->addr_len);
            tcppkt->addr_len = tcp->addr_len;

            g_queue_push_tail (tcp->queue_tcp, tcppkt);

            tcp->state++;
        } break;

    }
    return false;
}

bool falgnfq_tcp_server (FalgnfqTcp *tcp, int rng,
    FalgprotoPacket *pkt_first, FalgprotoPacket *pkt_last) {

    return false;
}

void falgnfq_tcp_free (FalgnfqTcp *tcp) {
    g_slice_free1 (sizeof (FalgnfqTcp), tcp);
}
