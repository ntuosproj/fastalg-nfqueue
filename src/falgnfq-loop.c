/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgnfq-config.h"
#include "falgnfq-loop.h"
#include "falgnfq-private.h"

// XXX: Workaround buggy libnetfilter_queue header file
#define nfq_ip6hdr_snprintf nfq_ip6_snprintf

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <linux/netfilter.h>
#include <stdint.h>
#include <stdlib.h>

// Casting macros
#define IPHDR(x)    ((struct iphdr*)(x))
#define IP6_HDR(x)  ((struct ip6_hdr*)(x))
#define TCPHDR      ((struct tcphdr*)(x))
#define UDPHDR      ((struct udphdr*)(x))


struct falgnfq_loop {
    FalgnfqConfig *config;
    struct mnl_socket *nl;
    unsigned portid;
    size_t pkt_max;
};

static struct nlmsghdr* queue_pkt_init (
    char *pkt, uint16_t type, uint32_t queue_num) {

    struct nlmsghdr *nlh = mnl_nlmsg_put_header (pkt);
    nlh->nlmsg_type = (NFNL_SUBSYS_QUEUE << 8) | type;
    nlh->nlmsg_flags = NLM_F_REQUEST;

    struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(
        nlh, sizeof(struct nfgenmsg));
    nfg->nfgen_family = AF_UNSPEC;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = htons(queue_num);

    return nlh;
}

static int queue_verdict (FalgnfqLoop *loop, uint32_t id, uint32_t mark) {
    ERRMSG_INIT;
    char pkt[loop->pkt_max];
    struct nlmsghdr *nlh;

    nlh = queue_pkt_init (pkt, NFQNL_MSG_VERDICT, loop->config->queue_num);
    nfq_nlmsg_verdict_put (nlh, id, NF_REPEAT);
    nfq_nlmsg_verdict_put_mark (nlh, mark);
    
    if (mnl_socket_sendto (loop->nl, nlh, nlh->nlmsg_len) < 0) {
        error ("%s: mnl_socket_sendto: %s\n", __func__, ERRMSG);
        return -1;
    }
    debug ("  packet id %" PRIu32 ", verdict: set mark = %" PRIu32, id, mark);

    return 0;
}

static int queue_cb (const struct nlmsghdr *nlh, void *loop_generic) {
    ERRMSG_INIT;
    FalgnfqLoop *loop = loop_generic;

    struct nlattr *attr[NFQA_MAX + 1] = {};
    if (nfq_nlmsg_parse (nlh, attr) < 0) {
        error ("%s: nfq_nlmsg_parse: %s", __func__, ERRMSG);
        return MNL_CB_ERROR;
    }

    // packet header
    struct nfqnl_msg_packet_hdr *pkt_hdr;
    uint32_t pkt_id;
    if (attr[NFQA_PACKET_HDR] == NULL) {
        error ("%s: packet header not found", __func__);
        return MNL_CB_ERROR;
    }
    pkt_hdr = mnl_attr_get_payload (attr[NFQA_PACKET_HDR]);
    pkt_id = ntohl (pkt_hdr->packet_id);
    debug ("  packet id %" PRIu32, pkt_id);

    // packet mark
    uint32_t pkt_mark;
    if (attr[NFQA_MARK]) {
        pkt_mark = ntohl (mnl_attr_get_u32 (attr[NFQA_MARK]));
        debug ("  packet id %" PRIu32 ", mark %" PRIu32, pkt_id, pkt_mark);
    } else {
        debug ("  packet id %" PRIu32 ", mark not set", pkt_id);
    }

    // packet payload
    uint16_t pkt_len;
    uint32_t cap_len;
    char* pkt_payload;
    if (attr[NFQA_PAYLOAD] == NULL) {
        error ("  packet id %" PRIu32 ", payload not found", pkt_id);
        return MNL_CB_ERROR;
    }
    pkt_len = mnl_attr_get_payload_len (attr[NFQA_PAYLOAD]);
    pkt_payload = mnl_attr_get_payload (attr[NFQA_PAYLOAD]);

    if (attr[NFQA_CAP_LEN]) {
        debug ("  packet id %" PRIu32 ", cap_len %" PRIu32, pkt_id, cap_len);
        if (pkt_len != cap_len) {
            warning ("  packet id %" PRIu32 " may be truncated!", pkt_id);
        }
    }

    // print packet payload
    if (!falgnfq_ndebug) {
        char print_buf[2048];
        switch (loop->config->family) {
            case AF_INET:
                nfq_ip_snprintf (print_buf, 2048, IPHDR (pkt_payload));
                break;
            case AF_INET6:
                nfq_ip6_snprintf (print_buf, 2048, IP6_HDR (pkt_payload));
                break;
            default:
                strncpy (print_buf, "unavailable", 2048);
        }
        debug ("  packet id %" PRIu32 ", %s", pkt_id, print_buf);
    }

    // packet skbinfo
    uint32_t skbinfo;
    if (attr[NFQA_SKB_INFO]) {
        skbinfo = ntohl (mnl_attr_get_u32 (attr[NFQA_SKB_INFO]));
        if (skbinfo & NFQA_SKB_GSO) {
            warning ("  packet id %" PRIu32 " GSO!", pkt_id);
        }
    } else {
        skbinfo = 0;
    }

    // TODO: inspect packet content
    
    // send default verdict
    // TODO: send other verdicts
    queue_verdict (loop, pkt_id, loop->config->default_mark);

    return MNL_CB_OK;
}

FalgnfqLoop* falgnfq_loop_new (FalgnfqConfig *config) {
    ERRMSG_INIT;

    debug ("FalgnfqLoop new");

    struct mnl_socket *nl = mnl_socket_open (NETLINK_NETFILTER);
    if (nl == NULL) {
        error ("mnl_socket_open: %s\n", ERRMSG);
        return NULL;
    }

    if (mnl_socket_bind (nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        error ("mnl_socket_bind: %s\n", ERRMSG);
        return NULL;
    }

    size_t pkt_inet_max = 0xffff;
    size_t pkt_max = pkt_inet_max + MNL_SOCKET_BUFFER_SIZE;
    char pkt[pkt_max];
    struct nlmsghdr *nlh;

    // bind to the queue
    nlh = queue_pkt_init (pkt, NFQNL_MSG_CONFIG, 0);
    nfq_nlmsg_cfg_put_cmd(nlh, config->family, NFQNL_CFG_CMD_BIND);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        error ("mnl_socket_sendto: NFQNL_CFG_CMD_BIND: %s\n", ERRMSG);
        return NULL;
    }

    // set queue number and options
    nlh = queue_pkt_init (pkt, NFQNL_MSG_CONFIG, config->queue_num);
    nfq_nlmsg_cfg_put_params (nlh, NFQNL_COPY_PACKET, pkt_inet_max);
    mnl_attr_put_u32 (nlh, NFQA_CFG_FLAGS,
        htonl (NFQA_CFG_F_GSO | NFQA_CFG_F_UID_GID | NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32 (nlh, NFQA_CFG_MASK,
        htonl (NFQA_CFG_F_GSO | NFQA_CFG_F_UID_GID | NFQA_CFG_F_CONNTRACK));
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        error ("mnl_socket_sendto: NFQA_CFG_FLAGS: %s\n", ERRMSG);
        return NULL;
    }

    // allocate the struct and return
    FalgnfqLoop *loop = malloc (sizeof (FalgnfqLoop));
    if (loop == NULL) {
        error ("malloc: %s\n", ERRMSG);
        return NULL;
    }

    loop->config = config;
    loop->nl = nl;
    loop->portid = mnl_socket_get_portid (nl);
    loop->pkt_max = pkt_max;

    debug ("FalgnfqLoop new -> %p", loop);

    return loop;
}

int falgnfq_loop_run (FalgnfqLoop *loop) {
    ERRMSG_INIT;
    char pkt[loop->pkt_max];

    debug ("FalgnfqLoop %p run", loop);
    while (!falgnfq_exit) {
        debug ("FalgnfqLoop %p run: mnl_socket_recvfrom", loop);
        ssize_t pkt_len = mnl_socket_recvfrom (loop->nl, pkt, loop->pkt_max);
        if (pkt_len < 0) {
            if (errno == ENOBUFS) {
                warning ("mnl_socket_recvfrom: %s", ERRMSG);
            } else {
                error ("mnl_socket_recvfrom: %s", ERRMSG);
                return -1;
            }
        }

        debug ("FalgnfqLoop %p run: mnl_cb_run", loop);
        if (mnl_cb_run (pkt, pkt_len, 0, loop->portid, queue_cb, loop) < 0) {
            error ("mnl_cb_run: %s", ERRMSG);
            if (!falgnfq_ndebug) {
                error ("DEVELOPER_MODE: UNEXPECTED ERROR");
                return -1;
            }
        }
    }

    return 0;
}

void falgnfq_loop_free (FalgnfqLoop *loop) {
    debug ("FalgnfqLoop %p free", loop);
    mnl_socket_close (loop->nl);
    free (loop);
}
