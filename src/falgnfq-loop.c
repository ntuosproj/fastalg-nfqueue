/* vim: set sw=4 ts=4 sts=4 et: */

#include "config.h"
#include "falgnfq-config.h"
#include "falgnfq-loop.h"
#include "falgnfq-private.h"
#include "falgnfq-dump.h"

// XXX: Workaround buggy libnetfilter_queue header file
#define nfq_ip6hdr_snprintf nfq_ip6_snprintf

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <inttypes.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv6.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdlib.h>

// Casting macros
#define IPHDR(x)    ((struct iphdr*)(x))
#define IP6_HDR(x)  ((struct ip6_hdr*)(x))
#define TCPHDR      ((struct tcphdr*)(x))
#define UDPHDR      ((struct udphdr*)(x))


struct proto_info {
    FalgprotoTransport      transport;
    FalgprotoParamGetter    param_getter;
    FalgprotoPrinter        printer;
    FalgprotoMatcher        matcher;
};

struct falgnfq_loop {
    FalgnfqConfig*      config;
    struct proto_info   proto;      // (cache) protocol info
    struct mnl_socket*  nl;         // netlink socket
    unsigned            portid;     // (cache) netlink socket portid
    size_t              pkt_max;    // maximal possible netlink packet
    GHashTable*         pkts;       // a hash table of FalgprotoPacket
};

/* We only process one transport layer protocol (TCP or UDP), so
 * using source port and destination port is enough. We encode
 * the source port and destination port into an integer, so memory
 * allocation for the hash key is not needed. */
#define PACKET_KEY(sport,dport) \
    GUINT_TO_POINTER ((unsigned int)(((uint32_t)dport) * 65536 + sport))

#define PKT_INFO(x) ((struct pkt_info*)(x))

struct pkt_info {
    uint32_t            id;
    uint32_t            mark;
    struct pkt_buff*    pktb;
};

/* The first item in the list is not used to store packets.
 * Its only significant field is data, which is used to store
 * the pointer to the last packet in the list.
 *
 * Other items are used to store packets, with data field used
 * to store the other information using struct pkt_info.
 */
#define ITEM_SIZE   (sizeof (FalgprotoPacket) + sizeof (struct pkt_info))
#define FIRST_PKT(list)   ((list)->next)
#define LAST_PKT(list)    ((FalgprotoPacket*)((list)->data))
#define GET_PKT_INFO(x) \
    (struct pkt_info*)(((char*)(x)) + sizeof (FalgprotoPacket))

static FalgprotoPacket* packet_list_new (void) {
    FalgprotoPacket *list = g_slice_alloc (ITEM_SIZE);
    list->next = NULL;
    list->data = list;
    list->payload = NULL;
    list->len = 0;
    return list;
}

static void packet_list_append (
    FalgprotoPacket *head, char *payload, size_t len,
    uint32_t id, uint32_t mark, struct pkt_buff *pktb) {

    FalgprotoPacket *item = g_slice_alloc (ITEM_SIZE);
    struct pkt_info *info = GET_PKT_INFO (item);

    info->id = id;
    info->mark = mark;
    info->pktb = pktb;

    item->next = NULL;
    item->data = info;
    item->payload = payload;
    item->len = len;

    FalgprotoPacket *last = head->data;
    last->next = item;
    head->data = item;
}

static void packet_list_free (void *head) {
    FalgprotoPacket *iter = head;
    FalgprotoPacket *next = iter->next;

    g_slice_free1 (ITEM_SIZE, iter);
    for (iter = next; iter != NULL; iter = next) {
        next = iter->next;
        pktb_free (PKT_INFO (iter->data)->pktb);
        g_slice_free1 (ITEM_SIZE, iter);
    }
}

static struct nlmsghdr* queue_pkt_init (
    char *pkt, uint16_t type, uint16_t queue_num) {

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

static void queue_verdict (FalgnfqLoop *loop,
    FalgprotoPacket *list, void *key, uint32_t mark) {

    ERRMSG_INIT;
    char pkt[loop->pkt_max];
    struct nlmsghdr *nlh;

    for (FalgprotoPacket *iter = list->next; iter != NULL; iter = iter->next) {
        nlh = queue_pkt_init (pkt, NFQNL_MSG_VERDICT, loop->config->queue_num);
        nfq_nlmsg_verdict_put (nlh, (int)(PKT_INFO (iter->data)->id), NF_REPEAT);
        nfq_nlmsg_verdict_put_mark (nlh, mark);

        debug ("  packet id %" PRIu32 ", verdict: set mark = %" PRIu32,
            PKT_INFO (iter->data)->id, mark);

        if (mnl_socket_sendto (loop->nl, nlh, nlh->nlmsg_len) < 0) {
            error ("%s: mnl_socket_sendto: %s\n", __func__, ERRMSG);
        }
    }

    g_hash_table_remove (loop->pkts, key);
}

/* TODO: All NULL checks in this function should be removed when
 *       protocol support in fastalg-protocol are completed because
 *       there will be no need to check whether a function is implemented.
 */
static int before_get_param (FalgprotoPacket *pkt,
    FalgnfqLoop *loop, const char *caller_name) {

    if_debug {
        if (loop->proto.printer == NULL) {
            warning ("  %s: application layer data printer or debugger "
                "is not available", caller_name);
        } else {
            loop->proto.printer (stdout, pkt);
        }
    }

    if (loop->proto.param_getter == NULL) {
        critical ("  %s: no param getter for %s, fallback to default mark",
            caller_name, falgproto_get_description (loop->config->protocol));
        return -1;
    }
    if (loop->proto.matcher == NULL) {
        critical ("  %s: no matcher for %s, fallback to default mark",
            caller_name, falgproto_get_description (loop->config->protocol));
        return -1;
    }

    return 0;
}

static bool tcp_inspect (
    FalgnfqLoop *loop, struct tcphdr *th,
    FalgprotoPacket *list, void *key,
    struct pkt_info info, uint32_t *verdict) {

    error ("  %s: function not implemented", __func__);
    *verdict = loop->config->default_mark;
    return true;
}


/* XXX: nfq_udp_get_payload does not work at all. Its implementation is WRONG!
 *      Therefore, we implement our version udp_get_payload.
 */
static void* udp_get_payload (struct udphdr *udph, struct pkt_buff *pktb) {
    uint16_t pkt_len = ntohs (udph->len);

    /* malformed UDP packet length. */
    if (pkt_len < 8) {
        return NULL;
    }

    /* packet is too short. */
    uint8_t *transport_header = pktb_transport_header (pktb);
    uint8_t *tail = pktb_data (pktb) + pktb_len (pktb);
    if (transport_header + pkt_len > tail) {
        return NULL;
    }

    /* UDP packet header is 8 bytes. */
    return transport_header + 8;
}

/* XXX: nfq_udp_get_payload_len is WRONG!
 *      We have to implement our version of it.
 *      Why there is so many bugs in libnetfilter_queue?
 */
static unsigned int udp_get_payload_len (
    struct udphdr *udph, struct pkt_buff *pktb) {

    uint8_t *transport_header = pktb_transport_header (pktb);
    uint8_t *tail = pktb_data (pktb) + pktb_len (pktb);
    return (unsigned int)(tail - transport_header) - 8;
}

static bool udp_inspect (
    FalgnfqLoop *loop, struct udphdr *uh,
    FalgprotoPacket *list, void *key,
    struct pkt_info info, uint32_t *verdict) {

    char *payload = udp_get_payload (uh, info.pktb);
    size_t len = udp_get_payload_len (uh, info.pktb);
    debug ("  %s: %zu bytes of payload", __func__, len);
    packet_list_append (list, payload, len, info.id, info.mark, info.pktb);
    if (payload == NULL) {
        warning ("  %s: this is not a valid UDP packet!", __func__);
        warning ("  %s: please check your ip/nftables settings", __func__);
        *verdict = loop->config->default_mark;
        return true;
    }

    FalgprotoPacket *pkt = FIRST_PKT (list);
    if (before_get_param (pkt, loop, __func__) < 0) {
        *verdict = loop->config->default_mark;
        return true;
    }

    FalgprotoParam param = loop->proto.param_getter (pkt);

    if (param.result < 0) {
        error ("  %s: error while getting param from the packet", __func__);
        *verdict = loop->config->default_mark;
        return true;
    } else if (param.result > 0) {
        debug ("  %s: incomplete data, waiting for the next packet", __func__);
        return false;
    }

    uint32_t mark = loop->config->default_mark;
    if (param.param) {
        debug ("  %s: param is %*s", __func__, (int)(param.len), param.param);
        for (size_t i = 0; i < loop->config->maps_len; i++) {
            if (loop->proto.matcher (param.param, param.len,
                loop->config->maps[i].param,
                loop->config->maps[i].param_len)) {

                mark = loop->config->maps[i].mark;
                debug ("  %s: maps[%zu] matched (%s)",
                    __func__, i, loop->config->maps[i].param);
                debug ("  %s: new mark is %" PRIu32, __func__, mark);
                break;
            }
        }
    }

    if (param.dup) {
        free (param.param);
    }

    *verdict = mark;
    return true;
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

    if_debug {
        char dump_file[50]= {0};
        snprintf(dump_file, 50, "packet_%" PRIu32 "_dumpfile", pkt_id);
        if(falgnfq_dump_payload(dump_file, pkt_payload, pkt_len) == pkt_len){
            debug ("  packet id %" PRIu32 ", payload dumped.", pkt_id);
        }else{
            error ("  packet id %" PRIu32 ", payload not correctly dumped.", pkt_id);
        }
    }
#ifdef HAVE_LIBNETFILTER_QUEUE_GSO
    if (attr[NFQA_CAP_LEN]) {
        cap_len = ntohl (mnl_attr_get_u32 (attr[NFQA_CAP_LEN]));
        debug ("  packet id %" PRIu32 ", cap_len %" PRIu32, pkt_id, cap_len);
        if (pkt_len != cap_len) {
            warning ("  packet id %" PRIu32 " may be truncated!", pkt_id);
        }
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
#endif

    /* Use functions provided by libnetfilter_queue to parse the packet.
     * XXX: Using this functions causes extra malloc and copying, which
     *      may have performance impact.
     *
     * We always use AF_INET here because pktb_alloc does not
     * recognize AF_INET6
     */
    struct pkt_buff *pktb = pktb_alloc (AF_INET, pkt_payload, pkt_len, 0);
    if (pktb == NULL) {
        error ("  packet id %" PRIu32 ", cannot allocate pkt_buff: %s",
            pkt_id, ERRMSG);
        return MNL_CB_ERROR;
    }

    switch (loop->config->family) {
        case AF_INET: {
            struct iphdr *iph = nfq_ip_get_hdr (pktb);
            if (iph == NULL) {
                error ("  packet id %" PRIu32 ", malformed IPv4 packet", pkt_id);
                goto free_pktb;
            }

            if (nfq_ip_set_transport_header (pktb, iph) < 0) {
                error ("  packet id %" PRIu32 ", truncated IPv4 packet", pkt_id);
            }

            debug ("  packet id %" PRIu32 ", %s", pkt_id,
                iph->protocol == IPPROTO_TCP ? "layer 4 is TCP" :
                iph->protocol == IPPROTO_UDP ? "layer 4 is UDP" :
                "unknown layer 4 protocol");

            if_debug {
                char print_buf[2048];
                nfq_ip_snprintf (print_buf, 2048, iph);
                debug ("  packet id %" PRIu32 ", %s", pkt_id, print_buf);
            }
        } break;

        case AF_INET6: {
            struct ip6_hdr *ip6h = nfq_ip6_get_hdr (pktb);
            if (ip6h == NULL) {
                error ("  packet id %" PRIu32 ", malformed IPv6 packet", pkt_id);
                goto free_pktb;
            }

            // XXX: Which target should we use?
            if (nfq_ip6_set_transport_header (pktb, ip6h, IPPROTO_NONE) < 0) {
                error ("  packet id %" PRIu32 ", truncated IPv6 packet", pkt_id);
            }

            if_debug {
                char print_buf[2048];
                nfq_ip6_snprintf (print_buf, 2048, ip6h);
                debug ("  packet id %" PRIu32 ", %s", pkt_id, print_buf);
            }
        } break;

        default:
            error ("  packet id %" PRIu32 ", unknown layer 3 protocol", pkt_id);
            goto free_pktb;
    }

    // make the info struct
    struct pkt_info info = {
        .id = pkt_id,
        .mark = pkt_mark,
        .pktb = pktb
    };

    // get transport layer header, inspect data, and make verdict
    uint32_t verdict;
    void *key;
    switch (loop->proto.transport) {
        case FALGPROTO_TRANSPORT_TCP: {
            struct tcphdr *th = nfq_tcp_get_hdr (pktb);
            if (th == NULL) {
                error ("  packet id %" PRIu32 ", malformed TCP packet", pkt_id);
                goto free_pktb;
            }

            if_debug {
                char print_buf[2048];
                nfq_tcp_snprintf (print_buf, 2048, th);
                debug ("  packet id %" PRIu32 ", %s", pkt_id, print_buf);
            }

            key = PACKET_KEY (ntohs (th->source), ntohs (th->dest));
            FalgprotoPacket *list = g_hash_table_lookup (loop->pkts, key);
            if (list == NULL) {
                list = packet_list_new ();
                g_hash_table_insert (loop->pkts, key, list);
            }

            if (!tcp_inspect (loop, th, list, key, info, &verdict)) {
                debug ("  packet id %" PRIu32 ", saved in the list", pkt_id);
                return MNL_CB_OK;
            }

            queue_verdict (loop, list, key, verdict);
        } break;

        case FALGPROTO_TRANSPORT_UDP: {
            struct udphdr *uh = nfq_udp_get_hdr (pktb);
            if (uh == NULL) {
                error ("  packet id %" PRIu32 ", malformed UDP packet", pkt_id);
                goto free_pktb;
            }

            if_debug {
                char print_buf[2048];
                nfq_udp_snprintf (print_buf, 2048, uh);
                debug ("  packet id %" PRIu32 ", %s", pkt_id, print_buf);
            }

            key = PACKET_KEY (ntohs (uh->source), ntohs (uh->dest));
            FalgprotoPacket *list = g_hash_table_lookup (loop->pkts, key);
            if (list == NULL) {
                list = packet_list_new ();
                g_hash_table_insert (loop->pkts, key, list);
            }

            if (!udp_inspect (loop, uh, list, key, info, &verdict)) {
                debug ("  packet id %" PRIu32 ", saved in the list", pkt_id);
                return MNL_CB_OK;
            }

            queue_verdict (loop, list, key, verdict);
        } break;

        default:
            error ("  packet id %" PRIu32 ", unknown layer 4 protocol", pkt_id);
            goto free_pktb;
    }

    return MNL_CB_OK;

free_pktb:
    pktb_free (pktb);
    return MNL_CB_ERROR;
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
    size_t pkt_max = pkt_inet_max + (size_t)(MNL_SOCKET_BUFFER_SIZE);
    char pkt[pkt_max];
    struct nlmsghdr *nlh;

    // bind to the queue
    nlh = queue_pkt_init (pkt, NFQNL_MSG_CONFIG, config->queue_num);
    nfq_nlmsg_cfg_put_cmd(nlh, (uint16_t)(config->family), NFQNL_CFG_CMD_BIND);
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        error ("mnl_socket_sendto: NFQNL_CFG_CMD_BIND: %s\n", ERRMSG);
        return NULL;
    }

    // set queue number and options
    nlh = queue_pkt_init (pkt, NFQNL_MSG_CONFIG, config->queue_num);
    nfq_nlmsg_cfg_put_params (nlh, NFQNL_COPY_PACKET, (int)pkt_inet_max);
    mnl_attr_put_u32 (nlh, NFQA_CFG_FLAGS,
        htonl (
#ifdef HAVE_LIBNETFILTER_QUEUE_GSO
            NFQA_CFG_F_GSO |
#endif
            NFQA_CFG_F_CONNTRACK));
    mnl_attr_put_u32 (nlh, NFQA_CFG_MASK,
        htonl (
#ifdef HAVE_LIBNETFILTER_QUEUE_GSO
            NFQA_CFG_F_GSO |
#endif
            NFQA_CFG_F_CONNTRACK));
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
    loop->proto.transport = falgproto_get_transport (config->protocol);
    loop->proto.param_getter = falgproto_get_param_getter (config->protocol);
    loop->proto.printer = falgproto_get_printer (config->protocol);
    loop->proto.matcher = falgproto_get_matcher (config->protocol);
    loop->nl = nl;
    loop->portid = mnl_socket_get_portid (nl);
    loop->pkt_max = pkt_max;
    loop->pkts = g_hash_table_new_full (
        g_direct_hash, g_direct_equal, NULL, packet_list_free);

    debug ("FalgnfqLoop new -> %p", loop);

    return loop;
}

int falgnfq_loop_run (FalgnfqLoop *loop) {
    ERRMSG_INIT;
    char pkt[loop->pkt_max];

    debug ("FalgnfqLoop %p run", loop);
#ifndef NDEBUG
    while (!falgnfq_exit) {
#else
    while (true) {
#endif
        debug ("FalgnfqLoop %p run: mnl_socket_recvfrom", loop);
        ssize_t pkt_rval = mnl_socket_recvfrom (loop->nl, pkt, loop->pkt_max);
        if (pkt_rval < 0) {
            if (errno == ENOBUFS) {
                warning ("mnl_socket_recvfrom: %s", ERRMSG);
                continue;
            } else if (errno == EINTR || errno == EWOULDBLOCK) {
                debug ("FalnfqLoop %p: mnl_socket_recvfrom interrupted", loop);
                continue;
            } else {
                error ("mnl_socket_recvfrom: %s", ERRMSG);
                return -1;
            }
        }

        size_t pkt_len = (size_t)pkt_rval;
        debug ("FalgnfqLoop %p run: mnl_cb_run", loop);
        if (mnl_cb_run (pkt, pkt_len, 0, loop->portid, queue_cb, loop) < 0) {
            error ("mnl_cb_run: %s", ERRMSG);
            if_debug {
                error ("DEVELOPER_MODE: UNEXPECTED ERROR, EXIT NOW!");
                return -1;
            }
        }
    }

    return 0;
}

void falgnfq_loop_free (FalgnfqLoop *loop) {
    debug ("FalgnfqLoop %p free", loop);
    mnl_socket_close (loop->nl);
    g_hash_table_destroy (loop->pkts);
    free (loop);
}
