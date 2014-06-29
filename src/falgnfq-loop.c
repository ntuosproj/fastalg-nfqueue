/* vim: set sw=4 ts=4 sts=4 et: */

#define USE_PKT_INFO
#define USE_QUEUED_PKT

#include "config.h"
#include "falgnfq-config.h"
#include "falgnfq-dump.h"
#include "falgnfq-loop.h"
#include "falgnfq-private.h"
#include "falgnfq-rng.h"
#include "falgnfq-tcp.h"

#define LIBNETFILTER_QUEUE_IS_VERY_BUGGY

// XXX: Workaround buggy libnetfilter_queue functions
#ifdef LIBNETFILTER_QUEUE_IS_VERY_BUGGY
# define nfq_ip6hdr_snprintf    nfq_ip6_snprintf
#endif // LIBNETFILTER_QUEUE_IS_VERY_BUGGY

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
#include <poll.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

// XXX: Workaround buggy libnetfilter_queue functions
#ifdef LIBNETFILTER_QUEUE_IS_VERY_BUGGY
# define nfq_tcp_get_payload        tcp_get_payload
# define nfq_tcp_get_payload_len    tcp_get_payload_len
# define nfq_udp_get_payload        udp_get_payload
# define nfq_udp_get_payload_len    udp_get_payload_len
# define nfq_ip_snprintf            ip_snprintf
#endif // LIBNETFILTER_QUEUE_IS_VERY_BUGGY


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
    int                 nl_fd;      // netlink socket file descriptor
    unsigned            portid;     // (cache) netlink socket portid
    size_t              pkt_max;    // maximal possible netlink packet
    GHashTable*         pkts;       // a hash table of FalgprotoPacket
    int                 rng;        // (TCP only) random number generator
    int                 raw_ip;     // (TCP only) raw IPv4 / IPv6 socket
    GQueue              raw_ip_q;   // (TCP only) raw IPv4 / IPv6 packet queue
    int                 raw_tcp;    // (TCP only) raw TCP socket
    GQueue              raw_tcp_q;  // (TCP only) raw TCP packet queue
};

static struct sockaddr* sockaddr_copy (struct sockaddr *addr) {
    switch (addr->sa_family) {
        case AF_INET: {
            struct sockaddr_in *na = g_slice_new (struct sockaddr_in);
            *na = *SOCKADDR_IN (addr);
            return SOCKADDR (na);
        }
        case AF_INET6: {
            struct sockaddr_in6 *na = g_slice_new (struct sockaddr_in6);
            *na = *SOCKADDR_IN6 (addr);
            return SOCKADDR (na);
        }
    }
    return NULL;
}

static void sockaddr_free (void *addr) {
    switch (SOCKADDR (addr)->sa_family) {
        case AF_INET:
            g_slice_free1 (sizeof (struct sockaddr_in), addr);
            break;
        case AF_INET6:
            g_slice_free1 (sizeof (struct sockaddr_in6), addr);
            break;
    }
}

static unsigned int sockaddr_hash (const void *addr) {
    switch (SOCKADDR (addr)->sa_family) {
        case AF_INET: {
            struct sockaddr_in *inaddr = SOCKADDR_IN (addr);
            uint16_t port = inaddr->sin_port;
            uint16_t *uint16 = (uint16_t*)&(inaddr->sin_addr.s_addr);
            uint32_t host = (uint32_t)(uint16[0]) + uint16[1];
            return (host << 16) + port;
        }
        case AF_INET6: {
            struct sockaddr_in6 *in6addr = SOCKADDR_IN6 (addr);
            uint16_t port = in6addr->sin6_port;
            uint16_t *uint16 = (uint16_t*)(in6addr->sin6_addr.s6_addr);
            uint32_t host = 0;
            for (size_t i = 0; i < 8; i++) {
                host += (uint32_t)(uint16[i]);
            }
            return (host << 16) + port;
        }
    }
    return GPOINTER_TO_UINT (addr);
}

static inline int sockaddr_in_equal (
    const struct sockaddr_in *a, const struct sockaddr_in *b) {

    return a->sin_port == b->sin_port &&
           a->sin_addr.s_addr == b->sin_addr.s_addr;
}

static inline int sockaddr_in6_equal (
    const struct sockaddr_in6 *a, const struct sockaddr_in6 *b) {

    return a->sin6_port == b->sin6_port &&
           a->sin6_flowinfo == b->sin6_flowinfo &&
           a->sin6_scope_id == b->sin6_scope_id &&
           !memcmp (a->sin6_addr.s6_addr, b->sin6_addr.s6_addr, 16);
}

static int sockaddr_equal (const void *a, const void *b) {
    const struct sockaddr *sa = a;
    const struct sockaddr *sb = b;

    if (sa->sa_family != sb->sa_family) {
        return false;
    }

    switch (sa->sa_family) {
        case AF_INET:
            return sockaddr_in_equal (SOCKADDR_IN (sa), SOCKADDR_IN (sb));
        case AF_INET6:
            return sockaddr_in6_equal (SOCKADDR_IN6 (sa), SOCKADDR_IN6 (sb));
    }

    return false;
}

#define TRANSPORT_STATUS(x)  ((struct transport_status*)(x))
#define TCP_STATUS(x)        ((struct tcp_status*)(x))
#define UDP_STATUS(x)        ((struct udp_status*)(x))

typedef struct transport_status {
    FalgprotoPacket*        last;
} TransportStatus;

typedef struct tcp_status {
    TransportStatus         inherited;
    FalgnfqTcp*             tcp;
    struct sockaddr_storage addr;
    socklen_t               addr_len;
} TcpStatus;

typedef struct udp_status {
    TransportStatus         inherited;
} UdpStatus;

/* The first item in the list is not used to store packets.
 * Its only significant field is data, which is used to store
 * information of the entire connection. It must contain the
 * pointer to the last packet in the list, so insertion to the
 * list can be done in constant time.
 *
 * Other items are used to store packets, with data field used
 * to store the other information using struct pkt_info.
 *
 *
 * Example:
 *
 * head->payload   is unused.
 * head->len       is unused.
 * head->data      is a (struct tcp_info*) or a (struct udp_info*).
 *
 * head->next->payload   is the pointer to the payload of the first packet.
 * head->next->len       is the length of the payload of the first packet.
 * head->next->data      is the (struct pkt_info*) of the first packet.
 *
 */
#define PKT_FIRST(head)   ((head)->next)
#define PKT_LAST(head)    (TRANSPORT_STATUS ((head)->data)->last)

// This function should not be used directly
static inline FalgprotoPacket* packet_list_new (size_t head_data_size) {
    FalgprotoPacket *list = g_slice_alloc (sizeof (FalgprotoPacket));
    list->next = NULL;
    list->payload = NULL;
    list->len = 0;
    list->state = NULL;
    list->data = g_slice_alloc (head_data_size);
    PKT_LAST (list) = list;
    return list;
}

static FalgprotoPacket* packet_list_tcp_new (
    struct sockaddr_storage *addr, socklen_t addr_len,
    GQueue *queue_ip, GQueue *queue_tcp) {

    FalgprotoPacket *list = packet_list_new (sizeof (TcpStatus));

    // Constructor code of TcpStatus goes here
    TcpStatus *status = TCP_STATUS (list->data);
    status->tcp = falgnfq_tcp_new (
        SOCKADDR (addr), addr_len, queue_ip, queue_tcp);
    status->addr = *addr;
    status->addr_len = addr_len;

    return list;
}

static FalgprotoPacket* packet_list_udp_new (void) {
    FalgprotoPacket *list = packet_list_new (sizeof (UdpStatus));

    // Constructor code of UdpStatus goes here

    return list;
}

static void packet_list_append (
    FalgprotoPacket *head, char *payload, size_t len,
    uint32_t id, uint32_t mark, struct pkt_buff *pktb,
    void *transport_header) {

    FalgprotoPacket *item = g_slice_alloc (sizeof (FalgprotoPacket));
    struct pkt_info *info = g_slice_alloc (sizeof (PktInfo));

    info->id = id;
    info->mark = mark;
    info->pktb = pktb;
    info->network_header = pktb_network_header (pktb);
    info->transport_header = transport_header;

    item->next = NULL;
    item->payload = payload;
    item->len = len;
    item->state = NULL;
    item->data = info;

    PKT_LAST (head)->next = item;
    PKT_LAST (head) = item;
}

// This function should not be used directly
static inline void packet_list_free (void *head, size_t head_data_size) {
    FalgprotoPacket *iter = head;
    FalgprotoPacket *next = iter->next;

    g_slice_free1 (head_data_size, iter->data);
    g_slice_free1 (sizeof (FalgprotoPacket), iter);
    for (iter = next; iter != NULL; iter = next) {
        next = iter->next;
        pktb_free (PKT_INFO (iter->data)->pktb);
        g_slice_free1 (sizeof (PktInfo), iter->data);
        g_slice_free1 (sizeof (FalgprotoPacket), iter);
    }
}

static void packet_list_tcp_free (void *head_generic) {
    // Destructor code of TcpStatus goes here
    FalgprotoPacket *head = head_generic;
    falgnfq_tcp_free (TCP_STATUS (head->data)->tcp);

    packet_list_free (head_generic, sizeof (TcpStatus));
}

static void packet_list_udp_free (void *head_generic) {
    // Destructor code of UdpStatus goes here

    packet_list_free (head_generic, sizeof (UdpStatus));
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
static inline int before_get_param (FalgprotoPacket *pkt,
    FalgnfqLoop *loop, const char *caller_name) {

    if_debug (1) {
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

static inline uint32_t get_mark_from_param (
    FalgnfqLoop *loop, FalgprotoParam param) {

    if (param.param) {
        debug ("  %s: param is %*s", __func__, (int)(param.len), param.param);
        for (size_t i = 0; i < loop->config->maps_len; i++) {
            if (loop->proto.matcher (param.param, param.len,
                loop->config->maps[i].param,
                loop->config->maps[i].param_len)) {

                debug ("  %s: maps[%zu] matched (%s)",
                    __func__, i, loop->config->maps[i].param);
                debug ("  %s: new mark is %" PRIu32,
                    __func__, loop->config->maps[i].mark);
                return loop->config->maps[i].mark;
            }
        }
    }

    return loop->config->default_mark;
}


#ifdef LIBNETFILTER_QUEUE_IS_VERY_BUGGY

/* XXX: libnetfilter_queue contains many buggy functions, so we have to write
 *      our correct version and use them instead.
 *      Not all bugs have been reported to the upstream. Here is the upstream
 *      bugzilla: http://bugzilla.netfilter.org/.
 */

/* XXX: nfq_tcp_get_payload returns NULL when there is no payload, but we need
 *      these packets because they may contains control message.
 */
static void* tcp_get_payload (struct tcphdr *tcph, struct pkt_buff *pktb) {
    unsigned int doff = (unsigned int)(tcph->doff) * 4;

    /* malformed TCP data offset. */
    uint8_t *transport_header = pktb_transport_header (pktb);
    uint8_t *tail = pktb_data (pktb) + pktb_len (pktb);
    if (transport_header + doff > tail) {
        return NULL;
    }

    return transport_header + doff;
}

/* XXX: nfq_tcp_get_payload_len is WRONG!
 */
static unsigned int tcp_get_payload_len (
    struct tcphdr *tcph, struct pkt_buff *pktb) {

    uint8_t *transport_header = pktb_transport_header (pktb);
    uint8_t *tail = pktb_data (pktb) + pktb_len (pktb);
    unsigned int doff = (unsigned int)(tcph->doff) * 4;

    return (unsigned int)(tail - transport_header) - doff;
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

/* XXX: nfq_ip_snprintf uses inet_ntoa, but its usage is WRONG!
 *      We implement our version using inet_ntop instead.
 */
static int ip_snprintf (
    char *buf, size_t size, const struct iphdr *iph) {

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop (AF_INET, &iph->saddr, src, INET_ADDRSTRLEN);
    inet_ntop (AF_INET, &iph->daddr, dst, INET_ADDRSTRLEN);

    return snprintf (buf, size,
                     "SRC=%s DST=%s LEN=%u TOS=0x%X "
                     "PREC=0x%X TTL=%u ID=%u PROTO=%u ",
                     src, dst, ntohs (iph->tot_len), IPTOS_TOS (iph->tos),
                     IPTOS_PREC (iph->tos), iph->ttl, ntohs (iph->id),
                     iph->protocol);
}

#endif // LIBNETFILTER_QUEUE_IS_VERY_BUGGY


static bool tcp_inspect (
    FalgnfqLoop *loop, struct tcphdr *th,
    FalgprotoPacket *list, void *key,
    struct pkt_info info, uint32_t *verdict) {

    char *payload = nfq_tcp_get_payload (th, info.pktb);
    size_t len = nfq_tcp_get_payload_len (th, info.pktb);
    debug ("  %s: %zu bytes of payload", __func__, len);
    packet_list_append (list, payload, len, info.id, info.mark, info.pktb, th);
    if (payload == NULL) {
        warning ("  %s: this is not a valid TCP packet!", __func__);
        warning ("  %s: please check your ip/nftables settings", __func__);
        *verdict = loop->config->default_mark;
        return true;
    }

    FalgprotoPacket *pkt = PKT_FIRST (list);
    if (before_get_param (pkt, loop, __func__) < 0) {
        *verdict = loop->config->default_mark;
        return true;
    }

    if (!falgnfq_tcp_client (TCP_STATUS (list->data)->tcp,
        loop->rng, PKT_FIRST (list), PKT_LAST (list))) {

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

    uint32_t mark = get_mark_from_param (loop, param);

    if (param.dup) {
        free (param.param);
    }

    *verdict = mark;
    return true;
}

static bool udp_inspect (
    FalgnfqLoop *loop, struct udphdr *uh,
    FalgprotoPacket *list, void *key,
    struct pkt_info info, uint32_t *verdict) {

    char *payload = nfq_udp_get_payload (uh, info.pktb);
    size_t len = nfq_udp_get_payload_len (uh, info.pktb);
    debug ("  %s: %zu bytes of payload", __func__, len);
    packet_list_append (list, payload, len, info.id, info.mark, info.pktb, uh);
    if (payload == NULL) {
        warning ("  %s: this is not a valid UDP packet!", __func__);
        warning ("  %s: please check your ip/nftables settings", __func__);
        *verdict = loop->config->default_mark;
        return true;
    }

    FalgprotoPacket *pkt = PKT_FIRST (list);
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

    uint32_t mark = get_mark_from_param (loop, param);

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

    if_debug (2) {
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

    struct sockaddr_storage addr;
    socklen_t addr_len;
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

            SOCKADDR_IN (&addr)->sin_family = AF_INET;
            SOCKADDR_IN (&addr)->sin_addr.s_addr = iph->saddr;
            addr_len = sizeof (struct sockaddr_in);

            debug ("  packet id %" PRIu32 ", %s", pkt_id,
                iph->protocol == IPPROTO_TCP ? "layer 4 is TCP" :
                iph->protocol == IPPROTO_UDP ? "layer 4 is UDP" :
                iph->protocol == IPPROTO_ICMP ? "layer 4 is ICMP" :
                iph->protocol == IPPROTO_ICMPV6 ? "layer 4 is ICMPv6" :
                "unknown layer 4 protocol");

            if_debug (1) {
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

            SOCKADDR_IN6 (&addr)->sin6_family = AF_INET6;
            SOCKADDR_IN6 (&addr)->sin6_addr = ip6h->ip6_src;
            addr_len = sizeof (struct sockaddr_in6);

            if_debug (1) {
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

            if_debug (1) {
                char print_buf[2048];
                nfq_tcp_snprintf (print_buf, 2048, th);
                debug ("  packet id %" PRIu32 ", %s", pkt_id, print_buf);
            }

            switch (addr.ss_family) {
                case AF_INET:
                    SOCKADDR_IN (&addr)->sin_port = th->source;
                    break;

                case AF_INET6:
                    SOCKADDR_IN6 (&addr)->sin6_port = th->source;
                    break;

                // This should never happen
                default:
                    error ("UNEXPECTED ERROR: unknown address family");
                    abort ();
            }

            key = sockaddr_copy (SOCKADDR (&addr));
            FalgprotoPacket *list = g_hash_table_lookup (loop->pkts, key);
            if (list == NULL) {
                list = packet_list_tcp_new (
                    &addr, addr_len, &loop->raw_ip_q, &loop->raw_tcp_q);
                g_hash_table_replace (loop->pkts, key, list);
            }

            if (!tcp_inspect (loop, th, list, key, info, &verdict)) {
                debug ("  packet id %" PRIu32 ", saved in the list", pkt_id);
                return MNL_CB_OK;
            }

            // TODO: Call falgnfq_tcp_server

            queue_verdict (loop, list, key, verdict);
        } break;

        case FALGPROTO_TRANSPORT_UDP: {
            struct udphdr *uh = nfq_udp_get_hdr (pktb);
            if (uh == NULL) {
                error ("  packet id %" PRIu32 ", malformed UDP packet", pkt_id);
                goto free_pktb;
            }

            if_debug (1) {
                char print_buf[2048];
                nfq_udp_snprintf (print_buf, 2048, uh);
                debug ("  packet id %" PRIu32 ", %s", pkt_id, print_buf);
            }

            switch (addr.ss_family) {
                case AF_INET:
                    SOCKADDR_IN (&addr)->sin_port = uh->source;
                    break;

                case AF_INET6:
                    SOCKADDR_IN6 (&addr)->sin6_port = uh->source;
                    break;

                // This should never happen
                default:
                    error ("UNEXPECTED ERROR: unknown address family");
                    abort ();
            }

            key = sockaddr_copy (SOCKADDR (&addr));
            FalgprotoPacket *list = g_hash_table_lookup (loop->pkts, key);
            if (list == NULL) {
                list = packet_list_udp_new ();
                g_hash_table_replace (loop->pkts, key, list);
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
        mnl_socket_close (nl);
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
        goto free_nl;
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
        goto free_nl;
    }

    // allocate the struct and return
    FalgnfqLoop *loop = malloc (sizeof (FalgnfqLoop));
    if (loop == NULL) {
        error ("malloc: %s\n", ERRMSG);
        goto free_nl;
    }

    loop->config = config;
    loop->proto.transport = falgproto_get_transport (config->protocol);
    loop->proto.param_getter = falgproto_get_param_getter (config->protocol);
    loop->proto.printer = falgproto_get_printer (config->protocol);
    loop->proto.matcher = falgproto_get_matcher (config->protocol);
    loop->nl = nl;
    loop->nl_fd = mnl_socket_get_fd (nl);
    loop->portid = mnl_socket_get_portid (nl);
    loop->pkt_max = pkt_max;

    switch (loop->proto.transport) {
        case FALGPROTO_TRANSPORT_TCP: {
            loop->rng = falgnfq_rng_new ();
            if (loop->rng < 0) {
                error ("Fail to open the random number generator: %s", ERRMSG);
                goto free_loop;
            }

            int one = 1;
            loop->raw_ip = socket (loop->config->family, SOCK_RAW, IPPROTO_RAW);
            if (loop->raw_ip < 0) {
                error ("Fail to open a raw socket: %s", ERRMSG);
                goto free_rng;
            }
            if (setsockopt (loop->raw_ip, IPPROTO_IP, IP_HDRINCL,
                &one, sizeof(one)) < 0) {
                error ("setsockopt IP_HDRINCL = 1: %s", ERRMSG);
                goto free_raw_ip;
            }

            int zero = 0;
            loop->raw_tcp = socket (loop->config->family, SOCK_RAW, IPPROTO_TCP);
            if (loop->raw_tcp < 0) {
                error ("Fail to open a raw socket: %s", ERRMSG);
                goto free_raw_ip;
            }
            if (setsockopt (loop->raw_tcp, IPPROTO_IP, IP_HDRINCL,
                &zero, sizeof (zero)) < 0) {
                error ("setsockopt IP_HDRINCL = 0: %s", ERRMSG);
                goto free_raw_tcp;
            }

            loop->pkts = g_hash_table_new_full (
                sockaddr_hash, sockaddr_equal,
                sockaddr_free, packet_list_tcp_free);
            g_queue_init (&loop->raw_ip_q);
            g_queue_init (&loop->raw_tcp_q);
        } break;

        case FALGPROTO_TRANSPORT_UDP: {
            loop->pkts = g_hash_table_new_full (
                sockaddr_hash, sockaddr_equal,
                sockaddr_free, packet_list_udp_free);
        } break;

        default:
            error (
                "UNEXPECTED ERROR: unknown transport layer protocol "
                "returned from fastalg-protocol library.");
            abort ();
    }

    debug ("FalgnfqLoop new -> %p", loop);

    return loop;

free_raw_tcp:
    close (loop->raw_tcp);
free_raw_ip:
    close (loop->raw_ip);
free_rng:
    falgnfq_rng_free (loop->rng);
free_loop:
    free (loop);
free_nl:
    mnl_socket_close (nl);
free_nothing:
    return NULL;
}

int falgnfq_loop_run (FalgnfqLoop *loop) {
    ERRMSG_INIT;
    char pkt[loop->pkt_max];
    bool tcp = loop->proto.transport == FALGPROTO_TRANSPORT_TCP;

    debug ("FalgnfqLoop %p run", loop);

    enum {
        POLL_NETLINK,
        POLL_RAW_IP,
        POLL_RAW_TCP,
        POLL_MAX
    };
    struct pollfd fds[POLL_MAX] = {
        [POLL_NETLINK] = { .fd = loop->nl_fd,   .events = POLLIN | POLLPRI },
        [POLL_RAW_IP]  = { .fd = loop->raw_ip,  .events = POLLOUT },
        [POLL_RAW_TCP] = { .fd = loop->raw_tcp, .events = POLLOUT }
    };
    nfds_t nfds = tcp ? POLL_MAX : 1;

#ifndef NDEBUG
    while (!falgnfq_exit) {
#else
    while (true) {
#endif
        if (tcp) {
            // Prevent endless loops
            if (g_queue_is_empty (&loop->raw_ip_q)) {
                debug ("FalgnfqLoop %p run: disable raw IP socket", loop);
                if (fds[POLL_RAW_IP].fd > 0) {
                    fds[POLL_RAW_IP].fd = - fds[POLL_RAW_IP].fd;
                }
            } else {
                debug ("FalgnfqLoop %p run: enable raw IP socket", loop);
                if (fds[POLL_RAW_IP].fd < 0) {
                    fds[POLL_RAW_IP].fd = - fds[POLL_RAW_IP].fd;
                }
            }

            if (g_queue_is_empty (&loop->raw_tcp_q)) {
                debug ("FalgnfqLoop %p run: disable raw TCP socket", loop);
                if (fds[POLL_RAW_TCP].fd > 0) {
                    fds[POLL_RAW_TCP].fd = - fds[POLL_RAW_TCP].fd;
                }
            } else {
                debug ("FalgnfqLoop %p run: enable raw TCP socket", loop);
                if (fds[POLL_RAW_TCP].fd < 0) {
                    fds[POLL_RAW_TCP].fd = - fds[POLL_RAW_TCP].fd;
                }
            }
        }

        debug ("FalgnfqLoop %p run: poll", loop);
        if (poll (fds, nfds, -1) < 0) {
            if (errno == EINTR || errno == EWOULDBLOCK) {
                debug ("FalnfqLoop %p run: poll interrupted", loop);
                continue;
            } else {
                error ("poll: %s", ERRMSG);
                return -1;
            }
        }

        if (fds[POLL_NETLINK].revents & POLLIN ||
            fds[POLL_NETLINK].revents & POLLPRI) {

            debug ("FalgnfqLoop %p run: netlink socket is ready", loop);
            debug ("FalgnfqLoop %p run: mnl_socket_recvfrom", loop);
            ssize_t pkt_rval =
                mnl_socket_recvfrom (loop->nl, pkt, loop->pkt_max);
            if (pkt_rval < 0) {
                if (errno == ENOBUFS) {
                    warning ("mnl_socket_recvfrom: %s", ERRMSG);
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
                if_debug (1) {
                    error ("DEVELOPER_MODE: UNEXPECTED ERROR, EXIT NOW!");
                    return -1;
                }
            }
        }

        if (!tcp) {
            continue;
        }

        // Below are TCP-only
        if (fds[POLL_RAW_IP].revents & POLLOUT) {
            debug ("FalgnfqLoop %p run: raw IP socket is ready", loop);
        }

        if (fds[POLL_RAW_TCP].revents & POLLOUT) {
            debug ("FalgnfqLoop %p run: raw TCP socket is ready", loop);

            QueuedPkt *qpkt = g_queue_pop_head (&loop->raw_tcp_q);
            if (sendto (loop->raw_tcp, qpkt->data, qpkt->len, 0,
                SOCKADDR (&qpkt->addr), qpkt->addr_len) < 0) {

                error ("sendto: %s", ERRMSG);
                if_debug (1) {
                    error ("DEVELOPER_MODE: UNEXPECTED ERROR, EXIT NOW!");
                    free (qpkt);
                    return -1;
                }
            }

            free (qpkt);
        }
    }

    return 0;
}

void falgnfq_loop_free (FalgnfqLoop *loop) {
    debug ("FalgnfqLoop %p free", loop);
    mnl_socket_close (loop->nl);
    g_hash_table_destroy (loop->pkts);
    if (loop->proto.transport == FALGPROTO_TRANSPORT_TCP) {
        falgnfq_rng_free (loop->rng);
        close (loop->raw_ip);
        close (loop->raw_tcp);
        while (!g_queue_is_empty (&loop->raw_ip_q)) {
            free (g_queue_pop_tail (&loop->raw_ip_q));
        }
        while (!g_queue_is_empty (&loop->raw_tcp_q)) {
            free (g_queue_pop_tail (&loop->raw_tcp_q));
        }
    }
    free (loop);
}
