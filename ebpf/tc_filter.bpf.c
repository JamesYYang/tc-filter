#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

struct filter_config
{
    u32 saddr;
    u32 daddr;
    u8 l4_proto;
    u16 sport;
    u16 dport;
    u16 port;
    u8 is_drop;
} __attribute__((packed));

static volatile const struct filter_config FCG;
#define fcg (&FCG)

struct net_packet_event
{
    u64 ts;
    u32 len;
    u32 mark;
    u32 ifindex;
    u32 protocol;
    u32 sip;   // 源IP
    u32 dip;   // 目的IP
    u16 sport; // 源端口
    u16 dport; // 目的端口
    u16 ingress;
    u16 fin;
    u16 syn;
    u16 rst;
    u16 psh;
    u16 ack;
};

/* BPF ringbuf map */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} tc_capture_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct net_packet_event *unused __attribute__((unused));

static inline int filterL3SKB(struct iphdr *iph)
{
    if (fcg->l4_proto && iph->protocol != fcg->l4_proto)
    {
        return 0;
    }

    if (fcg->saddr && iph->saddr != fcg->saddr)
    {
        return 0;
    }

    if (fcg->daddr && iph->daddr != fcg->daddr)
    {
        return 0;
    }

    return 1;
}

static inline int filterL4SKB(u16 dport, u16 sport)
{
    if (fcg->sport && sport != fcg->sport)
    {
        return 0;
    }

    if (fcg->dport && dport != fcg->dport)
    {
        return 0;
    }

    if (fcg->port && (dport != fcg->port && sport != fcg->port))
    {
        return 0;
    }

    return 1;
}

static inline int capture_packets(struct __sk_buff *skb, u16 is_ingress)
{
    // packet data
    void *data_end = ctx_ptr(skb->data_end);
    void *data_start = ctx_ptr(skb->data);

    // Boundary check: check if packet is larger than a full ethernet + ip header
    if (data_start + ETH_HLEN + IP_HLEN + TCP_HLEN > data_end)
    {
        return TC_ACT_OK;
    }

    // Ethernet headers
    struct ethhdr *eth = (struct ethhdr *)data_start;
    // filter out non-IP packets
    // TODO support IPv6
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    // IP headers
    struct iphdr *iph = (struct iphdr *)(data_start + ETH_HLEN);
    if (!filterL3SKB(iph))
    {
        return TC_ACT_OK;
    }

    u16 l4_proto = iph->protocol;

    u16 sport = 0, dport = 0;
    u16 f = 0, r = 0, s = 0, a = 0, p = 0;

    if (l4_proto == IPPROTO_TCP)
    {
        // TCP header
        struct tcphdr *tcp = (struct tcphdr *)(data_start + ETH_HLEN + IP_HLEN);
        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        if (!filterL4SKB(dport, sport))
        {
            return TC_ACT_OK;
        }
        f = tcp->fin;
        r = tcp->rst;
        s = tcp->syn;
        p = tcp->psh;
        a = tcp->ack;
    }
    else if (l4_proto == IPPROTO_UDP)
    {
        // UDP header
        struct udphdr *udp = (struct udphdr *)(data_start + ETH_HLEN + UDP_HLEN);
        sport = bpf_ntohs(udp->source);
        dport = bpf_ntohs(udp->dest);
        if (!filterL4SKB(dport, sport))
        {
            return TC_ACT_OK;
        }
    }

    struct net_packet_event *pkt;
    pkt = bpf_ringbuf_reserve(&tc_capture_events, sizeof(*pkt), 0);
    if (!pkt)
    {
        return TC_ACT_OK;
    }

    pkt->ts = bpf_ktime_get_ns();
    pkt->len = skb->len;
    pkt->mark = skb->mark;
    pkt->ifindex = skb->ifindex;
    pkt->ingress = is_ingress;
    pkt->protocol = iph->protocol;
    pkt->dip = iph->daddr;
    pkt->sip = iph->saddr;
    pkt->dport = dport;
    pkt->sport = sport;
    pkt->fin = f;
    pkt->rst = r;
    pkt->syn = s;
    pkt->psh = p;
    pkt->ack = a;

    bpf_ringbuf_submit(pkt, 0);

    if (fcg->is_drop)
    {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

// egress_cls_func is called for packets that are going out of the network
SEC("classifier/egress")
int egress_cls_func(struct __sk_buff *skb)
{
    return capture_packets(skb, 0);
}

// ingress_cls_func is called for packets that are coming into the network
SEC("classifier/ingress")
int ingress_cls_func(struct __sk_buff *skb)
{
    return capture_packets(skb, 1);
}

char _license[] SEC("license") = "GPL";