#include "vmlinux.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"
#include "helper.h"
#include "bpf_endian.h"

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

// https://github.com/aquasecurity/tracee/blob/main/pkg/ebpf/c/tracee.bpf.c#L6060
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
    // filter out non-TCP packets
    // if (iph->protocol != IPPROTO_TCP)
    // {
    //     return TC_ACT_OK;
    // }
    //

    struct tcphdr *tcp = (struct tcphdr *)(data_start + ETH_HLEN + IP_HLEN);
    if (tcp->source == bpf_htons(22) || tcp->dest == bpf_htons(22))
    {
        return TC_ACT_OK;
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
    pkt->dport = bpf_ntohs(tcp->dest);
    pkt->sport = bpf_ntohs(tcp->source);
    pkt->fin = tcp->fin;
    pkt->rst = tcp->rst;
    pkt->syn = tcp->syn;
    pkt->psh = tcp->psh;
    pkt->ack = tcp->ack;

    bpf_ringbuf_submit(pkt, 0);

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