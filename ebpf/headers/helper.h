
#define READ_KERN(ptr)                                     \
    ({                                                     \
        typeof(ptr) _val;                                  \
        __builtin_memset((void *)&_val, 0, sizeof(_val));  \
        bpf_probe_read((void *)&_val, sizeof(_val), &ptr); \
        _val;                                              \
    })

#define READ_USER(ptr)                                          \
    ({                                                          \
        typeof(ptr) _val;                                       \
        __builtin_memset((void *)&_val, 0, sizeof(_val));       \
        bpf_probe_read_user((void *)&_val, sizeof(_val), &ptr); \
        _val;                                                   \
    })

#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AF_INET6
#define AF_INET6 10
#endif

#define TCP_EVENT_CONNECT 1
#define TCP_EVENT_ACCEPT 2
#define TCP_EVENT_CLOSE 3

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4
#define TC_ACT_REDIRECT 7

#define ETH_P_IP 0x0800 /* Internet Protocol packet        */

#define ETH_HLEN sizeof(struct ethhdr)
#define IP_HLEN sizeof(struct iphdr)
#define TCP_HLEN sizeof(struct tcphdr)
#define UDP_HLEN sizeof(struct udphdr)
#define DNS_HLEN sizeof(struct dns_hdr)
#define ctx_ptr(field) (void *)(long)(field)

struct net_tcp_event
{
    u32 pid;
    u16 event;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 comm[16];
};