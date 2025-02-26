#include <stddef.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_packet.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/filter.h>
#include <asm/types.h>
#include <linux/udp.h>
#include <linux/random.h>
#include <linux/net.h>


enum {
	IPPROTO_IP = 0,
	IPPROTO_ICMP = 1,
	IPPROTO_IGMP = 2,
	IPPROTO_IPIP = 4,
	IPPROTO_TCP = 6,
	IPPROTO_EGP = 8,
	IPPROTO_PUP = 12,
	IPPROTO_UDP = 17,
	IPPROTO_IDP = 22,
	IPPROTO_TP = 29,
	IPPROTO_DCCP = 33,
	IPPROTO_IPV6 = 41,
	IPPROTO_RSVP = 46,
	IPPROTO_GRE = 47,
	IPPROTO_ESP = 50,
	IPPROTO_AH = 51,
	IPPROTO_MTP = 92,
	IPPROTO_BEETPH = 94,
	IPPROTO_ENCAP = 98,
	IPPROTO_PIM = 103,
	IPPROTO_COMP = 108,
	IPPROTO_L2TP = 115,
	IPPROTO_SCTP = 132,
	IPPROTO_UDPLITE = 136,
	IPPROTO_MPLS = 137,
	IPPROTO_ETHERNET = 143,
	IPPROTO_RAW = 255,
	IPPROTO_MPTCP = 262,
	IPPROTO_MAX = 263,
};


// Connection tracking key (external perspective)
struct conn_key {
    __u32 src_ip;
    __u16 src_port;
    __u8 protocol;
};

// Original connection info (container perspective)
struct conn_value {
    __u32 orig_dst_ip;
    __u16 orig_dst_port;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct conn_key);
  __type(value, struct conn_value);
  __uint(max_entries, 1 << 24);
} conn_tracker SEC(".maps");


static __always_inline __u16 ipv4_csum(struct iphdr *ip) {
    __u16 *buf = (__u16 *)ip;
    __u32 sum = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < sizeof(*ip)/2; i++) {
        sum += buf[i];
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
} 

SEC("tc")
int tc_egress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    // Check container subnet 10.0.0.0/24
    if ((ip->saddr & bpf_htonl(0xFFFFFF00)) != bpf_htonl(0x0A000000)) {
        return TC_ACT_OK;
    }

    // Store original values
    __u32 orig_src_ip = ip->saddr;
    __u16 orig_src_port = 0;

    // Get transport header
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        orig_src_port = tcp->source;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        orig_src_port = udp->source;
    } else {
        return TC_ACT_OK; // Only handle TCP/UDP
    }

    // Create NAT mapping
    struct conn_key key = {
        .src_ip = bpf_htonl(0xC0A80164), // Host external IP
        .src_port = orig_src_port,       // Keep same port for demo
        .protocol = ip->protocol
    };

    struct conn_value value = {
        .orig_dst_ip = orig_src_ip,
        .orig_dst_port = orig_src_port
    };

    bpf_map_update_elem(&conn_tracker, &key, &value, BPF_ANY);

    // Perform SNAT
    ip->saddr = bpf_htonl(0xC0A80164); // 192.168.1.100
    ip->check = ipv4_csum(ip);

    return TC_ACT_OK;
}

SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    // Check if destined to host external IP
    if (ip->daddr != bpf_htonl(0xC0A80164)) return TC_ACT_OK;

    // Look up connection tracking
    struct conn_key key = {
        .src_ip = ip->daddr,
        .src_port = 0,
        .protocol = ip->protocol
    };

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) > data_end) return TC_ACT_OK;
        key.src_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        if ((void *)(udp + 1) > data_end) return TC_ACT_OK;
        key.src_port = udp->dest;
    } else {
        return TC_ACT_OK;
    }

    struct conn_value *value = bpf_map_lookup_elem(&conn_tracker, &key);
    if (!value) return TC_ACT_OK;

    // Perform DNAT
    ip->daddr = value->orig_dst_ip;
    
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        tcp->dest = value->orig_dst_port;
        tcp->check = 0; // Recalc done by kernel
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + sizeof(*ip);
        udp->dest = value->orig_dst_port;
        udp->check = 0; // Optional for IPv4
    }

    ip->check = ipv4_csum(ip);

    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
