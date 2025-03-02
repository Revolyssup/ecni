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
    __u32 src_ip;    // NATed source IP
    __u16 src_port;  // NATed source port
    __u8 protocol;
};

// Original connection info (container perspective)
struct conn_value {
    __u32 orig_src_ip;   // Original source IP (container's IP)
    __u16 orig_src_port; // Original source port (container's port)
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

struct packet {
  __u32 source_ip;
  __u32 dest_ip;
  __u32 size;
  __u16 source_port;
  __u16 dest_port;
  __u8 protocol;
  _Bool is_dropped;
  __u8 direction;
};

SEC("tc/egress")
int tc_egress(struct __sk_buff *ctx) {
    bpf_printk("EGRESS START");
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Ethernet header check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
        bpf_printk("EGRESS: eth header check failed");
        return TC_ACT_OK;
    }
    if (eth->h_proto != bpf_htons(ETH_P_IP)){
        bpf_printk("EGRESS: eth proto check failed");
        return TC_ACT_OK;
    }


    // IP header check
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end){
        bpf_printk("EGRESS: ip header check failed");
        return TC_ACT_OK;
    }
    __u8 ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(*ip) || (void *)ip + ip_header_len > data_end)
    {
        bpf_printk("EGRESS: ip header len check failed");
        return TC_ACT_OK;
    }


    // Extract original source information
    __u32 orig_src_ip = ip->saddr;
    __u16 orig_src_port = 0;
    __u8 protocol = ip->protocol;

    // Debug: Print original IP info
    bpf_printk("EGRESS START: proto=%d src=%pI4 -> dest=%pI4", 
              protocol, &orig_src_ip, &ip->daddr);

    // Extract ports for TCP/UDP
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u16 *ports = (__u16 *)((void *)ip + ip_header_len);
        if ((void *)(ports + 2) > data_end)
            return TC_ACT_OK;
        orig_src_port = bpf_ntohs(ports[0]);
        bpf_printk("EGRESS PORTS: src_port=%d dst_port=%d", 
                  orig_src_port, bpf_ntohs(ports[1]));
    }

    // Perform NAT
    __u32 new_src_ip = bpf_htonl(0xC0A8007C); // 192.168.0.124
    __u32 old_saddr = ip->saddr;
    ip->saddr = new_src_ip;
    __u16 new_src_port = bpf_htons(bpf_get_prandom_u32() & 0xFFFF);
    
    // Update packet and connection tracker
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u16 *ports = (__u16 *)((void *)ip + ip_header_len);
        ports[0] = new_src_port;  // Update source port in packet
    }
    // Debug: Print NAT translation
    bpf_printk("EGRESS NAT: %pI4:%d -> %pI4:%d", 
              &old_saddr, orig_src_port, 
              &new_src_ip, orig_src_port);

    // Update connection tracker
    struct conn_key key = {
        .src_ip = bpf_ntohl(new_src_ip),
        .src_port = bpf_ntohs(new_src_port),
        .protocol = protocol
    };
    struct conn_value value = {
        .orig_src_ip = bpf_ntohl(old_saddr),
        .orig_src_port = orig_src_port
    };
    
    bpf_map_update_elem(&conn_tracker, &key, &value, BPF_ANY);
    bpf_printk("EGRESS MAP UPDATE: key(%pI4:%d) -> value(%pI4:%d)", 
              &key.src_ip, key.src_port,
              &value.orig_src_ip, value.orig_src_port);

    // Adjust checksum
    __u32 delta = new_src_ip - old_saddr;
    __u32 sum = (~bpf_ntohs(ip->check)) & 0xFFFF;
    sum += (delta >> 16) + (delta & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    ip->check = bpf_htons(~sum & 0xFFFF);

    bpf_printk("EGRESS COMPLETE: new checksum=0x%x", ip->check);
    return TC_ACT_OK;
}

SEC("tc/ingress")
int tc_ingress(struct __sk_buff *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // Ethernet header check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // IP header check
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    __u8 ip_header_len = ip->ihl * 4;
    if (ip_header_len < sizeof(*ip) || (void *)ip + ip_header_len > data_end)
        return TC_ACT_OK;

    // Extract destination information
    __u32 dest_ip = bpf_ntohl(ip->daddr);
    __u16 dest_port = 0;
    __u8 protocol = ip->protocol;
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u16 *ports = (__u16 *)((void *)ip + ip_header_len);
        if ((void *)(ports + 2) > data_end)
            return TC_ACT_OK;
        dest_port = bpf_ntohs(ports[0]);
        bpf_printk("EGRESS PORTS: src_port=%d dst_port=%d", 
                  dest_port, bpf_ntohs(ports[1]));
    }


    bpf_printk("INGRESS START: proto=%d dest=%pI4", protocol, &ip->daddr);

    // Extract ports for TCP/UDP
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        __u16 *ports = (__u16 *)((void *)ip + ip_header_len);
        if ((void *)(ports + 2) > data_end)
            return TC_ACT_OK;
        dest_port = bpf_ntohs(ports[1]);
        bpf_printk("INGRESS PORTS: src_port=%d dst_port=%d", 
                  bpf_ntohs(ports[0]), dest_port);
    }

    // Lookup connection tracker entry
    struct conn_key key = {
        .src_ip = dest_ip,
        .src_port = dest_port,
        .protocol = protocol
    };
    
    bpf_printk("INGRESS MAP LOOKUP: key(%pI4:%d)", &key.src_ip, key.src_port);
    struct conn_value *value = bpf_map_lookup_elem(&conn_tracker, &key);
    
    if (!value) {
        bpf_printk("INGRESS MISS: No map entry for %pI4:%d", 
                  &key.src_ip, key.src_port);
        return TC_ACT_OK;
    }

    // Perform reverse NAT
    __u32 orig_src_ip = bpf_htonl(value->orig_src_ip);
    __u16 orig_src_port = value->orig_src_port;
    __u32 old_daddr = ip->daddr;
    ip->daddr = orig_src_ip;

    bpf_printk("INGRESS R-NAT: %pI4:%d -> %pI4:%d", 
              &old_daddr, dest_port,
              &orig_src_ip, orig_src_port);

    // Adjust checksum
    __u32 delta = orig_src_ip - old_daddr;
    __u32 sum = (~bpf_ntohs(ip->check)) & 0xFFFF;
    sum += (delta >> 16) + (delta & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    ip->check = bpf_htons(~sum & 0xFFFF);

    bpf_printk("INGRESS COMPLETE: new checksum=0x%x", ip->check);
    return TC_ACT_OK;
}


char __license[] SEC("license") = "Dual MIT/GPL";
