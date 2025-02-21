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

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
