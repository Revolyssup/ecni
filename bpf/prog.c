#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_ingress(struct __sk_buff *skb)
{
    volatile u32 counter = 0;
    counter++;
    bpf_printk("Packet received (count: %d)\n", counter);
    return BPF_OK;
}

char __license[] SEC("license") = "Dual MIT/GPL";
