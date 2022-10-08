#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/filter.h>
#include <uapi/linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include "bpf_legacy.h"


#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))


SEC("tc_silly_filter")
int bpf_prog(struct __sk_buff *skb)
{
    __u32 sip = load_word(skb, IP_SRC_OFF);
    __u32 dip = load_word(skb, IP_DST_OFF);
    if (sip == (__u32)0xac120103 || dip == (__u32)0xac120103) {
        return (1<<16)|1; //1:1
    }
	return -1; // default
}

char _license[] SEC("license") = "GPL";
