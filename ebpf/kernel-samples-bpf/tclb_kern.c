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

/* compiler workaround */
#define _htonl __builtin_bswap32

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define IS_PSEUDO 0x10

static inline int set_tcp_ip_dst(struct __sk_buff *skb, __u32 new_ip)
{
	__u32 old_ip = _htonl(load_word(skb, IP_DST_OFF));
    if (old_ip != 0x0A010A0A) return 0;
    bpf_printk("redirect from %x to %x\n", old_ip, new_ip);
	bpf_l4_csum_replace(skb, TCP_CSUM_OFF, old_ip, new_ip, IS_PSEUDO | sizeof(new_ip));
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
	bpf_skb_store_bytes(skb, IP_DST_OFF, &new_ip, sizeof(new_ip), 0);
    return 1;
}

SEC("tclb")
int bpf_prog(struct __sk_buff *skb)
{
	__u8 proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));

	if (proto == IPPROTO_TCP) {
		if (set_tcp_ip_dst(skb, 0x030112ac)) return TC_ACT_REPEAT;
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
