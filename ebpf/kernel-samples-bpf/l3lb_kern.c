#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "l3lb.h"
#include <uapi/linux/tcp.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
 	__uint(key_size, sizeof(unsigned int));
	__uint(value_size, sizeof(BNode));
	__uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} l3bindings SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1);
} tx_addr SEC(".maps");


static __always_inline
void swap_src_dst_mac(void *data)
{
	unsigned short *p = data;
	unsigned short dst[3];

	dst[0] = p[0];
	dst[1] = p[1];
	dst[2] = p[2];
	p[0] = p[3];
	p[1] = p[4];
	p[2] = p[5];
	p[3] = dst[0];
	p[4] = dst[1];
	p[5] = dst[2];
}

static __always_inline BNode *_check(unsigned int ip) {
    unsigned int m = 0xffffffff;
    int i;
    BNode *r;
    ip = (ip>>24) | (((ip>>16)&0xff)<<8) | (((ip>>8)&0xff)<<16) | ((ip&0xff)<<24);
    for (i=0; i<31; i++) {
        ip &= m;
        r=bpf_map_lookup_elem(&l3bindings, &ip);
        if (r) return r;
        m<<=1;
    }
    return NULL;
}

static __always_inline void  iphdr_adjust_csum(struct iphdr* iph, int dsum) {
    if (dsum == 0) return;
    unsigned int csum = (~iph->check)&0xffff;
    if (dsum < 0) {
        dsum = -dsum;
        if (csum >= dsum) csum-=dsum;
        else csum += (0xffff-dsum);
    } else if (dsum > 0) {
        csum+=dsum;
        if (csum>0xffff) csum = (csum&0xffff)+1;
    }
    iph->check = ~csum;
}


SEC("xdp")
int xdp_ipv4_l3lb(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
    struct iphdr *iph;
	u16 h_proto;
	u64 nh_off;
    BNode *value = NULL;
    int i, o_ifindex=0, rc;
	struct bpf_fib_lookup fib_params;
    unsigned int *pip = NULL;
    int dsum=0;
    // struct tcphdr *tcph = NULL;

	nh_off = sizeof(*eth);
	if (data + nh_off > data_end) return XDP_PASS;

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_PASS;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto == htons(ETH_P_8021Q) || h_proto == htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end)
			return XDP_PASS;
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	if (h_proto != htons(ETH_P_IP)) return XDP_PASS;
    if (data + nh_off + sizeof(*iph) > data_end) return XDP_PASS;
	iph = data + nh_off;
    if (iph->ttl <= 1) return XDP_PASS;

    i=0;
    pip = bpf_map_lookup_elem(&tx_addr, &i);
    if (pip == NULL) return XDP_PASS;

	__builtin_memset(&fib_params, 0, sizeof(fib_params));
    fib_params.family	= AF_INET;
    fib_params.tos		= iph->tos;
    // fib_params.l4_protocol	= iph->protocol;
    fib_params.tot_len	= ntohs(iph->tot_len);

    if (iph->daddr == *pip) {
        value =  _check(iph->saddr);
        if (!value) return XDP_PASS;
        if (ctx->ingress_ifindex != value->ifin) return XDP_PASS;
        // change daddr and  redirect
        // bpf_printk("capture source ip %x -> %x %x\n", iph->saddr, iph->daddr, value->daddr);
        fib_params.ipv4_src	= *pip; // iph->saddr;
		fib_params.ipv4_dst	= value->daddr;
        o_ifindex = value->ifout;
        dsum = (value->daddr&0xffff) + (value->daddr>>16);
        dsum -= (iph->daddr&0xffff) + (iph->daddr>>16);
        iph->daddr = value->daddr;
    } else {
        value = _check(iph->daddr);
        if (!value) return XDP_PASS;
        if (ctx->ingress_ifindex != value->ifout) return XDP_PASS;
        // change saddr
        // bpf_printk("capture dest ip %x <> %x %x\n", iph->saddr, iph->daddr, value->saddr);
        fib_params.ipv4_src	= value->saddr;
		fib_params.ipv4_dst	= iph->daddr;
        o_ifindex = value->ifin;
        dsum = (value->saddr&0xffff) + (value->saddr>>16);
        dsum -= (iph->saddr&0xffff) + (iph->saddr>>16);
        iph->saddr = value->saddr;
    }
    iph->ttl--;
    dsum -= htons(0x0100);
    iphdr_adjust_csum(iph, dsum);
    // iph->protocol == IPPROTO_TCP tcp->check ?

	fib_params.ifindex = ctx->ingress_ifindex; // o_ifindex;
	rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT); // 0, BPF_FIB_LOOKUP_DIRECT, or BPF_FIB_LOOKUP_OUTPUT
	if (rc == BPF_FIB_LKUP_RET_SUCCESS) {
		memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
		memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
		return  bpf_redirect(o_ifindex, 0);
	} else {
        bpf_printk("fib failed: %d, try sending icmp ping?\n", rc);
    }
	return XDP_PASS;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";

