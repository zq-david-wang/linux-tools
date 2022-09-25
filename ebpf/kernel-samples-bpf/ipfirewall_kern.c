#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
 	__uint(key_size, sizeof(unsigned int));
	__uint(value_size, sizeof(unsigned int));
	__uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} rules SEC(".maps");



SEC("xdp")
int xdp_ipv4_firewalling(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
    struct iphdr *iph;
	u16 h_proto;
	u64 nh_off;
    unsigned int sip=0;
    unsigned int m = 0xffffffff;
    unsigned int *value = NULL;
    int i;

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

        
    sip = iph->saddr;
    sip = (sip>>24) | (((sip>>16)&0xff)<<8) | (((sip>>8)&0xff)<<16) | ((sip&0xff)<<24);
    // cat /sys/kernel/debug/tracing/trace_pipe
    // bpf_printk("capture source ip %x\n", sip);
    for (i=0; i<31; i++) {
        sip &= m;
        value=bpf_map_lookup_elem(&rules, &sip);
        if (value) {
            if (*value) return XDP_DROP;
            return XDP_PASS;
        }
        m<<=1;
    }
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

