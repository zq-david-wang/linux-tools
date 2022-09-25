#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <uapi/linux/ip.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>

#define MAXN 128
typedef unsigned int VNode[MAXN];

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(unsigned int));
	__uint(value_size, sizeof(VNode));
	__uint(max_entries, 1024);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} viprules SEC(".maps");

SEC("cgroup/connect4")
int bpf_connectlb(struct bpf_sock_addr *sk)
{
	if (sk->family == AF_INET) {
        unsigned int ip = sk->user_ip4, n, i;
        VNode *value;

        value = bpf_map_lookup_elem(&viprules, &ip);
        if (!value) return 1; // let go
        n = (*value)[0]; 
        if (n == 0) return 0; // vip exist, but no real ip, reject this conn
        i = 1+(bpf_get_prandom_u32()%n);
        if (i<MAXN) {
            ip =(*value)[i];
            sk->user_ip4 = ip;
        }
    }
	return 1;
}
char _license[] SEC("license") = "GPL";
