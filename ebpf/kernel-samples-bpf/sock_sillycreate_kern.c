#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include <uapi/linux/ip.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>


SEC("cgroup/sock_create")
int bpf_sock_create(struct bpf_sock *ctx)
{
    ctx->priority = (1<<16)|0xffff;
	return 1;
}
char _license[] SEC("license") = "GPL";
