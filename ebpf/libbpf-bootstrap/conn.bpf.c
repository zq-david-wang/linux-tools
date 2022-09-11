#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "conn.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} conns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, void*);
} accept_addr SEC(".maps");


struct syscalls_enter_connect_args {
    char _[24];
    struct sockaddr *addr;
};
struct syscalls_enter_accept_args {
    char _[24];
    struct sockaddr *addr;
};

SEC("tp/syscalls/sys_enter_connect")
int trace_enter_connect(struct syscalls_enter_connect_args *ctx)
{
	struct conn_event *event;
	event = bpf_ringbuf_reserve(&conns, sizeof(*event), 0);
	if (!event) return 0;
	event->pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_probe_read_user(&event->addr, sizeof(event->addr), (void*)(ctx->addr))) {
        bpf_ringbuf_discard(event, 0);
    } else bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_accept")
int trace_enter_accept(struct syscalls_enter_accept_args *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    void *addr = (void*)(ctx->addr);
	bpf_map_update_elem(&accept_addr, &pid, &addr, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_accept")
int trace_exit_accept(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    void **paddr = (void**)bpf_map_lookup_elem(&accept_addr, &pid);
    if (paddr) {
        bpf_map_delete_elem(&accept_addr, &pid);
        struct conn_event *event;
        event = bpf_ringbuf_reserve(&conns, sizeof(*event), 0);
        if (!event) return 0;
        event->pid = -pid;
        long r=bpf_probe_read_user(&(event->addr), sizeof(event->addr), *paddr);
        if (r) {
            // bpf_printk("fail to read user space value %lld\n", r);
            bpf_ringbuf_discard(event, 0);
        } else bpf_ringbuf_submit(event, 0);
    }
	return 0;
}

SEC("tp/syscalls/sys_enter_accept4")
int trace_enter_accept4(struct syscalls_enter_accept_args *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    void *addr = (void*)(ctx->addr);
	bpf_map_update_elem(&accept_addr, &pid, &addr, BPF_ANY);
	return 0;
}

SEC("tp/syscalls/sys_exit_accept4")
int trace_exit_accept4(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    void **paddr = (void**)bpf_map_lookup_elem(&accept_addr, &pid);
    if (paddr) {
        bpf_map_delete_elem(&accept_addr, &pid);
        struct conn_event *event;
        event = bpf_ringbuf_reserve(&conns, sizeof(*event), 0);
        if (!event) return 0;
        event->pid = -pid;
        long r=bpf_probe_read_user(&(event->addr), sizeof(event->addr), *paddr);
        if (r) {
            // bpf_printk("fail to read user space value %lld\n", r);
            bpf_ringbuf_discard(event, 0);
        } else bpf_ringbuf_submit(event, 0);
    }
	return 0;
}

char _license[] SEC("license") = "GPL";
