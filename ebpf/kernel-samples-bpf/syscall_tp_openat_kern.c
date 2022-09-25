#include <uapi/linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "syscall_tp.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} opens SEC(".maps");


struct syscalls_enter_open_args {
	unsigned long long unused;
	long syscall_nr;
	long filename_ptr;
	long flags;
	long mode;
};


SEC("tracepoint/syscalls/sys_enter_openat")
int trace_enter_open_at(struct syscalls_enter_open_args *ctx)
{
	struct open_event *event;
	event = bpf_ringbuf_reserve(&opens, sizeof(*event), 0);
    bpf_printk("open at event \n");
	if (!event) return 0;
	event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_probe_read_user_str(event->fname, sizeof(event->fname), (void*)(ctx->filename_ptr));
	bpf_ringbuf_submit(event, 0);
	return 0;
}


char _license[] SEC("license") = "GPL";
