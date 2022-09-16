#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "commargv.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} comms SEC(".maps");


struct syscalls_enter_exec_args {
    char bb[24];
    char ** argv;
};


SEC("tp/syscalls/sys_enter_execve")
int trace_enter_execve(struct syscalls_enter_exec_args *ctx)
{
	struct comm_event *event;
	event = bpf_ringbuf_reserve(&comms, sizeof(*event), 0);
	if (!event) return 0;
	event->pid = bpf_get_current_pid_tgid() >> 32;
    int i, n;
    char *args=NULL;
    void *p = ctx->argv;
#pragma unroll
    for (i=0; i<MAXPN; i++) {
        args = NULL;
        bpf_probe_read_user(&args, sizeof(args), p);
        if (args==NULL) break;
        n = bpf_probe_read_user_str((void*)(event->argv[i]), sizeof(event->argv[i]), (void*)args);
        if (n<0) break;
        p += sizeof(char *);
    }

    event->n = i;
	bpf_ringbuf_submit(event, 0);
	return 0;
}


char _license[] SEC("license") = "GPL";
