// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, u32);
	__type(value, unsigned long long);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ksysread_stats SEC(".maps");

SEC("kprobe/ksys_read")
int BPF_KPROBE(ksys_read, unsigned int fd, char *buf, size_t count)
{
    int i;
    #pragma unroll
    for(i=30; i>=0; i--) {
        if (count&(1<<i)) {
            unsigned long long* counter = bpf_map_lookup_elem(&ksysread_stats, &i);
            if (counter) (*counter)++;
            break;
        }
    }
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
