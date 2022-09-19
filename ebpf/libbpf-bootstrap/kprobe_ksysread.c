// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kprobe_ksysread.skel.h"


static struct kprobe_ksysread_bpf *skel=NULL;
static void int_exit(int signo) {
    if (skel) {
        kprobe_ksysread_bpf__destroy(skel);
    }
    exit(0);
}

int main(int argc, char **argv) {
	int err;

	/* Open load and verify BPF application */
	skel = kprobe_ksysread_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = kprobe_ksysread_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    while(1) sleep(3600);

cleanup:
    int_exit(0);
	return 0;
}
