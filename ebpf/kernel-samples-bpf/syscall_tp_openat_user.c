#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpf_load.h"
#include "syscall_tp.h"

struct bpf_object *obj = NULL;
struct ring_buffer *ring_buf = NULL;
static void int_exit(int sig) {
    if (ring_buf) {
        ring_buffer__free(ring_buf);
        ring_buf= NULL;
    }
    if (obj){
        bpf_object__close(obj);
        obj = NULL;
    }
}

static int event_handler(void *_ctx, void *data, size_t size) {
    if (size != sizeof(struct open_event)){
        printf("receive unmatch size %d\n", (int)size);
        return 0;
    }
    struct open_event* event = (struct open_event*)data;
    printf("[%d] open %s\n", event->pid, event->fname);
    return 0;
}

int main(int argc, char *argv[]) {
    int fd;
    if (load_bpf_file("./syscall_tp_openat_kern.o")) {
        perror("fail to load bpf file");
        return 1;
    }
    fd = map_fd[0];
    /*
	obj = bpf_object__open_file("./syscall_tp_openat_kern.o", NULL);
	if (libbpf_get_error(obj)) {
        perror("Fail to open bpf file");
        return 1;
    }
	if (bpf_object__load(obj)) {
        perror("Fail to load bpf prog");
        return 1;
    }
	fd = bpf_object__find_map_fd_by_name(obj, "opens");
    if (fd<0) {
        perror("Fail to locate map");
        return 1;
    }
    */
    ring_buf = ring_buffer__new(fd, event_handler, NULL, NULL);
    if (!ring_buf) {
        perror("Fail to alloc ring buf");
        return 1;
    }
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
    while (ring_buffer__poll(ring_buf, -1) >= 0) {}
    int_exit(0);

    return 0;
}
