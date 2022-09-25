#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <string.h>
#include <bpf/bpf.h>
#include "l3lb.h"


int main(int argc, char **argv) {
    __u32 curr_prog_fd=0;
    int prog_fd;
    if (argc != 4) {
        printf("Usage: %s [in_inf] [out_inf] [tx_addr]\n", argv[0]);
        return 1;
    }
    int if1 = if_nametoindex(argv[1]);
    if (!if1) { perror("Fail to get inf index"); return 1; }
    if (bpf_get_link_xdp_id(if1, &curr_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST)) { perror("bpf_get_link_xdp_id failed\n"); return 1; }
    if (curr_prog_fd) {
        printf("xdp prog id(%d) already linked to %s, removing it now..\n", curr_prog_fd, argv[1]);
        bpf_set_link_xdp_fd(if1, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
    }
    int if2 = if_nametoindex(argv[2]);
    if (!if2) { perror("Fail to get inf index"); return 1; }
    if (bpf_get_link_xdp_id(if2, &curr_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST)) { perror("bpf_get_link_xdp_id failed\n"); return 1; }
    if (curr_prog_fd) {
        printf("xdp prog id(%d) already linked to %s, removing it now..\n", curr_prog_fd, argv[2]);
        bpf_set_link_xdp_fd(if2, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
    }
    unsigned int tx_addr = parse_ip(argv[3]);
    if (tx_addr==0) { printf("invalid tx ip address %s\n", argv[3]); return 1; }
    // load bpf object
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
        .file = "./l3lb_kern.o",
	};
	struct bpf_object *obj;
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
        perror("Fail to load bpf object");
        return 1;
    }
	int map_fd = bpf_object__find_map_fd_by_name(obj, "tx_addr");
    if (map_fd<0) { perror("Fail to locate tx addr map"); return 1; }
    int key = 0;
	int ret = bpf_map_update_elem(map_fd, &key, &tx_addr, 0);
    if (ret) { perror("Fail to update tx addr"); return 1; }

    if (bpf_set_link_xdp_fd(if1, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        printf("fail to link if1\n"); return 1;
    }
    if (bpf_set_link_xdp_fd(if2, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
        printf("fail to link if2\n"); return 1;
    }
    return 0;
}
