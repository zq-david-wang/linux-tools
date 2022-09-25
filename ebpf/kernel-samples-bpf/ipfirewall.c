#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <string.h>

int main(int argc, char **argv) {
    int i, ifindex;
    __u32 curr_prog_fd=0;
    int prog_fd;
    for (i=1; i<argc; i++) {
        ifindex = if_nametoindex(argv[i]);
        if (!ifindex) {
            perror("if_nametoindex");
            return 1;
        }
        if (bpf_get_link_xdp_id(ifindex, &curr_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST)) {
            printf("bpf_get_link_xdp_id failed\n");
            return 1;
        }
        if (curr_prog_fd) {
            printf("xdp prog id(%d) already linked to %s, removing it now..\n", curr_prog_fd, argv[i]);
            bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
        }
    }
    // load bpf object
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
        .file = "./ipfirewall_kern.o",
	};
	struct bpf_object *obj;
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
        perror("Fail to load bpf object");
        return 1;
    }
    for (i=1; i<argc; i++) {
        ifindex = if_nametoindex(argv[i]);
        if (bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST) < 0) {
            printf("Fail to link to %s\n", argv[i]);
            for (i--; i>=1; i--) {
                bpf_set_link_xdp_fd(ifindex, -1, XDP_FLAGS_UPDATE_IF_NOEXIST);
            }
            return 1;
        }
    }
    return 0;
}
