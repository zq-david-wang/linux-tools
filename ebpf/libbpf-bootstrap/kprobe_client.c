#include <stdio.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <string.h>


static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}
static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}


int get_root_fd() {
    union bpf_attr attr_pin;
    int fd, rc;
    memset(&attr_pin, 0, sizeof(attr_pin));
    attr_pin.pathname = ptr_to_u64("/sys/fs/bpf/ksysread_stats");
    fd = sys_bpf(BPF_OBJ_GET, &attr_pin, sizeof(attr_pin));
    return fd;
}


int main(int argc, char *argv[]) {
    unsigned int vip, ip;
    int i, rc, fd;
    union bpf_attr attr_elem;
    unsigned int key;
    unsigned long long value, b=1;
    int root_fd = get_root_fd();
    if (root_fd < 0) {
        perror("fail to open map\n");
        return -1;
    }
    memset(&attr_elem, 0, sizeof(attr_elem));
    attr_elem.flags = BPF_ANY;
    attr_elem.map_fd = root_fd;
    attr_elem.key    = ptr_to_u64(&key);
    attr_elem.value    = ptr_to_u64(&value);
    for (key=0; key<32; key++) {
        rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("fail to get read stats %d\n", key);
            return 0;
        }
        // if (value==0) continue;
        if (b>=1024*1024) printf("%6lldMB: %-9lld\n", b/1024/1024, value);
        else if (b>=1024) printf("%6lldKB: %-9lld\n", b/1024, value);
        else printf("%7lldB: %-9lld\n", b, value);
        b<<=1;
    }
    return 0;
}
