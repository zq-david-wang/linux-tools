#include <stdio.h>
#include <string.h>
#include <linux/bpf.h>
#include <unistd.h>
#include <asm/unistd.h>

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

unsigned int parse(char *p) {
    int k, i=0, b;
    unsigned int ip=0, mk=0xffffffff;
    for (k=0; k<4; k++) {
        b=0;
        if (p[i]<'0'||p[i]>'9') return 0;
        while(p[i]>='0'&&p[i]<='9') {
            b=b*10+p[i++]-'0';
            if (b>256) return 0;
        }
        if (k<3&&p[i]!='.') return 0;
        if (k==3&&p[i]!=0&&p[i]!='/') return 0;
        ip = (ip<<8) | b;
        if (k==3) break;
        i++;
    }
    if (p[i]==0) mk=0xffffffff;
    else if (p[i]=='/') {
        i++; b=0;
        while(p[i]>='0'&&p[i]<='9') {
            b=b*10+p[i++]-'0';
            if (b>32) return 0;
        }
        if (p[i]!=0||b>32||b<1) return 0;
        b=32-b;
        mk>>=b; mk<<=b;
    } else return 0;
    return ip&mk;
}

int main(int argc, char *argv[]) {
    unsigned int ip, value;
    union bpf_attr attr_pin, attr_elem;
    int fd, rc;
    memset(&attr_pin, 0, sizeof(attr_pin));
    memset(&attr_elem, 0, sizeof(attr_elem));
    attr_pin.pathname = ptr_to_u64("/sys/fs/bpf/rules");
    fd = sys_bpf(BPF_OBJ_GET, &attr_pin, sizeof(attr_pin));
    if (fd<0) {
        printf("bpf map /sys/fs/bpf/rules not exist yet, need to start bpf prog first\n");
        return 1;
    }
    attr_elem.map_fd = fd;
    attr_elem.key = ptr_to_u64(&ip);
    attr_elem.value = ptr_to_u64(&value);
    if (argc != 3) {
        printf("usage: %s [allow/block] [ipnetwork]\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "allow")==0) {
        ip = parse(argv[2]);
        printf("allow ip %x\n", ip);
        if (ip==0) {
            printf("ip network %s not valid\n", argv[2]);
            return 1;
        }
        value=0;
        rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc<0) {
            printf("fail to register the firewall rule\n");
            return 1;
        }
    } else if (strcmp(argv[1], "block")==0) {
        ip = parse(argv[2]);
        printf("block ip %x\n", ip);
        if (ip==0) {
            printf("ip network %s not valid\n", argv[2]);
            return 1;
        }
        value=1;
        rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc<0) {
            printf("fail to register the firewall rule\n");
            return 1;
        }
    } else {
        printf("usage: %s [allow/block] [ipnetwork]\n", argv[0]);
        return 1;
    }
}
