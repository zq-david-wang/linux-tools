#include <stdio.h>
#include <unistd.h>
#include <linux/bpf.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <string.h>


#define MAXN 128
typedef unsigned int VNode[MAXN];

static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}



int get_root_fd() {
    union bpf_attr attr_create, attr_pin;
    int fd, rc;
    memset(&attr_pin, 0, sizeof(attr_pin));
    memset(&attr_create, 0, sizeof(attr_create));
    attr_pin.pathname = ptr_to_u64("/sys/fs/bpf/viprules");
    fd = sys_bpf(BPF_OBJ_GET, &attr_pin, sizeof(attr_pin));
    if (fd<0) {
        attr_create.map_type = BPF_MAP_TYPE_HASH;
        attr_create.key_size    = sizeof(unsigned int);
        attr_create.value_size  = sizeof(VNode);
        attr_create.max_entries = 1024;
        strcpy(attr_create.map_name, "viprules");
        printf("root bpf map not initialized, create it now\n");
        fd = sys_bpf(BPF_MAP_CREATE, &attr_create, sizeof(attr_create));
        if (fd<0) {
            perror("fail to create bpf map:");
            return -1;
        }
        attr_pin.bpf_fd = fd;
        rc = sys_bpf(BPF_OBJ_PIN, &attr_pin, sizeof(attr_pin));
        if (rc != 0) {
            perror("fail to pin root bpf map:");
            return -1;
        }
    }
    return fd;
}

unsigned int parse_ip(char *p) {
    int k, i=0, b;
    unsigned int ip=0;
    for (k=0; k<4; k++) {
        b=0;
        if (p[i]<'0'||p[i]>'9') return 0;
        while(p[i]>='0'&&p[i]<='9') {
            b=b*10+p[i++]-'0';
            if (b>256) return 0;
        }
        if (p[i]!=0&&p[i]!='.') return 0;
        ip |= b<<(k*8);
        if (k==3) break;
        i++;
    }
    if (p[i]!=0) return 0;
    return ip;
}

void print_ip(unsigned int ip) {
    int k;
    int bs[4];
    for (k=0; k<4; k++) {
        bs[k] = ip&0xff;
        ip>>=8;
    }
    printf("%d.%d.%d.%d\n", bs[0], bs[1], bs[2], bs[3]);
}

int main(int argc, char *argv[]) {
    unsigned int vip, ip;
    int i, rc, fd, n;
    union bpf_attr attr_elem;
    unsigned int key;
    VNode value;
    unsigned int rip;
    int root_fd = get_root_fd();
    if (root_fd < 0) return -1;
    memset(&attr_elem, 0, sizeof(attr_elem));
    attr_elem.flags = BPF_ANY;

    
    if (argc==3&&strcmp(argv[1], "list")==0) {
        vip = parse_ip(argv[2]);
        if (vip==0) {
            printf("invalid ip: %s\n", argv[2]);
            return -1;
        }
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&vip);
        attr_elem.value    = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("vip not found\n");
            return 0;
        }
        printf("vip: %s\n", argv[2]);
        n = value[0];
        for (i=0; i<n; i++) print_ip(value[i+1]);
    } else if (argc==3&&strcmp(argv[1], "pop")==0) {
        vip = parse_ip(argv[2]);
        if (vip==0) {
            printf("invalid ip: %s\n", argv[2]);
            return -1;
        }
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&vip);
        attr_elem.value    = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("vip not found\n");
            return 0;
        }
        if (value[0]==0) {
            printf("no real ip to pop\n");
            return 0;
        }
        value[0]-=1;
        rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("fail to sync count\n");
            return -1;
        }
    } else if (argc==4&&strcmp(argv[1], "push")==0) {
        vip = parse_ip(argv[2]);
        if (vip==0) {
            printf("invalid ip: %s\n", argv[2]);
            return -1;
        }
        attr_elem.map_fd = root_fd;
        attr_elem.key    = ptr_to_u64(&vip);
        attr_elem.value    = ptr_to_u64(&value);
        rc = sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("vip not found, adding new entry now\n");
            value[0]=0;
            rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
            if (rc!=0) {
                perror("fail to register new vip\n");
                return -1;
            }
        }
        if (value[0]+1>=MAXN) {
            printf("rip cap reached, could not append more\n");
            return -1;
        }
        ip = parse_ip(argv[3]);
        if (ip==0) {
            printf("invalid ip: %s\n", argv[3]);
            return -1;
        }
        value[0]+=1;
        value[value[0]]=ip;
        rc = sys_bpf(BPF_MAP_UPDATE_ELEM, &attr_elem, sizeof(attr_elem));
        if (rc!=0) {
            printf("fail to sync count\n");
            return -1;
        }
    } else {
        return -1;
    }

    return 0;
}
