#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>


enum {
    PTRACEXX_REMAP = 1,
};

typedef struct {
    int pid;
    unsigned long old_start, old_end;
    unsigned long new_start, new_end;
} RemapDataT;

typedef union {
    RemapDataT remap;
} IoctlDataT;

int main() {
    char fb[64];
    IoctlDataT d;
    int fd, w=0;
    long rc;
    int pid=2024;
    // 7fffbebcf000-7fffbebd1000
    unsigned long start=0x7fffbebcf000L;
    unsigned long end=0x7fffbebd1000L;
    unsigned long nstart=0x7ffff0000000L;
    unsigned int magic = 0x12345678;
    unsigned int v, vv;
    size_t n;
    fd = open("/dev/ptracexx", O_NONBLOCK);
    if (fd<0) { perror("fail to open ptracexx\n"); return -1; }
    sprintf(fb, "/proc/%d/mem", pid);
    FILE *mem = fopen(fb, "rb");
    if (mem==NULL) {
        printf("fail to open virtual mem space for pid %d\n", pid);
        close(fd);
        return -1;
    }
    d.remap.pid = pid;;
    d.remap.old_start = start;
    d.remap.old_end = end;
    d.remap.new_start = nstart;
    d.remap.new_end = end-start+nstart;
    fseek(mem, start, SEEK_SET);
    if (w) {
        n = fwrite(&magic, 1, sizeof(magic), mem);
        printf("write magic ==> %ld\n", n);
    }
    fread(&v, 1, sizeof(v), mem);
    fclose(mem); mem=NULL;
    // remap
    rc = ioctl(fd, PTRACEXX_REMAP, &d);
    if (rc<0) {
        printf("fail to remap %ld\n", rc);
    } else {
        mem = fopen(fb, "rb");
        fseek(mem, nstart, SEEK_SET);
        if (w) {
            n = fread(&vv, 1, sizeof(vv), mem);
            printf("read back(%ld) %d, expect %d\n", n, vv, magic);
        }
        n = fread(&vv, 1, sizeof(vv), mem);
        printf("read after remap(%ld) %d, old value %d\n",n, vv, v);
    }
    if (mem) fclose(mem);
    close(fd);
    return 0;
}
