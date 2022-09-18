#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <asm/perf_regs.h>


#include <map>
#include <unordered_set>
#include <unordered_map>
#include <queue>
using namespace std;


#define error(msg) do { perror(msg); exit(1); } while(0)
#define MAXN  128

// refer to https://lkml.kernel.org/netdev/D0757E13-27E8-4392-972A-399D6E132111@fb.com/t/
//
//
//
static long perf_event_open(struct perf_event_attr *perf_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, perf_event, pid, cpu, group_fd, flags);
}
static void *addr = NULL;
static long long psize;
map<int, pair<void*, long long>> res;
static int alive=1;
void int_exit(int s) {
    for (auto x: res) {
        auto y = x.second;
        void* addr = y.first;
        munmap(addr, (1+MAXN)*psize);
        close(x.first);
    }
    res.clear();
    alive=0;
    exit(0);
}

char *func = NULL;
using xtt =  tuple<time_t, string, string>;
static map<int, xtt> pids;
int process_event(char *base, unsigned long long size, unsigned long long offset) {
    struct perf_event_header* p = NULL;
    int pid, i;
    unsigned long long abi, addr, arg1, arg2, arg3, arg4;
    offset%=size;
    // assuming the header would fit within size
    p = (struct perf_event_header*) (base+offset);
    offset+=sizeof(*p); if (offset>=size) offset-=size;
    if (p->type == PERF_RECORD_SAMPLE) {
        pid = *(int*)(base+offset);  offset+=8; if (offset>=size) offset-=size;
        time_t ctime = time(NULL);
        if (pids.count(pid)==0 || ctime-get<0>(pids[pid]) > 1000) {
            char b[128];
            char comm[128];
            char host[128];
            sprintf(b, "/proc/%d/comm", pid);
            FILE* fp;
            size_t i=0;
            fp = fopen(b, "r"); if (fp) {
                comm[0]=0; fgets(comm, sizeof(comm), fp);
                while(i<sizeof(comm)&&comm[i]!=0&&comm[i]!='\n'&&comm[i]!='\r') i++;
                comm[i]=0;
                fclose(fp);
            }
            if (i<1) strcpy(comm, "unknown-command");
            sprintf(b, "/proc/%d/root/etc/hostname", pid);
            i=0; fp = fopen(b, "r"); if (fp) {
                host[0]=0; fgets(host, sizeof(host), fp);
                while(i<sizeof(host)&&host[i]!=0&&host[i]!='\n'&&host[i]!='\r') i++;
                host[i]=0;
                fclose(fp);
            }
            if (i<1) strcpy(host, "unknown-host");
            pids[pid] = make_tuple(ctime, string(comm), string(host));
        }
        abi = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size;
        if (abi == PERF_SAMPLE_REGS_ABI_64) {
            addr = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rax
            arg3 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rdx
            arg2 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rsi
            arg1 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rdi
            arg4 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //r10
            printf("%s@%s[%d] %s(0x%llx,0x%llx,0x%llx,0x%llx)\n", get<1>(pids[pid]).c_str(), get<2>(pids[pid]).c_str(), pid, func, arg1, arg2, arg3, arg4);
        }
    }
    return p->size;
}


#define MAXCPU 1024
struct pollfd polls[MAXCPU];
int main(int argc, char *argv[]) {
    int i, k, type;
    // start perf event
    if (argc<2) { printf("Need kprobe function name, e.g. %s do_sys_open\n", argv[0]); return 1; }
    func = argv[1];
    psize = sysconf(_SC_PAGE_SIZE); // getpagesize();
    int cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
	struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    // /sys/bus/event_source/devices/kprobe/type
    FILE *fp = fopen("/sys/bus/event_source/devices/kprobe/type", "r");
    if (fp == NULL) { printf("fail to find type for kprobe\n"); return 1; }
    type = 0;
    fscanf(fp, "%d", &type);
    fclose(fp);
    if (type <= 0) { printf("unexpected type %d\n", type); return 1; }
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = 0; // (1<<0) for kreprobe
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.sample_type = PERF_SAMPLE_TID|PERF_SAMPLE_REGS_INTR;
    // ffffffff92ea9240 t bprm_execve
    attr.kprobe_func = (__u64)func; // "do_sys_open"; // "bprm_execve";
    attr.probe_offset = 0;
    attr.sample_regs_intr = (1<<PERF_REG_X86_AX)|(1<<PERF_REG_X86_DI)|(1<<PERF_REG_X86_SI)|(1<<PERF_REG_X86_DX)|(1<<PERF_REG_X86_R10)|
        (1<<PERF_REG_X86_R8)|(1<<PERF_REG_X86_R9);
    int fd, cgroup_fd;
    for (i=0, k=0; i<cpu_num&&i<MAXCPU; i++) {
        printf("attaching cpu %d\n", i);
        fd = perf_event_open(&attr, -1, i, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd<0) { perror("fail to open perf event"); continue; }
        addr = mmap(NULL, (1+MAXN)*psize, PROT_READ, MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) { perror("mmap failed"); close(fd); continue; }
        res[fd] = make_pair(addr, 0);
        polls[k].fd = fd;
        polls[k].events = POLLIN;
        polls[k].revents = 0;
        k++;
    }
    if (k==0) { printf("no cpu event attached at all\n"); return 1; }

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

    unsigned long long head;
    struct perf_event_mmap_page *mp;
    while (poll(polls, k, -1)>0) {
        for (i=0; i<k; i++) {
            if (!alive) break;
            if ((polls[i].revents&POLLIN)==0) continue;
            fd = polls[i].fd;
            addr = res[fd].first;
            mp = (struct perf_event_mmap_page *)addr;
            head = res[fd].second;
            if (head==mp->data_head) continue;
            ioctl(fd, PERF_EVENT_IOC_PAUSE_OUTPUT, 1);
            head = mp->data_head-((mp->data_head-head)%mp->data_size);
            while(head<mp->data_head) head+=process_event((char*)addr+mp->data_offset, mp->data_size, head);
            ioctl(fd, PERF_EVENT_IOC_PAUSE_OUTPUT, 0);
            res[fd].second = mp->data_head;
        }
    }
    int_exit(0);
    return 0;
}
