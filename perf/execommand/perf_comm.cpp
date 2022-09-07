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


#include <map>
#include <unordered_set>
#include <unordered_map>
#include <queue>
using namespace std;


#define error(msg) do { perror(msg); exit(1); } while(0)
#define MAXN  128

static long perf_event_open(struct perf_event_attr *perf_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, perf_event, pid, cpu, group_fd, flags);
}
static void *addr = NULL;
static long long psize;
map<int, pair<void*, long long>> res;
static unsigned long long cx_count=0, g_stime=0, g_total=0, g_rtotal=0;
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
}

unordered_map<int, string> hostnames;
unordered_map<int, string> commands;
queue<int> pids;
char bb[256];
int get_hostname(int pid) {
    sprintf(bb, "/proc/%d/root/etc/hostname", pid);
    FILE* fp = fopen(bb, "r");
    int i=0;
    if (fp) {
        fgets(bb, sizeof(bb), fp);
        while(i<sizeof(bb)-1&&bb[i]&&bb[i]!='\r'&&bb[i]!='\n') i++; bb[i]=0;
        fclose(fp);
    }
    return i;
}

int process_event(char *base, unsigned long long size, unsigned long long offset) {
    struct perf_event_header* p = NULL;
    int pid, i, j, ppid;
    offset%=size;
    // assuming the header would fit within size
    p = (struct perf_event_header*) (base+offset);
    offset+=sizeof(*p); if (offset>=size) offset-=size;
    if (p->type == PERF_RECORD_FORK) {
        pid = *(int*)(base+offset); 
        ppid = *(int*)(base+offset+4); 
        if (hostnames.count(pid)==0&&get_hostname(ppid)) hostnames[pid] =string(bb);
    } else if (p->type == PERF_RECORD_COMM) {
        pid = *(int*)(base+offset); 
        offset+=8; if (offset>=size) offset-=size;
        i=offset;
        for (j=0; j<sizeof(bb)-1; j++) {
            if (base[i]==0) break;
            bb[j]=base[i];
            i++; if (i>=size) i-=size;
        } bb[j]=0;
        commands[pid] = string(bb);
        if (hostnames.count(pid)==0&&get_hostname(pid)) hostnames[pid] = string(bb);
        pids.push(pid);
    } else if (p->type == PERF_RECORD_EXIT) {
        pid = *(int*)(base+offset); 
        ppid = *(int*)(base+offset+4); 
        if (hostnames.count(pid)==0&&get_hostname(ppid)) hostnames[pid] =string(bb);
        pids.push(-pid);
    }
    return p->size;
}

void process_queue() {
    int pid;
    while(!pids.empty()) {
        pid=pids.front(); pids.pop();
        if (pid>0) {
            if (commands.count(pid)==0) continue;
            if (hostnames.count(pid)==0&&get_hostname(pid)) hostnames[pid]=string(bb);
            if (hostnames.count(pid)==0) {
                printf("<--?--> start command [%s](%d)\n", commands[pid].c_str(), pid);
            } else {
                printf("<%s> start command [%s](%d)\n", hostnames[pid].c_str(), commands[pid].c_str(), pid);
            }
        } else {
            pid=-pid;
            if (commands.count(pid)) {
                if (hostnames.count(pid)==0) {
                    printf("<--?--> stop  command [%s](%d)\n", commands[pid].c_str(), pid);
                } else {
                    printf("<%s> stop  command [%s](%d)\n", hostnames[pid].c_str(), commands[pid].c_str(), pid);
                }
                commands.erase(pid);
            }
            if (hostnames.count(pid)) hostnames.erase(pid);
        }
    }
    fflush(stdout);
}

#define MAXCPU 1024
struct pollfd polls[MAXCPU];
int main(int argc, char *argv[]) {
    int i, k;
    // start perf event
    psize = sysconf(_SC_PAGE_SIZE); // getpagesize();
    int cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
	struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_DUMMY;
    // attr.sample_period = 1;
    // attr.wakeup_events = 1;
    attr.comm = 1;
    // attr.comm_exec = 1;
    attr.sample_id_all = 1;
    attr.task = 1;
    int fd, cgroup_fd;
    for (i=0, k=0; i<cpu_num&&i<MAXCPU; i++) {
        printf("attaching cpu %d\n", i);
        fd = perf_event_open(&attr, -1, i, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd<0) { perror("fail to open perf event"); continue; }
        addr = mmap(NULL, (1+MAXN)*psize, PROT_READ, MAP_SHARED, fd, 0);
        if (addr == MAP_FAILED) { perror("mmap failed"); close(fd); continue; }
        res[fd] = make_pair(addr, 0);
        k++;
    }
    if (k==0) { printf("no cpu event attached at all\n"); return 1; }

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

    unsigned long long head;
    struct perf_event_mmap_page *mp;
    while(alive) {
        process_queue();
        sleep(1);
        for (auto x: res) {
            addr = x.second.first;
            head = x.second.second;
            mp = (struct perf_event_mmap_page *)addr;
            fd = x.first;
            if (head >= mp->data_head) continue;
            ioctl(fd, PERF_EVENT_IOC_PAUSE_OUTPUT, 1);
            head = mp->data_head-((mp->data_head-head)%mp->data_size);
            while(head<mp->data_head) head+=process_event((char*)addr+mp->data_offset, mp->data_size, head);
            res[fd].second = mp->data_head;
            ioctl(fd, PERF_EVENT_IOC_PAUSE_OUTPUT, 0);
        }
    }
    int_exit(0);
    return 0;
}
