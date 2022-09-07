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
#include <queue>
using namespace std;


#define error(msg) do { perror(msg); exit(1); } while(0)
#define MAXN  128

static long perf_event_open(struct perf_event_attr *perf_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, perf_event, pid, cpu, group_fd, flags);
}
static void *addr = NULL;
static int fd = -1;
static long long psize;
vector<int> res;
static unsigned long long cx_count=0, g_stime=0, g_total=0, g_rtotal=0;
int alive=1;
void int_exit(int s) {
    for (auto x: res) close(x);
    res.clear();
    alive=0;
}



#define MAXCPU 1024
char buf[10240];
int main(int argc, char *argv[]) {
    if (argc != 2) { printf("need pid\n"); return 1; }
    int pid = atoi(argv[1]); if (pid<=0) { printf("invalid pid %s\n", argv[1]); return 1; }
    // find cgroup
    char xb[256], xb2[256];
    int i, j, k;
    sprintf(xb, "/proc/%d/cgroup", pid);
    FILE* fp = fopen(xb, "r");
    if (fp==NULL) error("fail to open cgroup file");
    char *p;
    xb2[0]=0;
    int cgroup_name_len=0;
    while(1) {
        p = fgets(xb, sizeof(xb), fp); if (p==NULL) break;
        i=0; while(p[i]&&p[i]!=':') i++; if (p[i]==0) continue; 
        if (strstr(p, "perf_event")) {
            i++; while(p[i]!=':'&&p[i]) i++;  if (p[i]!=':') continue; i++;
            j=i; while(p[j]!='\r'&&p[j]!='\n'&&p[j]!=0) j++; p[j]=0;
            sprintf(xb2, "/sys/fs/cgroup/perf_event%s", p+i);
            cgroup_name_len=j-i;
            break;
        } else if (p[i+1]==':') {
            i+=2; j=i; while(p[j]!='\r'&&p[j]!='\n'&&p[j]!=0) j++; p[j]=0;
            sprintf(xb2, "/sys/fs/cgroup/%s", p+i);
            cgroup_name_len=j-i;
        }
    }
    fclose(fp);
    if (xb2[0]==0) error("no proper cgroup found\n");
    if (cgroup_name_len<2) {
        printf("cgroup %s seems to be root, not allowed\n", xb2);
        return -1;
    }

    printf("try to use cgroup %s\n", xb2);
    int cgroup_id = open(xb2, O_CLOEXEC);
    if (cgroup_id<=0) { perror("error open cgroup dir"); return 1; }

    // start perf event
    psize = sysconf(_SC_PAGE_SIZE); // getpagesize();
    int cpu_num = sysconf(_SC_NPROCESSORS_ONLN);
	struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.config = PERF_COUNT_SW_PAGE_FAULTS_MAJ;
    for (i=0, k=0; i<cpu_num&&i<MAXCPU; i++) {
        printf("attaching cpu %d\n", i);
        fd = perf_event_open(&attr, cgroup_id, i, -1, PERF_FLAG_FD_CLOEXEC|PERF_FLAG_PID_CGROUP);
        if (fd<0) { perror("fail to open perf event"); continue; }
        res.push_back(fd);
    }
    if (res.size()==0) { printf("no cpu event attached at all\n"); return 1; }

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);

    unsigned long long counter;
    while(alive) {
        sleep(1);
        counter = 0;
        for (auto x:res) {
            k = read(x, buf, sizeof(buf));
            if (k>=8) {
               counter += *(unsigned long long *)buf;
            }
            if (k<0) perror("fail to read");
        }
        printf("counter --> %lld\n", counter);
    }


    int_exit(0);
    return 0;
}
