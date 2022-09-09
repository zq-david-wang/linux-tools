#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>

#include "openat.h"
#include "openat.skel.h"

#include <map>
#include <algorithm>
#include <tuple>
#include <string>
#include <set>
using namespace std;



// cpp code, to compile run `CC=g++ make openat`

static struct ring_buffer *ring_buf = NULL;
static struct openat_bpf *skel = NULL;
static int exiting = 0;
static void int_exit(int sig) {
    exiting = 1;
    if (ring_buf) {
        ring_buffer__free(ring_buf);
        ring_buf= NULL;
    }
    if (skel){
        openat_bpf__destroy(skel);
        skel = NULL;
    }
}

using xtt =  tuple<time_t, string, string>;
static map<int, xtt> pids;
static set<string> whitelist; // = {"gnome-shell","firefox-esr", "openat"};
static int event_handler(void *_ctx, void *data, size_t size) {
    if (size != sizeof(struct open_event)){
        printf("receive unmatch size %d\n", (int)size);
        return 0;
    }
    struct open_event* event = (struct open_event*)data;
    if (event->fname[0]==0) return 0;
    int pid = event->pid;
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
    if (whitelist.count(get<1>(pids[pid]))==0) {
        printf("[%s@%s] open file <%s>\n", get<1>(pids[pid]).c_str(), get<2>(pids[pid]).c_str(), event->fname);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int err;
    char *p = argv[0];
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	skel = openat_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	err = openat_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	err = openat_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
    ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.opens), event_handler, NULL, NULL);
    if (!ring_buf) {
        perror("Fail to alloc ring buf");
		goto cleanup;
    }
    // white list self
    for (int i=0; p[i]; i++) {
        if (p[i]=='/') { p+=i; p++; i=-1; }
    } whitelist.insert(p);
    for (int i=1; i<argc; i++) whitelist.insert(argv[i]);
	while (!exiting) {
        if(ring_buffer__poll(ring_buf, -1) < 0) break;
    }

cleanup:
    int_exit(0);
    return 0;
}
