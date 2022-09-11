#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "conn.h"
#include "conn.skel.h"

#include <map>
#include <algorithm>
#include <tuple>
#include <string>
#include <set>
using namespace std;



// cpp code, to compile run `CC=g++ make conn`

static struct ring_buffer *ring_buf = NULL;
static struct conn_bpf *skel = NULL;
static int exiting = 0;
static void int_exit(int sig) {
    exiting = 1;
    if (ring_buf) {
        ring_buffer__free(ring_buf);
        ring_buf= NULL;
    }
    if (skel){
        conn_bpf__destroy(skel);
        skel = NULL;
    }
}

using xtt =  tuple<time_t, string, string>;
static map<int, xtt> pids;
char ob[256];
static int event_handler(void *_ctx, void *data, size_t size) {
    if (size != sizeof(struct conn_event)){
        printf("receive unmatch size %d\n", (int)size);
        return 0;
    }
    struct conn_event* event = (struct conn_event*)data;
    struct sockaddr_in* addr = (struct sockaddr_in*)(&(event->addr));
    int port=0;
    if (addr->sin_family==AF_INET) {
        unsigned char *ip = (unsigned char*)(&(addr->sin_addr.s_addr));
        sprintf(ob, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
        port = ntohs(addr->sin_port);
    } else if (addr->sin_family==AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        unsigned char *ip6 = addr6->sin6_addr.s6_addr;
        int k=0; for (k=0; k<16; k++) if (ip6[k]) break;
        int j=0;
        if (k==10) {
            ob[0]=':'; ob[1]=':'; j=2;
            for (; k<12; k++) {
                if (ip6[k]!=0xff) break;
                else { ob[j++]='F'; ob[j++]='F'; }
            }
            if (k==12) {
                sprintf(ob+j, ":%d.%d.%d.%d", ip6[12], ip6[13], ip6[14], ip6[15]);
            } else {
                while(k<16) {
                    if (k%4) ob[j++]=':';
                    j+=sprintf(ob+j, "%X", ip6[k]);
                    k++;
                }
            }
        } else {
            if (k>4) {
                ob[0]=':'; ob[1]=':'; j=2;
                while(k<16) {
                    if (k%4) ob[j++]=':';
                    j+=sprintf(ob+j, "%X", ip6[k]);
                    k++;
                }
            }
        }
        port = ntohs(addr6->sin6_port);
    } else return 0;
    int pid = event->pid;
    time_t ctime = time(NULL);
    char dir_in = 0;
    if (pid<0) { pid=-pid; dir_in=1; }
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
    if (dir_in) {
        // if (port)
            printf("[%s@%s] accept connection from <%s>\n", get<1>(pids[pid]).c_str(), get<2>(pids[pid]).c_str(), ob);
    } else {
        if (port) 
            printf("[%s@%s] try to connect  <%s:%d>\n", get<1>(pids[pid]).c_str(), get<2>(pids[pid]).c_str(), ob, port);
        else
            printf("[%s@%s] try to reach  <%s>\n", get<1>(pids[pid]).c_str(), get<2>(pids[pid]).c_str(), ob);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int err;
	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	skel = conn_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	err = conn_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}
	err = conn_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}
    ring_buf = ring_buffer__new(bpf_map__fd(skel->maps.conns), event_handler, NULL, NULL);
    if (!ring_buf) {
        perror("Fail to alloc ring buf");
		goto cleanup;
    }
	while (!exiting) {
        if(ring_buffer__poll(ring_buf, -1) < 0) break;
    }

cleanup:
    int_exit(0);
    return 0;
}
