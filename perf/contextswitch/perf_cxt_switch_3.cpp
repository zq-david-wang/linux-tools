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
#include <elf.h>
#include <string.h>

#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <algorithm>
using namespace std;


#define MAXN  128
#define MAXCPU 1024
#define error(msg) do { perror(msg); exit(1); } while(0)
//--------------------------------Tree for call chain and report-------------------------------
//
struct TNode {
    int c=0;
    unordered_map<string, TNode*> s;
    struct TNode *add(string n) {
        c++;
        if (s[n]==nullptr) s[n] = new TNode();
        return s[n];
    }
    int printit(FILE *fp, int k) {
        if (s.size()) {
            using tt = tuple<int, string, TNode*>;
            vector<tt> xx;
            for (auto x: s) xx.push_back(make_tuple(x.second->c, x.first, x.second));
            sort(begin(xx), end(xx), greater<tt>());
            for (auto x: xx) {
                auto count = get<0>(x);
                if (100.0*count/c<1) continue;
                auto name = get<1>(x);
                auto nx = get<2>(x);
                fprintf(fp, "<li>\n");
                fprintf(fp, "<input type=\"checkbox\" id=\"c%d\" />\n", k);
                fprintf(fp, "<label class=\"tree_label\" for=\"c%d\">%s(%.3f%% %d/%d)</label>\n", k, name.c_str(), 100.0*count/c, count, c);
                fprintf(fp, "<ul>\n");
                // printf("%s(%.3f%% %d/%d)\n", name.c_str(), 100.0*count/c, count, c);
                k = nx->printit(fp, k+1);
                fprintf(fp, "</ul>\n");
                fprintf(fp, "</li>\n");
            }
        }
        return k;
    }
};

//--------------------------------symbols-------------------------------------------
using STORE_T = map<unsigned long long, pair<string, unsigned long long>>;
using K_STORE_T = map<unsigned long long, string>;

/*
 * load FUNC symbols refering to the section indicated by the offset, relocate the virtual address
 */
void parse_elf64(FILE *fp, unsigned long long v_addr, unsigned long long v_size, unsigned long long v_offset, STORE_T& store) {
    // printf("read elf with offset 0x%llx, addr 0x%llx\n", v_offset, v_addr);
    Elf64_Ehdr ehdr;
    int rc = fread(&ehdr, sizeof(ehdr), 1, fp);
    if (rc != 1) return;
    int n, s, i;
    unsigned long long offset;

    // load program headers
    unsigned long long p_vaddr, p_size;
    n = ehdr.e_phnum;
    s = ehdr.e_phentsize;
    offset = ehdr.e_phoff;
    Elf64_Phdr phdr;
    for (i=0; i<n; i++) {
        rc = fseek(fp, offset, SEEK_SET); 
        if (rc<0) { perror("fail to seek"); return; }
        rc = fread(&phdr, sizeof(phdr), 1, fp);
        if (rc != 1) { perror("fail to read program header"); return; }
        if (phdr.p_flags&PF_X) {
            if (phdr.p_offset == v_offset) {
                p_vaddr = phdr.p_vaddr;
                p_size = phdr.p_memsz; if (p_size==0) p_size = 0xffffffff;
                break;
            }
        }
        offset+=s;
    }
    if (i>=n) { printf("No program header match offset found, fail to load\n"); return; }

    // load section headers
    n = ehdr.e_shnum;
    s = ehdr.e_shentsize;
    offset = ehdr.e_shoff;
    Elf64_Shdr shdr;
    vector<Elf64_Shdr> headers;
    for (int i=0; i<n; i++) {
        rc = fseek(fp, offset, SEEK_SET); 
        if (rc<0) { perror("fail to seek"); return; }
        rc = fread(&shdr, sizeof(shdr), 1, fp);
        if (rc != 1) { perror("fail to read sec header"); return; }
        headers.push_back(shdr);
        offset+=s;
    }
    Elf64_Sym symb;
    unsigned long long faddr, fsize;
    unsigned long long size, item_size;
    int link, ix, flink, k;
    char fname[128];
    for (int i=0; i<n; i++) {
        switch(headers[i].sh_type) {
            case SHT_SYMTAB:
            case SHT_DYNSYM:
                offset = headers[i].sh_offset;
                size = headers[i].sh_size;
                item_size = headers[i].sh_entsize;
                link = headers[i].sh_link;
                if (link<=0) break;
                for (k=0; k+item_size<=size; k+=item_size) {
                    rc = fseek(fp, offset+k, SEEK_SET); if (rc<0) continue;
                    rc = fread(&symb, sizeof(symb), 1, fp); if (rc != 1) continue;
                    if (ELF64_ST_TYPE(symb.st_info) != STT_FUNC ) continue;
                    flink = symb.st_shndx; if (flink==0) continue;
                    fsize = symb.st_size; if (fsize==0) continue;
                    faddr = symb.st_value; if (faddr>p_vaddr+p_size) continue;
                    ix = symb.st_name; if (ix==0) continue;
                    rc = fseek(fp, headers[link].sh_offset+ix, SEEK_SET); if (rc<0) continue;
                    if (fgets(fname, sizeof(fname), fp)==NULL) continue;
                    faddr = faddr-p_vaddr+v_addr;
                    store[faddr] = make_pair(string(fname), fsize);
                }
                break;
            default:
                break;
        }
    }
}

int load_symbol_from_file(const char *path, unsigned long long addr, unsigned long long size, unsigned long long offset, STORE_T& store) {
    printf("loading symble from %s\n", path);
    FILE *fp = fopen(path, "rb");
    if (fp==NULL) { perror("fail to open file"); return -1; }
    char ident[EI_NIDENT], c;
    int err=0;
    int rc = fread(ident, sizeof(ident), 1, fp);
    if (rc != 1) { perror("fail to read ident"); err=-1; goto end; }
    if (ident[0]!=0x7f) { printf("not a elf file\n"); err=-1; goto  end; }
    c=ident[4];
    rc = fseek(fp, 0, SEEK_SET); if (rc<0) { perror("fail to rewind"); goto end; }
    if (c == ELFCLASS32) {
        printf("32bit elf not supported yet\n"); err=-2; goto end;
    } else if (c == ELFCLASS64) {
        parse_elf64(fp, addr, size, offset, store);
    }

end:
    fclose(fp);
    return err;
}

static unsigned long long parse_hex(char *p, int *n) {
    unsigned long long r=0;
    int i=0;
    *n = 0;
    while(p[i]==' '||p[i]=='\t') i++;
    if (p[i]==0) return 0;
    if (p[i+1]=='x') i+=2;
    int v;
    while(p[i]) {
        if (p[i]>='0'&&p[i]<='9') v=p[i]-'0';
        else if (p[i]>='a'&&p[i]<='f') v=10+p[i]-'a';
        else if (p[i]>='A'&&p[i]<='F') v=10+p[i]-'A';
        else break;
        r=(r<<4)+v;
        i++;
    }
    *n = i;
    return r;
}

STORE_T*  load_symbol_pid(int pid) {
    printf("loading symbols for %d\n", pid);
    char bb[128];
    sprintf(bb, "/proc/%d/maps", pid);
    FILE* fp = fopen(bb, "r");
    if (fp==NULL) return NULL;
    STORE_T *store = new STORE_T();
    unsigned long long start, end, offset;
    char *p;
    int i, c, j;
    while(1) {
        p=fgets(bb, sizeof(bb), fp); if (p==NULL) break;
        i=0; c=0;
        start = parse_hex(p, &c); if (start==0) continue; i+=c; if (p[i]!='-') continue; i++;
        end = parse_hex(p+i, &c); if (end==0) continue; i+=c;
        // parse type
        for (j=0; j<8; j++) { if (p[i]=='x') break; i++; } if (j>=8) continue;
        while(p[i]!=' '&&p[i]!='\t'&&p[i]!=0) i++; if (p[i]==0) continue;
        offset = parse_hex(p+i, &c); if (c==0) continue;
        // remaining should contains '/' indicating this mmap is refering to a file
        while(p[i]&&p[i]!='/') i++; if (p[i]==0) continue;
        sprintf(bb, "/proc/%d/map_files/%llx-%llx", pid, start, end);
        load_symbol_from_file(bb, start, end-start, offset, *store);
    }
    fclose(fp);
    return store;
}

/* parse kernel func symbols from /proc/kallsyms */
K_STORE_T* load_kernel() {
    FILE* fp = fopen("/proc/kallsyms", "r");
    if (fp == NULL) return NULL;
    char *p; 
    unsigned long long addr;
    int c;
    K_STORE_T* store = new K_STORE_T();
    char bb[128], adr[128], type[8], name[128];
    while(1) {
        p = fgets(bb, sizeof(bb), fp); if (p==NULL) break;
        if (sscanf(p, "%s %s %s", adr, type, name)!=3) continue;;
        if (type[0]!='t'&&type[0]!='T') continue;
        addr=parse_hex(adr, &c); if (c==0) continue;
        (*store)[addr] = string(name);
    }
    return store;
    fclose(fp);
}

//------------------------------perf profiler-------------------------
static long perf_event_open(struct perf_event_attr *perf_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, perf_event, pid, cpu, group_fd, flags);
}
unordered_map<int, STORE_T*> pid_symbols;
K_STORE_T* kernel_symbols = NULL;

struct pollfd polls[MAXCPU];
// res for cleanup
static long long psize;
map<int, pair<void*, long long>> res;
TNode* gnode = NULL;

void int_exit(int _) {
    for (auto x: res) {
        auto y = x.second;
        void* addr = y.first;
        munmap(addr, (1+MAXN)*psize);
        close(x.first);
    }
    res.clear();
    if (gnode!=NULL) {
        FILE* fp = fopen("./report.html", "w");
        if (fp) {
            fprintf(fp, "<head> <link rel=\"stylesheet\" href=\"report.css\"> <script src=\"report.js\"> </script> </head>\n");
            fprintf(fp, "<ul class=\"tree\">\n");
            gnode->printit(fp, 0);
            fprintf(fp, "</ul>\n");
            fclose(fp);
            printf("report done\n");
        }
        gnode = NULL;
    }
}
/*
perf call chain process
For now, if a address would not be located to some function, the address would be skipped.
 */
int process_event(char *base, unsigned long long size, unsigned long long offset) {
    struct perf_event_header* p = NULL;
    int pid, xpid;
    unsigned long long time;
    offset%=size;
    // assuming the header would fit within size
    p = (struct perf_event_header*) (base+offset);
    offset+=sizeof(*p); if (offset>=size) offset-=size;
    if (p->type != PERF_RECORD_SAMPLE) return p->size;
    // pid, tip;
    pid = *((int *)(base+offset));  offset+=8; if (offset>=size) offset-=size;
    unsigned long long nr = *((unsigned long long*)(base+offset)); offset+=8; if (offset>=size) offset-=size;
    unsigned long long addr, o, addr0;
    if (nr) {
        if (gnode==NULL) gnode=new TNode();
        char bb[64];
        TNode* r = gnode;
        if (pid_symbols.count(pid)==0) pid_symbols[pid] = load_symbol_pid(pid);
        STORE_T* px = pid_symbols[pid];
        addr0 = *((unsigned long long *)(base+offset));
        char user_mark = 0;
        for (int i=nr-1; i>=0; i--) {
            o = i*8+offset; if (o>=size) o-=size;
            addr = *((unsigned long long*)(base+o));
            if ((addr>>56)==(addr0>>56) && (p->misc&PERF_RECORD_MISC_KERNEL)) {
                // skip the cross line command, no idear how to correctly resolve it now.
                if (user_mark) { user_mark=0; continue; }
                // check in kernel
                if (kernel_symbols&&!kernel_symbols->empty()) {
                    auto x = kernel_symbols->upper_bound(addr);
                    if (x==kernel_symbols->begin()) {
                        // sprintf(bb, "0x%llx", addr); r = r->add(string(bb));
                    } else {
                        x--;
                        r = r->add((*x).second);
                    }
                } else {
                    // sprintf(bb, "0x%llx", addr); r = r->add(string(bb));
                }
            } else {
                if (px) {
                    auto x = px->upper_bound(addr);
                    if (x==px->begin()) {
                        // sprintf(bb, "0x%llx", addr); r = r->add(string(bb));
                    } else {
                        x--;
                        auto y = (*x).second;
                        if (addr>(*x).first+y.second) {
                            // r = r->add(y.first);
                            // sprintf(bb, "0x%llx", addr); r = r->add(string(bb));
                        } else {
                            r = r->add(y.first);
                        }
                    }
                } else {
                    // sprintf(bb, "0x%llx", addr); r = r->add(string(bb));
                }
                user_mark=1;
            }
        }
    }
    return p->size;
}

int main(int argc, char *argv[]) {
    if (argc != 2) { printf("need pid\n"); return 1; }
    load_kernel();
    int pid = atoi(argv[1]); if (pid<=0) { printf("invalid pid %s\n", argv[1]); return 1; }
    // find cgroup
    char xb[256], xb2[256];
    int i, j, k;
    int fd;
    void *addr;
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
    attr.config = PERF_COUNT_SW_CONTEXT_SWITCHES;
    // attr.config = PERF_COUNT_SW_CPU_MIGRATIONS;
    attr.sample_period = 1;
    attr.wakeup_events = 32;
    attr.sample_type = PERF_SAMPLE_TID|PERF_SAMPLE_CALLCHAIN;
    attr.context_switch = 1;
    // attr.sample_id_all = 1;
    for (i=0, k=0; i<cpu_num&&i<MAXCPU; i++) {
        printf("attaching cpu %d\n", i);
        fd = perf_event_open(&attr, cgroup_id, i, -1, PERF_FLAG_FD_CLOEXEC|PERF_FLAG_PID_CGROUP);
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
