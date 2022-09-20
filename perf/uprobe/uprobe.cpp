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
#include <asm/perf_regs.h>

#include <vector>
#include <string>
#include <map>
#include <unordered_map>
#include <algorithm>
using namespace std;


#define MAXN  1024
#define MAXCPU 1024
#define error(msg) do { perror(msg); exit(1); } while(0)
//--------------------------------symbols-------------------------------------------
typedef struct { unsigned long long addr, size, baddr, boffset; } FNode;
using STORE_T = unordered_map<string, FNode>;
/*
 * load FUNC symbols refering to the section indicated by the offset, relocate the virtual address
 */
void parse_elf64(FILE *fp, STORE_T& store) {
    // printf("read elf with offset 0x%llx, addr 0x%llx\n", v_offset, v_addr);
    Elf64_Ehdr ehdr;
    FNode func;
    int rc = fread(&ehdr, sizeof(ehdr), 1, fp);
    if (rc != 1) return;
    int n, s, i;
    unsigned long long offset;

    // load program headers
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
            func.baddr=phdr.p_vaddr;
            func.boffset=phdr.p_offset;
        }
        offset+=s;
    }
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
    // TODO: remove symbols which need relocation
    Elf64_Rel rel;
    Elf64_Rela rela;
    unsigned long long faddr, fsize;
    unsigned long long size, item_size;
    int link, ix, flink, k;
    char fname[128];
    for (int i=0; i<n; i++) {
        offset = headers[i].sh_offset;
        size = headers[i].sh_size;
        item_size = headers[i].sh_entsize;
        link = headers[i].sh_link;
        switch(headers[i].sh_type) {
            case SHT_DYNSYM:
            case SHT_SYMTAB:
                if (link<=0) break;
                for (k=0; k+item_size<=size; k+=item_size) {
                    rc = fseek(fp, offset+k, SEEK_SET); if (rc<0) continue;
                    rc = fread(&symb, sizeof(symb), 1, fp); if (rc != 1) continue;
                    if (ELF64_ST_TYPE(symb.st_info) != STT_FUNC ) continue;
                    flink = symb.st_shndx; if (flink==0) continue;
                    fsize = symb.st_size;
                    faddr = symb.st_value;
                    ix = symb.st_name; if (ix==0) continue;
                    rc = fseek(fp, headers[link].sh_offset+ix, SEEK_SET); if (rc<0) continue;
                    if (fgets(fname, sizeof(fname), fp)==NULL) continue;
                    func.addr=faddr; func.size=fsize;
                    store[string(fname)] = func;
                }
                break;
            default:
                break;
        }
    }
}

STORE_T*  load_symbol_from_file(const char *path) {
    // printf("loading symble from %s\n", path);
    STORE_T *store = NULL;
    FILE *fp = fopen(path, "rb");
    if (fp==NULL) { perror("fail to open file"); return NULL; }
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
        store = new STORE_T();
        parse_elf64(fp, *store);
    }

end:
    fclose(fp);
    return store;
}


//------------------------------perf profiler-------------------------
static long perf_event_open(struct perf_event_attr *perf_event, pid_t pid, int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, perf_event, pid, cpu, group_fd, flags);
}

struct pollfd polls[MAXCPU];
// res for cleanup
static long long psize;
map<int, pair<void*, long long>> res;

void int_exit(int _) {
    for (auto x: res) {
        auto y = x.second;
        void* addr = y.first;
        munmap(addr, (1+MAXN)*psize);
        close(x.first);
    }
    exit(0);
}
/*
perf call chain process
For now, if a address would not be located to some function, the address would be skipped.
 */
int process_event(char *base, unsigned long long size, unsigned long long offset) {
    struct perf_event_header* p = NULL;
    int pid, xpid;
    unsigned long long rax, arg1, arg2, arg3, arg4;
    offset%=size;
    // assuming the header would fit within size
    p = (struct perf_event_header*) (base+offset);
    offset+=sizeof(*p); if (offset>=size) offset-=size;
    if (p->type != PERF_RECORD_SAMPLE) return p->size;
    // pid, tip;
    pid = *((int *)(base+offset));  offset+=8; if (offset>=size) offset-=size;
    unsigned long long abi = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size;
    if (abi == PERF_SAMPLE_REGS_ABI_64) {
        rax = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rax
        arg3 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rdx
        arg2 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rsi
        arg1 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //rdi
        arg4 = *(unsigned long long*)(base+offset); offset+=8; if (offset>=size) offset-=size; //r10
        printf("uprobe event: rax[0x%llx], f(%lld,...)\n", rax, arg1);
    }
    return p->size;
}

struct RNode {
    string func_name, file_name;
    unsigned long long vaddr, raddr;
};
int main(int argc, char *argv[]) {
    char bb[256], *p, *func;
    if (argc<3) { printf("usage: %s <pid> <func_name> \n", argv[0]); return 1; }
    int pid = atoi(argv[1]);
    func = argv[2];
    if (pid<=0) { printf("invalid pid %d\n", pid); return 1; }
    sprintf(bb, "/proc/%d/maps", pid);
    FILE *fp = fopen(bb, "r");
    if (fp==NULL) { printf("Fail to read proc for pid %d\n", pid); return 1; }
    unsigned long long start, end, offset, inode;
    char fname[128], mod[16], idx[32];
    char ff[256];
    char xx[64], xxx[32];
    int i, valid, k;
    int type = 0;
    vector<RNode> cans;
    RNode rr;
    while(1) {
        p = fgets(bb, sizeof(bb), fp); if (p==NULL) break;
        if (sscanf(p, "%s %s %s %s %lld %s", xx, mod, xxx, idx, &inode, fname)!=6) continue;
        for (i=0; i<4; i++) if (mod[i]=='x') break; if (i>=4) continue;
        if (fname[0]!='/') continue;
        valid=1;
        start=0; for (i=0; xx[i]&&xx[i]!='-'; i++) {
            if (xx[i]>='0'&&xx[i]<='9') start=start*16+xx[i]-'0';
            else if (xx[i]>='A'&&xx[i]<='F') start=start*16+xx[i]-'A'+10;
            else if (xx[i]>='a'&&xx[i]<='f') start=start*16+xx[i]-'a'+10;
            else { valid=0; break; }
        }
        if (valid==0||start==0) continue;
        end=0; for (i++; xx[i]; i++) {
            if (xx[i]>='0'&&xx[i]<='9') end=end*16+xx[i]-'0';
            else if (xx[i]>='A'&&xx[i]<='F') end=end*16+xx[i]-'A'+10;
            else if (xx[i]>='a'&&xx[i]<='f') end=end*16+xx[i]-'a'+10;
            else { valid=0; break; }
        }
        if (valid==0||start==0) continue;
        offset=0; for (i=0; xxx[i]; i++) {
            if (xxx[i]>='0'&&xxx[i]<='9') offset=offset*16+xxx[i]-'0';
            else if (xxx[i]>='A'&&xxx[i]<='F') offset=offset*16+xxx[i]-'A'+10;
            else if (xxx[i]>='a'&&xxx[i]<='f') offset=offset*16+xxx[i]-'a'+10;
            else { valid=0; break; }
        }
        if (valid==0) break;
        sprintf(ff, "/proc/%d/root%s", pid, fname); 
        STORE_T* s = load_symbol_from_file(ff);
        if (s) {
            for (auto x=s->begin(); x!=s->end(); x++) {
                auto v = (*x).second;
                if (strstr((*x).first.c_str(), func)) {
                    rr.func_name = (*x).first;
                    rr.file_name = string(ff);
                    rr.vaddr = v.addr-v.baddr+start;
                    rr.raddr = v.addr-v.baddr+v.boffset;
                    cans.push_back(rr);
                }
            }
            delete s;
        }
    }
    fclose(fp);

    if (cans.size()==0) { printf("no func found\n"); return 0; }
    k=0; if (cans.size()>1) {
        printf("%d candidates found, please make a selection: [0, %d]\n", cans.size(), cans.size()-1);
        for (i=0; i<cans.size(); i++) {
            printf("[%d]: %s<%s>\n", i, cans[i].func_name.c_str(), cans[i].file_name.c_str());
        }
        scanf("%d", &k);
        if (k<0||k>=cans.size()) { printf("invalid selection, abort\n"); return 1; }
    }
    printf("uprobing %s[%s] (vaddr 0x%llx, relative addr 0x%llx)\n", cans[k].func_name.c_str(), cans[k].file_name.c_str(), cans[k].vaddr, cans[k].raddr);
    fp = fopen("/sys/bus/event_source/devices/uprobe/type", "r");
    if (fp == NULL) { printf("fail to find type for kprobe\n"); return 1; }
    fscanf(fp, "%d", &type);
    fclose(fp);
    if (type <= 0) { printf("unexpected type %d\n", type); return 1; }
    // start perf event
    psize = sysconf(_SC_PAGE_SIZE); // getpagesize();
    int cpu_num = sysconf(_SC_NPROCESSORS_ONLN), fd;
	struct perf_event_attr attr;
    void *addr;
    memset(&attr, 0, sizeof(attr));
    attr.type = type;
    attr.size = sizeof(attr);
    attr.config = 0;
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.sample_type = PERF_SAMPLE_TID|PERF_SAMPLE_REGS_USER; //PERF_SAMPLE_REGS_INTR;
    attr.uprobe_path = (__u64)cans[k].file_name.c_str();
    attr.probe_offset = cans[k].raddr;
    attr.sample_regs_user = (1<<PERF_REG_X86_AX)|(1<<PERF_REG_X86_DI)|(1<<PERF_REG_X86_SI)|(1<<PERF_REG_X86_DX)|(1<<PERF_REG_X86_R10)|
        (1<<PERF_REG_X86_R8)|(1<<PERF_REG_X86_R9);
    for (i=0, k=0; i<cpu_num&&i<MAXCPU; i++) {
        printf("attaching cpu %d\n", i);
        fd = perf_event_open(&attr, pid, i, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd<0) { perror("fail to open perf event for pid"); continue; }
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
        // printf("wake\n");
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
