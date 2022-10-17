#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <linux/elf.h>
#include <sys/user.h>
#include <string.h>

#include <set>
#include <vector>
#include <string>
using namespace std;

#define exiterr(err, msg) do{ if(err<0) { perror(msg); exit(1); }} while(0)


char ibuf[1024*8];
typedef struct {
    unsigned long long start, end, offset;
    char mode;
    string name;
} MNode;
char ns[1024*8];
char vmk[128];
vector<MNode>* load_maps(int pid) {
    sprintf(ibuf, "/proc/%d/maps", pid);
    FILE *fp = fopen(ibuf, "r");
    char addrs[64], mode[8], offs[16], dev[16];
    long long inode;
    unsigned long long start, end, offset;
    MNode nn;
    int i, j, k;
    char m, *p;
    if (fp==NULL) return NULL;
    vector<MNode>* ms = new vector<MNode>();
    while(1) {
        p = fgets(ibuf, sizeof(ibuf), fp); if (p==NULL) break; 
        k = sscanf(p, "%s %s %s %s %lld %s", addrs, mode, offs, dev, &inode, ns);
        if (k<5) continue;
        start=end=offset=0;
        i=0; while(addrs[i]&&addrs[i]!='-') {
            if (vmk[addrs[i]]==-1) break;
            start=start*16+vmk[addrs[i]];
            i++;
        } if (i==0||addrs[i]!='-') continue;
        j=i+1; while(addrs[j]) {
            if (vmk[addrs[j]]==-1) break;
            end = end*16+vmk[addrs[j]];
            j++;
        } if (j==i+1||addrs[j]!=0) continue;
        i=0; while(offs[i]) {
            if (vmk[offs[i]]==-1) break;
            offset = offset*16+vmk[offs[i]];
            i++;
        } if (i==0||offs[i]!=0) continue;
        m=0; for (i=0; i<4; i++) if (mode[i]!='-') m|=(1<<i);
        nn.start=start;
        nn.end = end;
        nn.mode=m;
        nn.offset = offset;
        if (k==5) {
            nn.name = string();
        } else if (k==6) {
            // skip [vvar]
            i=0; while(ns[i]) i++;
            while(i>0&&ns[i-1]!='/') i--;
            nn.name = string(ns+i);
        }
        ms->push_back(nn);
    }
    fclose(fp);
    return ms;
}

char buf[1024*1024];
typedef struct {
    int regset;
    size_t size;
    unsigned long offset;
} RegHNode;
typedef struct {
    unsigned long start, end, offset;
    unsigned long noffset, doffset;
    size_t nlen, dsize;
    unsigned int mode;
} MapHNode;

int regset_ids[] = { NT_PRSTATUS, NT_PRFPREG, NT_PRPSINFO, NT_TASKSTRUCT, NT_AUXV, -1 };

int map_copy(FILE* out, FILE* mem, unsigned long long start, unsigned long long size) {
    int r;
    size_t n, rn=0;
    r = fseek(mem, start, SEEK_SET);
    if (r!=0) return r;
    while(size) {
        n = fread(ibuf, 1, sizeof(ibuf), mem); if (n==0) {
            printf("not enough file to read, left %d/%lld\n", n, size);
            break;
        }
        if (n>size) n=size;
        fwrite(ibuf, 1, n, out);
        size-=n;
        rn+=n;
    }
    return rn;
}

int main(int argc, char *argv[]) {
    int pid, err, status, x, i, z, n;
    unsigned long offset, hlen, dlen;
    // struct user_regs_struct regs;
    struct iovec regset;
    struct user userinfo;
    unsigned long *tp, vw, rn;
    if (argc<2) { printf("need pid\n"); return 1; }
    pid = atoi(argv[1]);
    if (pid<=0) { printf("invalid pid %s\n", argv[1]); return 1; }
    err = ptrace(PTRACE_ATTACH, pid, 0, 0);
    exiterr(err, "fail to attach");
    printf("attached with %d\n", pid);
    x = waitpid(-1, &status, __WALL);
    if (x != pid) {
        printf("expect pid %d, got %d\n", pid, x);
        return 1;
    }
    FILE *fp_header=NULL, *fp_binary=NULL, *fp_mem=NULL;
    RegHNode regset_header;
    vector<MNode>* mp = NULL;
    sprintf(ibuf, "/proc/%d/mem", pid);
    fp_mem = fopen(ibuf, "rb"); if (fp_mem==NULL) goto out;
    fp_header = fopen("./spirity.header", "wb"); if (fp_header==NULL) goto out;
    fp_binary = fopen("./spirity.binary", "wb"); if (fp_binary==NULL) goto out;
    // load user
    tp = (unsigned long*)&userinfo;
    for (i=0; i<sizeof(userinfo); i+=8) {
        errno = 0;
        vw = ptrace(PTRACE_PEEKUSER, pid, i, 0);
        if (errno) {
            printf("only read %d userinfo --> %ld\n", i, vw);
            perror("error");
            break;
        }
        *tp=vw; tp++;
    }
    offset=0; hlen=0;
    fwrite(&userinfo, sizeof(userinfo), 1, fp_header);
    hlen += sizeof(userinfo);
    // get register
    regset.iov_base = (void*)buf;
    for (i=0; ; i++) {
        z = regset_ids[i];
        if (z==-1) break;
        regset.iov_len = sizeof(buf);
        x = ptrace(PTRACE_GETREGSET, pid, z, &regset);
        if (x>=0) {
            printf("saving register set %d, length %d\n", z, regset.iov_len);
            regset_header.regset = z;
            regset_header.offset = offset;
            regset_header.size = regset.iov_len;
            n = fwrite(&regset_header, sizeof(regset_header), 1, fp_header);
            fwrite(&regset.iov_base, 1, regset.iov_len, fp_binary);
            offset += regset.iov_len;
            hlen+=sizeof(regset_header);
        }
    }
    regset_header.regset = -1;
    fwrite(&regset_header, sizeof(regset_header), 1, fp_header);
    hlen+=sizeof(regset_header);
    // get maps
    memset(vmk, 0xff, sizeof(vmk));
    for (i='0'; i<='9'; i++) vmk[i]=i-'0';
    for (i='a'; i<='f'; i++) vmk[i]=i-'a'+10;
    for (i='A'; i<='F'; i++) vmk[i]=i-'A'+10;
    mp = load_maps(pid);
    MapHNode mheader;
    if (mp) {
        for (auto m: *mp) {
            mheader.start = m.start;
            mheader.end = m.end;
            mheader.offset = m.offset;
            mheader.mode = m.mode;
            n = m.name.length();
            mheader.nlen = n;
            if (n) {
                strcpy(ns, m.name.c_str());
                mheader.noffset = offset;
                n = (n+16)/8*8;
                fwrite(ns, 1, n, fp_binary);
                offset+=n;
            }
            // read maps if the map is writable
            //if (mheader.mode&(1<<1)) {
                dlen = m.end-m.start;
                mheader.doffset = offset;
                if (n)
                    printf("try copy from memory address 0x%llx, sizeof %lld [%s]\n", m.start, dlen, m.name.c_str());
                else 
                    printf("try copy from memory address 0x%llx, sizeof %lld []\n", m.start, dlen);
                rn = map_copy(fp_binary, fp_mem, m.start, dlen);
                mheader.dsize = rn;
                offset+=rn;
            // }
            fwrite(&mheader, sizeof(mheader), 1, fp_header);
            hlen += sizeof(mheader);
        }
        delete mp;
    }
    // mark the end
    mheader.start = -1;
    fwrite(&mheader, sizeof(mheader), 1, fp_header);
    hlen += sizeof(mheader);
    // ptrace(PTRACE_CONT, pid, 0, 0);
    ptrace(PTRACE_KILL, pid, 0, 0);

out:
    if (fp_header) fclose(fp_header);
    if (fp_binary) fclose(fp_binary);
    if (fp_mem) fclose(fp_mem);
    return 0;
}
