#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <errno.h>
#include <linux/elf.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <set>
#include <vector>
#include <string>
using namespace std;

#define exiterr(err, msg) do{ if(err<0) { perror(msg); exit(1); }} while(0)

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
        nn.offset = offset;
        nn.mode=m;
        if (k==5) {
            nn.name = string();
        } else if (k==6) {
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

char mmk[128];

int main(int argc, char *argv[]) {
    int pid, err, status, x, i, z, n, fd=-1;
    unsigned long offset, hlen, dlen;
    unsigned long faddr = 0x200000000000;
    struct iovec regset;
    unsigned long cz, sz, zzz, nstart, nend, _start, _end; 
    int ddd, j, nj;
    long rc;
    unsigned long vw, *tp;
    struct user userinfo;
    FILE *fp_header=NULL, *fp_binary=NULL;
    vector<MNode>* mp = NULL;
    RegHNode regset_header;
    MapHNode mheader;
    vector<MapHNode> omp;
    vector<string> oname;
    vector<RegHNode> regsets;
    IoctlDataT d;
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
    fp_header = fopen("./spirity.header", "rb"); if (fp_header==NULL) goto out;
    fp_binary = fopen("./spirity.binary", "rb"); if (fp_binary==NULL) goto out;
    fd = open("/dev/ptracexx", O_NONBLOCK);
    if (fd<0) { perror("fail to open ptracexx\n"); goto out; }
    // read user info
    if (fread(&userinfo, sizeof(userinfo), 1, fp_header)!=1) {
        printf("fail to read userinfo\n"); goto out;
    }
    // read reg header
    regset.iov_base = (void*)buf;
    while(1) {
        n = fread(&regset_header, sizeof(regset_header), 1, fp_header);
        if (n!=1) goto out;
        if (regset_header.regset == -1) break;
        printf("regset %d: size %ld, data offset 0x%lx\n", regset_header.regset, regset_header.size, regset_header.offset);
        regsets.push_back(regset_header);
        // write back
        // read to buf
        /*
        fseek(fp_binary, regset_header.offset, SEEK_SET);
        n = fread(buf, 1, regset_header.size, fp_binary); if (n!=regset_header.size) {
            printf("fail to load regset data");
            goto out;
        }
        regset.iov_len = regset_header.size;
        x = ptrace(PTRACE_SETREGSET, pid, regset_header.regset, &regset);
        if (x<0) {
            printf("fail to load regset\n");
            goto out;
        }
        */
    }
    // get pid maps
    memset(vmk, 0xff, sizeof(vmk));
    for (i='0'; i<='9'; i++) vmk[i]=i-'0';
    for (i='a'; i<='f'; i++) vmk[i]=i-'a'+10;
    for (i='A'; i<='F'; i++) vmk[i]=i-'A'+10;
    mp = load_maps(pid); if (mp==NULL) goto  out;
    // read mmaps from save
    while(1) {
        n = fread(&mheader, sizeof(mheader), 1, fp_header); if (n!=1) goto out;
        if (mheader.start == -1) break;
        ibuf[0]=0;
        if (mheader.nlen) {
            fseek(fp_binary, mheader.noffset, SEEK_SET);
            fread(ibuf, 1, mheader.nlen, fp_binary);
            ibuf[mheader.nlen]=0;
        }
        printf("[0x%lx,0x%lx) 0x%lx 0x%x  namelen(%d):[%s], noffset(0x%lx), doffset(0x%lx)\n",
                mheader.start, mheader.end, mheader.offset, mheader.mode, mheader.nlen, ibuf,
                mheader.noffset, mheader.doffset);
        omp.push_back(mheader);
        if (ibuf[0]==0) oname.push_back(string());
        else oname.push_back(string(ibuf));
    }
    // align maps
    n = omp.size();
    if (mp->size() != n) {
        printf("size not match, current %d, expect %d\n", mp->size(), omp.size());
        goto out;
    }
    for (i=0; i<n; i++) mmk[i]=0;
    for (i=0; i<n; i++) printf("0x%lx[%s](0x%lx)---\n", (*mp)[i].start, (*mp)[i].name.c_str(), (*mp)[i].offset);
    d.remap.pid = pid;
    for (i=0; i<n; i++) {
        printf("0x%lx[%s](0x%lx) --->\n", omp[i].start, oname[i].c_str(), omp[i].offset);
        for (j=0; j<n; j++) if (mmk[j]==0) {
            if (oname[i]==(*mp)[j].name && omp[i].offset==(*mp)[j].offset) break;
        }
        if (j>=n) { printf("no match found\n"); goto out; }
        printf("found match --->0x%lx[%s](0x%lx)\n", (*mp)[j].start, (*mp)[j].name.c_str(), (*mp)[j].offset);
        mmk[j]=1;
        nstart = omp[i].start;
        nend = omp[i].end;
        if (omp[i].start!=(*mp)[j].start) {
            for (nj=0; nj<n; nj++) if (mmk[nj]==0) {
                _start = (*mp)[nj].start;
                _end = (*mp)[nj].end;
                if (_start>=nend) continue;
                if (_end<=nstart) continue;
                // remap to faddr
                d.remap.old_start = _start;
                d.remap.old_end = _end;
                d.remap.new_start = faddr;
                d.remap.new_end = _end-_start+faddr;
                (*mp)[nj].start = faddr;
                faddr += (_end-_start);
                (*mp)[nj].end = faddr;
                rc = ioctl(fd, PTRACEXX_REMAP, &d);
                if (rc<0) {
                    printf("fail to remap %ld\n", rc);
                    goto out;
                }
            }
            d.remap.old_start = (*mp)[j].start;
            d.remap.old_end = (*mp)[j].end;
            d.remap.new_start = nstart;
            d.remap.new_end = nend;
            rc = ioctl(fd, PTRACEXX_REMAP, &d);
            if (rc<0) {
                printf("fail to remap %ld\n", rc);
                goto out;
            }
        }
        // write memory
        //  if ((omp[i].mode&(1<<1))==0) continue;
        printf("try to copy memory\n");
        fseek(fp_binary, omp[i].doffset, SEEK_SET);
        sz = omp[i].dsize; // nend-nstart;
        while(sz) {
            cz=sz; if (cz>sizeof(buf)) cz=sizeof(buf);
            if(fread(buf, 1, cz, fp_binary)!=cz) { printf("fail to load map memory\n"); goto out; }
            for (zzz=0; zzz<cz; zzz+=8) {
                // copy word by word
                vw = *(unsigned long*)(buf+zzz);
                // printf("write to 0x%lx %x\n", nstart+zzz, ddd);
                x = ptrace(PTRACE_POKEDATA, pid, nstart+zzz, vw);
                if (x<0) { perror("fail to poke user memory"); break; }
            }
            if (zzz<cz) {
                sz-=zzz;
                break;
            }
            sz-=cz;
            nstart+=cz;
        }
        if (sz) printf("....%ld left\n", sz);
    }
    // load user
    tp = (unsigned long*)&userinfo;
    for (i=0; i<sizeof(userinfo); i+=sizeof(unsigned long)) {
        vw = ptrace(PTRACE_POKEUSER, pid, i, *tp);
        if (vw==-1) {
            printf("poke offset %d failed\n", i);
            perror("error:");
            goto out;
        }
        tp++;
    }
    // load reg
    n = regsets.size();
    for (i=0; i<n; i++) {
        regset_header = regsets[i];
        printf("load regset %d\n", regset_header.regset);
        // write back
        // read to buf
        fseek(fp_binary, regset_header.offset, SEEK_SET);
        n = fread(buf, 1, regset_header.size, fp_binary); if (n!=regset_header.size) {
            printf("fail to load regset data");
            goto out;
        }
        regset.iov_len = regset_header.size;
        x = ptrace(PTRACE_SETREGSET, pid, regset_header.regset, &regset);
        if (x<0) {
            printf("fail to load regset\n");
            goto out;
        }
    }
    
out:
    // ptrace(PTRACE_CONT, pid, 0, 0);
    if (fd>0) close(fd);
    if (fp_header) fclose(fp_header);
    if (fp_binary) fclose(fp_binary);
    return 0;
}
