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

#include <set>
using namespace std;

#define exiterr(err, msg) do{ if(err<0) { perror(msg); exit(1); }} while(0)


// TODO: should load vip<->rips maps somewhere
unsigned int vip4 = 0x28282828;
unsigned int rip4s[] = {
    0x50112ac,
    0x40112ac,
    0x30112ac,
};

int main(int argc, char *argv[]) {
    int pid, err, status, x;
    unsigned long cpid;
    struct user_regs_struct regs;
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
    // set opts
    err = ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACECLONE|PTRACE_O_TRACEFORK|PTRACE_O_TRACEVFORK|PTRACE_O_TRACESYSGOOD);
    exiterr(err, "fail to set trace options");
    // resume
    err = ptrace(PTRACE_SYSCALL, pid, 0, 0);
    exiterr(err, "fail to resume tracee");
    // loop
    while(1) {
        x = waitpid(-1, &status, __WALL);
        exiterr(x, "fail to wait for tracee event");
        if (WSTOPSIG(status)==(SIGTRAP|0x80)) {
            // syscalls
            err = ptrace(PTRACE_GETREGS, x, 0, &regs);
            if (err<0) {
                perror("fail to copy process registers");
                continue;
            }
            // printf("syscall(%d) %lld(%llx, %llx, %llx)\n", x, regs.orig_rax, regs.rdi, regs.rsi, regs.rdx);
            switch(regs.orig_rax) {
                case SYS_connect:
                    // on x86, rax == -ENOSYS in  syscall-enter-stop
                    if (regs.rax == -ENOSYS) {
                        // change 
                        struct sockaddr_in *p;
                        unsigned long w = ptrace(PTRACE_PEEKDATA, x, regs.rsi, 0);
                        // 64bit enough for ipv4
                        p = (struct sockaddr_in*)&w;
                        if (p->sin_family == AF_INET) {
                            // printf("ipv4 connect to %x\n", p->sin_addr.s_addr);
                            if (p->sin_addr.s_addr == vip4) {
                                p->sin_addr.s_addr = rip4s[rand()%(sizeof(rip4s)/sizeof(rip4s[0]))];
                                // write back
                                ptrace(PTRACE_POKEDATA, x, regs.rsi, w);
                            }
                        }
                    }
                    ptrace(PTRACE_SYSCALL, x, 0, 0);
                    break;
                default:
                    err = ptrace(PTRACE_SYSCALL, x, 0, 0);
                    // exiterr(err, "fail to resume tracee after a syscall event");
            }
        } else if (WIFSTOPPED(status)) {
            // mostly signal
            if (WSTOPSIG(status) != SIGSTOP&&WSTOPSIG(status) != SIGTRAP) ptrace(PTRACE_SYSCALL, x, 0, WSTOPSIG(status));
            else ptrace(PTRACE_SYSCALL, x, 0, 0);
        } else {
            // others
            ptrace(PTRACE_SYSCALL, x, 0, 0);
        }
    }
    // no need to deattach if exit?
    return 0;
}
