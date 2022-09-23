#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <errno.h>
#include <linux/unistd.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <fcntl.h>



static inline int seccomp(unsigned int operation, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, operation, flags, args);
}

// black list filter
// bpf_asm -c ...
// ========================================
// ld [4]                  /* offsetof(struct seccomp_data, arch) */
// jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
// ld [0]                  /* offsetof(struct seccomp_data, nr) */
// jeq #200, bad           /* __NR_bind */
// jeq #201, bad           /* __NR_listen */
// jeq #202, bad           /* __NR_accept */
// good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
// bad: ret #0x80000000    /* SECCOMP_RET_KILL_PROCESS */
// ========================================

static struct sock_filter filter[] = {
{ 0x20,  0,  0, 0x00000004 },
{ 0x15,  0,  5, 0xc000003e },
{ 0x20,  0,  0, 0000000000 },
{ 0x15,  3,  0, 0x000000c8 },
{ 0x15,  2,  0, 0x000000c9 },
{ 0x15,  1,  0, 0x000000ca },
{ 0x06,  0,  0, 0x7fff0000 },
{ 0x06,  0,  0, 0x80000000 },
};

int main(int argc, char *argv[]) {
    int status;
    if (argc<2) { printf("usage: %s <cmd> <args...?>\n", argv[0]); return 1; }
    pid_t pid = fork();
    if (pid==0) {
        printf("start forking thirdparty binary...\n");
        struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
        };
        if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)) {
            perror("seccomp");
            return 1;
        }
        execv(argv[1], &argv[1]);
    } else {
        wait(&status);
        if (WIFEXITED(status)) printf("secure computing done, exit status %d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status)||WIFSTOPPED(status)) {
            printf("secure computing killed/stopped by signal %d\n", WTERMSIG(status));
        } else {
            printf("secure computing aborted.");
        }
    }
    return 0;
}

