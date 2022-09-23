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

void thirdparty_func(int fd) {
    // seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL);
    int i, v, x=0; for (i=0; i<8; i++) {
        read(fd, &v, 4);
        x^=v;
    }
    printf("running some library code ==> 0x%x\n", x);
}

//-------------------------------------------------------------
// ld [4]                  /* offsetof(struct seccomp_data, arch) */
// jne #0xc000003e, bad    /* AUDIT_ARCH_X86_64 */
// ld [0]                  /* offsetof(struct seccomp_data, nr) */
// jeq #15, good           /* __NR_rt_sigreturn */
// jeq #231, good          /* __NR_exit_group */
// jeq #60, good           /* __NR_exit */
// jeq #0, good            /* __NR_read */
// jeq #1, good            /* __NR_write */
// jeq #5, good            /* __NR_fstat */
// jeq #9, good            /* __NR_mmap */
// jeq #14, good           /* __NR_rt_sigprocmask */
// jeq #13, good           /* __NR_rt_sigaction */
// jeq #35, good           /* __NR_nanosleep */
// bad: ret #0             /* SECCOMP_RET_KILL_THREAD */
// good: ret #0x7fff0000   /* SECCOMP_RET_ALLOW */
//-------------------------------------------------------------

static struct sock_filter filter[] = {
    { 0x20,  0,  0, 0x00000004 },
    { 0x15,  0, 11, 0xc000003e },
    { 0x20,  0,  0, 0000000000 },
    { 0x15, 10,  0, 0x0000000f },
    { 0x15,  9,  0, 0x000000e7 },
    { 0x15,  8,  0, 0x0000003c },
    { 0x15,  7,  0, 0000000000 },
    { 0x15,  6,  0, 0x00000001 },
    { 0x15,  5,  0, 0x00000005 },
    { 0x15,  4,  0, 0x00000009 },
    { 0x15,  3,  0, 0x0000000e },
    { 0x15,  2,  0, 0x0000000d },
    { 0x15,  1,  0, 0x00000023 },
    { 0x06,  0,  0, 0000000000 },
    { 0x06,  0,  0, 0x7fff0000 },
};

int main(int argc, char *argv[]) {
    int status;
    pid_t pid = fork();
    int fd = open("/dev/urandom", O_CLOEXEC|O_RDONLY);
    if (pid==0) {
        printf("start thirdpart library\n");
        struct sock_fprog prog = {
            .len = (unsigned short) (sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
        };
        if (seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog)) {
            perror("seccomp");
            return 1;
        }
        thirdparty_func(fd);
    } else {
        wait(&status);
        if (WIFEXITED(status)) printf("secure computing done, exit status %d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status)||WIFSTOPPED(status)) {
            printf("secure computing killed/stopped by signal %d\n", WTERMSIG(status));
        } else {
            printf("secure computing aborted.");
        }
        close(fd);
    }
    return 0;
}

