#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <errno.h>
// #include <linux/unistd.h>
#include <asm/unistd.h>
#include <sys/wait.h>
#include <fcntl.h>



static inline int seccomp(unsigned int operation, unsigned int flags, void *args) {
    return syscall(__NR_seccomp, operation, flags, args);
}

void thirdparty_func(int fd) {
    seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL);
    int i, v, x=0; for (i=0; i<8; i++) {
        read(fd, &v, 4);
        x^=v;
    }
    printf("running some library code ==> 0x%x\n", x);
    syscall(__NR_exit, 0);
}

int main(int argc, char *argv[]) {
    int status;
    pid_t pid = fork();
    int fd = open("/dev/urandom", O_CLOEXEC|O_RDONLY);
    if (pid==0) {
        printf("start thirdpart library\n");
        if (seccomp(SECCOMP_SET_MODE_STRICT, 0, NULL)) {
            perror("seccomp fail");
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
    }
    close(fd);
    return 0;
}

