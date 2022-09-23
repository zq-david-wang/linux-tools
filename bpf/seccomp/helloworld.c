#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>


char buf[1024*8];
int main(int argc, char *argv[]) {
    int fd = fork();
    int x, i, status;
    if (fd==0) {
        printf("This is the only io I can access\n");
        int fd = open("/dev/urandom", O_CLOEXEC|O_RDONLY);
        read(fd, buf, 4096+1); //sizeof(buf));
        for (x=0, i=0; i<sizeof(buf); i++) x^=buf[i];
        printf("Done reading.....0x%x\n", x);
    } else {
        wait(&status);
        if (WIFEXITED(status)) printf("third part done, exit status %d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status)||WIFSTOPPED(status)) {
            printf("third part killed/stopped by signal %d\n", WTERMSIG(status));
        } else {
            printf("third part aborted.");
        }
    }
    return 0;
}
