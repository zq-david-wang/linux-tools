#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>


int main(int argc, char *argv[]) {
    int sk, err, opt;
    int port;
    struct in_addr addr;
    struct sockaddr_in saddr;
    struct linger linger_opt;
    struct pollfd polls[1];
    if (argc!=3) {
        printf("usage %s <ip> <port>\n", argv[0]);
        return 1;
    }
    port = atoi(argv[2]); if (port<=0) {
        printf("invalid port %s\n", argv[2]);
        return 1;
    }
    if (inet_aton(argv[1], &addr) == 0) {
        printf("invalie ip addr %s\n", argv[1]);
        return 1;
    }

    sk = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    err = fcntl(sk, F_SETFL, O_RDONLY|O_NONBLOCK);
    if (err<0) { perror("fail to fcntl"); return 1; }
    opt=1; 
    err = setsockopt(sk, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
    if (err<0) { perror("fail to set socke opt nodelay to 1"); return 1; }
    opt=0; 
    err = setsockopt(sk, SOL_TCP, TCP_QUICKACK, &opt, sizeof(opt));
    if (err<0) { perror("fail to set socke opt quickact to 0"); return 1; }
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr = addr;
    connect(sk, &saddr, sizeof(saddr)); // non blocking, would reaturn -1
    polls[0].fd=sk;
    polls[0].events = POLLIN|POLLOUT|POLLRDHUP;
    err = poll(polls, 1, 1000);
    linger_opt.l_onoff=1;
    linger_opt.l_linger=0;
    setsockopt(sk, SOL_SOCKET, SO_LINGER, &linger_opt, sizeof(linger_opt));
    close(sk);
    if (err>0&&polls[0].revents==POLLOUT) printf("remote port active\n");
    else { printf("remote port not active\n"); return 1; }
    return 0;
}
