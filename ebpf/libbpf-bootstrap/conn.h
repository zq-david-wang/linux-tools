#ifndef __SYSCALL_TP_CONN_H_
#define __SYSCALL_TP_CONN_H_

struct conn_event{
    int pid;
    char addr[24];
    char _pad[8];
    // struct sockaddr addr;
};

#endif /* __SYSCALL_TP_CONN_H_ */
