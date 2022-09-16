#ifndef __SYSCALL_TP_H_
#define __SYSCALL_TP_H_

#define MAXPN 32
struct comm_event{
    int pid, n;
    char argv[MAXPN][32];
};

#endif /* __SYSCALL_TP_H_ */
