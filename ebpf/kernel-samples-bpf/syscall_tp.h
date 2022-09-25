#ifndef __SYSCALL_TP_H_
#define __SYSCALL_TP_H_

struct open_event{
    int pid;
    char fname[(1<<6)-sizeof(int)];
};

#endif /* __SYSCALL_TP_H_ */
