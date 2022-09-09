#ifndef __SYSCALL_TP_H_
#define __SYSCALL_TP_H_

struct open_event{
    int pid, _;
    char fname[(1<<7)-sizeof(int)*2];
};

#endif /* __SYSCALL_TP_H_ */
