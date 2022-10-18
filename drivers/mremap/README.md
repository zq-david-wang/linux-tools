# A silly experiment to add kernel interface for changing virtual memory layout for any pid.

> Linux kernel only support changing mmaps for `current` process, for good reason, I think.
> This silly attempt is to add kernel function for mremap any process, thus the `spirit` of one simple memory program could be injected into another program by a `muggle`.

## Kernel change

> The change is only experimental, only necessary parts involving `current` is changed, and a new interface is added for other module to exporse to user space.

## Driver module

> Supply `ioctl` interface to connect user space request with kernel mremap.

## extract

> Collect program's memory layout/content and registers, and save it.

* /proc/[pid]/maps ---- mem layout
* /proc/[pid]/mem ---- mem content
* ptrace PTRACE_PEEKUSER PTRACE_GETREGSET  ---- register collect



## inject

> convert a existing program, inject the `spirit` from other program

* /dev/ptracexx ---- change memlayout
* ptrace PTRACE_POKEDATA  ---- write back memory content
* ptrace PTRACE_POKEUSER PTRACE_SETREGSET ---- restore registry


