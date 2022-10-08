# Build

- clone linux kernel source
```
# for us who live in China
git clone https://mirrors.tuna.tsinghua.edu.cn/git/linux.git
```

- copy codes in this directory to `samples/bpf`

- change the Makefile, following is a example for building l3lb.*

```
diff --git a/samples/bpf/Makefile b/samples/bpf/Makefile
index f87ee02073ba..d35832a6a13e 100644
--- a/samples/bpf/Makefile
+++ b/samples/bpf/Makefile
@@ -109,6 +109,7 @@ task_fd_query-objs := bpf_load.o task_fd_query_user.o $(TRACE_HELPERS)
 xdp_sample_pkts-objs := xdp_sample_pkts_user.o $(TRACE_HELPERS)
 ibumad-objs := bpf_load.o ibumad_user.o $(TRACE_HELPERS)
 hbm-objs := bpf_load.o hbm.o $(CGROUP_HELPERS)
+l3lb-objs := l3lb.o
 
 # Tell kbuild to always build the programs
 always-y := $(tprogs-y)
@@ -170,6 +171,9 @@ always-y += ibumad_kern.o
 always-y += hbm_out_kern.o
 always-y += hbm_edt_kern.o
 always-y += xdpsock_kern.o
+always-y := sock_sillycreate_kern.o
+always-y += l3lb_kern.o l3lb
+

```

- Build the binary

```
cd samples/bpf
make

# if the module has a userland admin tool, the tool needs to be build seperatedly, e.g.
gcc -o l3lbadm l3lb_cmd.c
```
