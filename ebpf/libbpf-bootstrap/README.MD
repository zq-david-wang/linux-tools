# Build

- clone libbpf-bootstrap
```
git clone https://github.com/libbpf/libbpf-bootstrap.git
```
- copy codes in this directory to `libbpf-bootstrap/examples/c/`

- change the Makefile 

```
diff --git a/examples/c/Makefile b/examples/c/Makefile
index e77fca7..2d8dc4b 100644
--- a/examples/c/Makefile
+++ b/examples/c/Makefile
@@ -19,7 +19,7 @@ INCLUDES := -I$(OUTPUT) -I../../libbpf/include/uapi -I$(dir $(VMLINUX))
 CFLAGS := -g -Wall
 ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)
 
-APPS = minimal minimal_legacy bootstrap uprobe kprobe fentry usdt
+APPS = minimal minimal_legacy bootstrap uprobe kprobe fentry usdt openat conn commargv
 
 CARGO ?= $(shell which cargo)
 ifeq ($(strip $(CARGO)),)

```

- Build the binary with g++

```
CC=g++ make openat conn commargv
```
