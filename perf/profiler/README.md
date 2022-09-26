# A simple profiler
Fit for lightwight usage, minimum dependency

## Build
```
g++ -o profiler profiler.cpp
```
The code needs c++11 features, if an old g++ compiler is used, `-std=c++11` is needed.
You can also use static c/c++ libs via `-static-libstdc++ -static-libgcc`, or even further to build a static executable `-static`


## How it works
Profiler open  perf-event and collect sampled (pid,callchain) pair, whether userspace call-chain is collected depends on kernel version, a new kernel which can unwind user space stack is recommended, (I only tested the profiler on limited number of kernel version, and they all can unwind user stack, the lowest version of kernel I have tested is 3.10.0 from centos/redhat distributions.)
For each (pid, callchain) pair, if this pid has not been symbol-collected, profiler would  parse elf information based on `/proc/[pid]/maps` and `/proc/[pid]/map_files/*`; (If the program has its symbol stripped, e.g. via `ld -s`, user space call chain will be dropped.) Symbols are stored in an ordered structure, C++ map,  after symbols collected, each callchain address is binary searched for its  function name, and then full chain is inserted into a tree.


## Run
The profiler would open perf event with the cgroup which controls the specified pid
```
./profiler <pid>
```
To profile kernel call chains, run with a nagative pid value
```
./profiler -<pid>
```

To create a perf-event cgroup

cgroup v1
```
mkdir /sys/fs/cgroup/perf_event/<somename>
echo $$ > /sys/fs/cgroup/perf_event/<somename>/cgroup.procs
# run the target progrom
# run profiler with any pid within the cgroup
```
For cgroup v2, just use /sys/fs/cgroup/<somename>


## Example
When profiler terminated, a report is generated, following is an example showing the performance impact from seccomp when running a high-IO program within a docker container.
![example](./example1.png "report")

Profiling kernel only, following is what firefox's profiling snap compared with chromium's
![example](./example2.png "report")

