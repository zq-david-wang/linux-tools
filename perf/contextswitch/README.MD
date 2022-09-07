# Using context-switch perf event to collect interesting stats

## perf_cxt_switch_1
Simply report how many context-switch happened per second.

## perf_cxt_switch_2
Collect information about which cgroup, keyed by hostname, is now having a process directly contending with current cgroup.
When the program is stopped, via `Ctrl+C`, a report would be generated indicating which group has most direct impact.

## perf_cxt_switch_3
Profiling when context-switch happened, answering the question: what I was doing when I was interrupted.
