# Performance

Wake's overhead budget (SPEC.md §3) is **< 1% CPU and < 128 MiB RSS at 10k
events/s sustained** on the reference box.

Reproduce with `make perf`, which runs the in-repo load generator against a
live daemon and appends its measurement below. The script exits non-zero when a
budget is exceeded, so it can gate a release.

## Reference box

Framework Desktop, AMD Ryzen AI Max+ 395 (16 cores), 125 GiB RAM,
Fedora 44, kernel 7.1.5-201.fc44.x86_64.

## What the load generator measures

It issues `openat` on a path that does not exist, at a controlled rate. ENOENT
is deliberate: failing opens are both the cheapest events for the kernel to
produce and the most interesting ones diagnostically, so the measurement prices
Wake's pipeline rather than the kernel's own work.

Drop accounting is checked alongside the numbers. An overhead figure achieved
by quietly losing events would be worthless, so `make perf` prints the drop
report from `wake status` next to the measurement.

## Note on the first run below

The first measurement failed its RSS budget at 135.7 MiB. The cause was Go's
default heap growth target: with `GOGC=100` the runtime grows the heap to twice
the live set, so a 64 MiB ring settled at roughly twice that in RSS. Wake now
sets a soft `GOMEMLIMIT` derived from the configured ring budget
(`internal/daemon/memory.go`), which brought RSS to 27.3 MiB at a cost of 0.07
percentage points of CPU. An operator's explicit `GOMEMLIMIT` still wins.

This is recorded rather than quietly amended: the measurement harness catching
a real budget failure is the entire reason for having one.

## Measurements
