# userlandmylove

userland latency archeograph that interrogates the vDSO in memory to resolve `__vdso_clock_gettime`/`__kernel_clock_gettime`/`__vdso_gettimeofday` and bypassing `dlsym` and glibc indirections entirely. it emits syscall micro latency telemetry and contrasts raw `syscall(2)` paths against libc trampolines, and surfaces ABI, kernel and microarchitectural artifacts as a reproducible fingerprint

optional RDTSC timing is calibrated OTF against vDSO `CLOCK_MONOTONIC` whhereas CPU affinity pinning suppresses scheduler jitter, JSON output enables downstream ingestion and heuristics flag `LD_PRELOAD` / `LD_AUDIT` interference and seccomp policy by probing invalid syscall numbers and inspecting errno vectors

## Requirements

a brain

# Build

```bash
make
```
