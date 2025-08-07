#pragma once

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

typedef int (*vdso_clock_gettime_t)(clockid_t, struct timespec *);
typedef int (*vdso_gettimeofday_t)(struct timeval *, struct timezone *);

typedef struct vdso_info {
  const void *base_address;
  vdso_clock_gettime_t clock_gettime_fn;
  vdso_gettimeofday_t gettimeofday_fn;
  const char *resolved_symbol_name;
} vdso_info;

int vdso_init(vdso_info *info);

uint64_t now_ns_monotonic(const vdso_info *info);

uint64_t now_ns_realtime(const vdso_info *info);

int vdso_clock_gettime(const vdso_info *info, clockid_t clk, struct timespec *ts);
int vdso_gettimeofday(const vdso_info *info, struct timeval *tv, struct timezone *tz);

typedef struct bench_options {
  size_t iterations;
  int use_rdtsc;
  int pin_cpu;
  int verbose;
  int json;
  int hist_buckets;
  int compare_libc;
  int seccomp_probe;
} bench_options;

int run_syscall_fingerprint(const vdso_info *vi, const bench_options *opts);


