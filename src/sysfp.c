#include "../include/vdso.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

typedef struct bench_result {
  const char *name;
  double avg_ns;
  double p50_ns;
  double p99_ns;
} bench_result;

static int cmp_u64(const void *a, const void *b) {
  uint64_t ua = *(const uint64_t *)a;
  uint64_t ub = *(const uint64_t *)b;
  return (ua > ub) - (ua < ub);
}

static inline uint64_t rdtsc_read(void) {
#if defined(__x86_64__) || defined(__i386__)
  unsigned int aux;
  return __builtin_ia32_rdtscp(&aux);
#else
  return 0;
#endif
}

static uint64_t calibrate_tsc_to_ns(const vdso_info *vi) {
  const uint64_t target_ns = 50ULL * 1000ULL * 1000ULL;
  uint64_t t0 = now_ns_monotonic(vi);
  uint64_t c0 = rdtsc_read();
  while (now_ns_monotonic(vi) - t0 < target_ns) {
  }
  uint64_t t1 = now_ns_monotonic(vi);
  uint64_t c1 = rdtsc_read();
  uint64_t dt_ns = t1 - t0;
  uint64_t dc = (c1 > c0) ? (c1 - c0) : 1;
  if (dt_ns == 0) dt_ns = 1;
  return (dc * 1000000ULL) / dt_ns;
}

static bench_result run_bench(const vdso_info *vi, const bench_options *opts,
                              const char *name, size_t iters,
                              int (*fn)(void *), void *arg,
                              uint64_t **out_sorted, size_t *out_len) {
  uint64_t *samples = (uint64_t *)malloc(sizeof(uint64_t) * iters);
  if (!samples) {
    bench_result br = {name, 0, 0, 0};
    return br;
  }
  uint64_t cycles_per_ns_scaled = 0;
  if (opts && opts->use_rdtsc) {
    cycles_per_ns_scaled = calibrate_tsc_to_ns(vi);
    if (opts->verbose) {
      fprintf(stderr, "[rdtsc] cycles_per_ns_scaled=%" PRIu64 "\n", cycles_per_ns_scaled);
    }
  }
  for (size_t i = 0; i < 1000 && i < iters; ++i) {
    (void)fn(arg);
  }
  for (size_t i = 0; i < iters; ++i) {
    if (opts && opts->use_rdtsc && cycles_per_ns_scaled) {
      uint64_t c0 = rdtsc_read();
      (void)fn(arg);
      uint64_t c1 = rdtsc_read();
      uint64_t dc = c1 - c0;
      uint64_t ns = (dc * 1000000ULL) / cycles_per_ns_scaled;
      samples[i] = ns;
    } else {
      uint64_t t0 = now_ns_monotonic(vi);
      (void)fn(arg);
      uint64_t t1 = now_ns_monotonic(vi);
      samples[i] = t1 - t0;
    }
  }

  qsort(samples, iters, sizeof(uint64_t), cmp_u64);
  double sum = 0.0;
  for (size_t i = 0; i < iters; ++i) sum += (double)samples[i];
  bench_result br;
  br.name = name;
  br.avg_ns = sum / (double)iters;
  br.p50_ns = (double)samples[(size_t)(iters * 0.50)];
  br.p99_ns = (double)samples[(size_t)(iters * 0.99)];
  if (out_sorted) {
    *out_sorted = samples;
    if (out_len) *out_len = iters;
  } else {
    free(samples);
  }
  return br;
}

static int op_getpid_sys(void *arg) {
  (void)arg;
  return (int)syscall(SYS_getpid);
}

static int op_getpid_libc(void *arg) {
  (void)arg;
  return (int)getpid();
}

static int op_nanosleep_short_sys(void *arg) {
  (void)arg;
  struct timespec ts = {0, 1};
  return (int)syscall(SYS_nanosleep, &ts, NULL);
}

static int op_nanosleep_short_libc(void *arg) {
  (void)arg;
  struct timespec ts = {0, 1};
  return nanosleep(&ts, NULL);
}

typedef struct rw_ctx {
  int fd;
  void *buf;
  size_t len;
} rw_ctx;

static int op_read_sys(void *arg) {
  rw_ctx *ctx = (rw_ctx *)arg;
  return (int)syscall(SYS_read, ctx->fd, ctx->buf, ctx->len);
}

static int op_read_libc(void *arg) {
  rw_ctx *ctx = (rw_ctx *)arg;
  return (int)read(ctx->fd, ctx->buf, ctx->len);
}

static int op_write_sys(void *arg) {
  rw_ctx *ctx = (rw_ctx *)arg;
  return (int)syscall(SYS_write, ctx->fd, ctx->buf, ctx->len);
}

static int op_write_libc(void *arg) {
  rw_ctx *ctx = (rw_ctx *)arg;
  return (int)write(ctx->fd, ctx->buf, ctx->len);
}

static void print_bench(const bench_result *r) {
  printf("%-18s avg: %8.2f ns   p50: %8.2f ns   p99: %8.2f ns\n",
         r->name, r->avg_ns, r->p50_ns, r->p99_ns);
}

static void print_histogram_text(const char *name, const uint64_t *sorted, size_t n, int buckets) {
  if (!sorted || n == 0 || buckets <= 0) return;
  uint64_t min = sorted[0];
  uint64_t max = sorted[n - 1];
  if (max < min) max = min;
  uint64_t range = (max - min) + 1;
  uint64_t step = range / (uint64_t)buckets;
  if (step == 0) step = 1;
  int *counts = (int *)calloc((size_t)buckets, sizeof(int));
  if (!counts) return;
  for (size_t i = 0; i < n; ++i) {
    uint64_t v = sorted[i];
    uint64_t idx = (v - min) / step;
    if (idx >= (uint64_t)buckets) idx = (uint64_t)buckets - 1;
    counts[idx]++;
  }
  printf("%s histogram: min=%" PRIu64 " max=%" PRIu64 " buckets=%d\n", name, min, max, buckets);
  for (int b = 0; b < buckets; ++b) {
    uint64_t lo = min + (uint64_t)b * step;
    uint64_t hi = lo + step - 1;
    if (b == buckets - 1) hi = max;
    printf("[%" PRIu64 ", %" PRIu64 "] %d\n", lo, hi, counts[b]);
  }
  free(counts);
}

static void print_result_json(const bench_result *r, const uint64_t *sorted, size_t n, int buckets) {
  if (!r) return;
  if (buckets <= 0 || !sorted || n == 0) {
    printf("{\"name\":\"%s\",\"avg_ns\":%.2f,\"p50_ns\":%.2f,\"p99_ns\":%.2f}\n",
           r->name, r->avg_ns, r->p50_ns, r->p99_ns);
    return;
  }
  uint64_t min = sorted[0];
  uint64_t max = sorted[n - 1];
  uint64_t range = (max - min) + 1;
  uint64_t step = range / (uint64_t)buckets;
  if (step == 0) step = 1;
  int *counts = (int *)calloc((size_t)buckets, sizeof(int));
  if (!counts) {
    printf("{\"name\":\"%s\",\"avg_ns\":%.2f,\"p50_ns\":%.2f,\"p99_ns\":%.2f}\n",
           r->name, r->avg_ns, r->p50_ns, r->p99_ns);
    return;
  }
  for (size_t i = 0; i < n; ++i) {
    uint64_t v = sorted[i];
    uint64_t idx = (v - min) / step;
    if (idx >= (uint64_t)buckets) idx = (uint64_t)buckets - 1;
    counts[idx]++;
  }
  printf("{\"name\":\"%s\",\"avg_ns\":%.2f,\"p50_ns\":%.2f,\"p99_ns\":%.2f,\"hist\":{\"min\":%" PRIu64 ",\"max\":%" PRIu64 ",\"buckets\":%d,\"counts\":[",
         r->name, r->avg_ns, r->p50_ns, r->p99_ns, min, max, buckets);
  for (int b = 0; b < buckets; ++b) {
    printf("%s%d", (b ? "," : ""), counts[b]);
  }
  printf("]}}\n");
  free(counts);
}

static void maybe_warn_env(void) {
  const char *audit = getenv("LD_AUDIT");
  const char *preload = getenv("LD_PRELOAD");
  if (audit && *audit) fprintf(stderr, "[warn] LD_AUDIT set: %s\n", audit);
  if (preload && *preload) fprintf(stderr, "[warn] LD_PRELOAD set: %s\n", preload);
}

static int pin_to_cpu(int cpu) {
#ifdef __linux__
  if (cpu < 0) return 0;
  cpu_set_t set;
  CPU_ZERO(&set);
  CPU_SET((unsigned)cpu, &set);
  return sched_setaffinity(0, sizeof(set), &set);
#else
  (void)cpu; return 0;
#endif
}

static int probe_seccomp(void) {
  errno = 0;
  long r = syscall(999999);
  if (r != -1) return 0;
  if (errno == ENOSYS) return 0;
  if (errno == EPERM || errno == EACCES || errno == EINVAL) return 1;
  return 0;
}

int run_syscall_fingerprint(const vdso_info *vi, const bench_options *opts) {
  const size_t iters = opts ? opts->iterations : 100000;
  printf("Benchmarking %zu iterations (timed via %s)\n",
         iters,
         (opts && opts->use_rdtsc) ? "RDTSC" : ((vi && vi->clock_gettime_fn) ? "vDSO clock_gettime" : "syscall clock_gettime"));

  maybe_warn_env();
  if (opts && opts->pin_cpu >= 0) {
    if (pin_to_cpu(opts->pin_cpu) != 0) perror("sched_setaffinity");
  }
  if (opts && opts->seccomp_probe) {
    int s = probe_seccomp();
    if (s) fprintf(stderr, "[warn] possible seccomp restrictions detected\n");
  }

  bench_result r;

  uint64_t *samples = NULL; size_t slen = 0;
  r = run_bench(vi, opts, "getpid()[sys]", iters, op_getpid_sys, NULL, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
  if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
  if (samples) { free(samples); samples = NULL; slen = 0; }
  if (opts && opts->compare_libc) {
    r = run_bench(vi, opts, "getpid()[libc]", iters, op_getpid_libc, NULL, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
    if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
    if (samples) { free(samples); samples = NULL; slen = 0; }
  }

  r = run_bench(vi, opts, "nanosleep(1ns)[sys]", iters, op_nanosleep_short_sys, NULL, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
  if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
  if (samples) { free(samples); samples = NULL; slen = 0; }
  if (opts && opts->compare_libc) {
    r = run_bench(vi, opts, "nanosleep(1ns)[libc]", iters, op_nanosleep_short_libc, NULL, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
    if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
    if (samples) { free(samples); samples = NULL; slen = 0; }
  }

  char *buf = (char *)aligned_alloc(64, 4096);
  if (!buf) {
    perror("alloc");
    return -1;
  }
  memset(buf, 0, 4096);

  int fdz = open("/dev/zero", O_RDONLY | O_CLOEXEC);
  int fdn = open("/dev/null", O_WRONLY | O_CLOEXEC);
  if (fdz < 0 || fdn < 0) {
    perror("open /dev/{zero,null}");
    if (fdz >= 0) close(fdz);
    if (fdn >= 0) close(fdn);
    free(buf);
    return -1;
  }

  rw_ctx rctx = {.fd = fdz, .buf = buf, .len = 64};
  rw_ctx wctx = {.fd = fdn, .buf = buf, .len = 64};

  r = run_bench(vi, opts, "read(64B)[sys]", iters, op_read_sys, &rctx, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
  if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
  if (samples) { free(samples); samples = NULL; slen = 0; }
  if (opts && opts->compare_libc) {
    r = run_bench(vi, opts, "read(64B)[libc]", iters, op_read_libc, &rctx, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
    if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
    if (samples) { free(samples); samples = NULL; slen = 0; }
  }
  r = run_bench(vi, opts, "write(64B)[sys]", iters, op_write_sys, &wctx, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
  if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
  if (samples) { free(samples); samples = NULL; slen = 0; }
  if (opts && opts->compare_libc) {
    r = run_bench(vi, opts, "write(64B)[libc]", iters, op_write_libc, &wctx, (opts && (opts->hist_buckets>0 || opts->json)) ? &samples : NULL, &slen);
    if (opts && opts->json) print_result_json(&r, samples, slen, opts->hist_buckets); else { print_bench(&r); if (opts && opts->hist_buckets>0) print_histogram_text(r.name, samples, slen, opts->hist_buckets); }
    if (samples) { free(samples); samples = NULL; slen = 0; }
  }

  close(fdz);
  close(fdn);
  free(buf);

  return 0;
}


