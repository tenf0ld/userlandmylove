#include "../include/vdso.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void usage(const char *prog) {
  printf("Usage: %s [--iters N] [--rdtsc] [--pin CPU] [--verbose] [--json] [--hist N] [--compare-libc] [--seccomp-probe]\n", prog);
}

int run_syscall_fingerprint(const vdso_info *vi, const bench_options *opts);

static void print_vdso_info(const vdso_info *vi, int init_rc) {
  if (init_rc == 0) {
    printf("vDSO base: %p\n", vi->base_address);
    if (vi->clock_gettime_fn)
      printf("Resolved: %s\n", vi->resolved_symbol_name);
    else if (vi->gettimeofday_fn)
      printf("Resolved: __vdso_gettimeofday\n");
    else
      printf("Resolved: <none> (falling back to syscalls)\n");
  } else {
    printf("vDSO resolution failed: %d (falling back to syscalls)\n", init_rc);
  }
}

int main(int argc, char **argv) {
  bench_options opts = {
      .iterations = 100000,
      .use_rdtsc = 0,
      .pin_cpu = -1,
      .verbose = 0,
      .json = 0,
      .hist_buckets = 0,
      .compare_libc = 0,
      .seccomp_probe = 0,
  };
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--iters") == 0 && i + 1 < argc) {
      opts.iterations = (size_t)strtoull(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--rdtsc") == 0) {
      opts.use_rdtsc = 1;
    } else if (strcmp(argv[i], "--pin") == 0 && i + 1 < argc) {
      opts.pin_cpu = (int)strtol(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--verbose") == 0) {
      opts.verbose = 1;
    } else if (strcmp(argv[i], "--json") == 0) {
      opts.json = 1;
    } else if (strcmp(argv[i], "--hist") == 0 && i + 1 < argc) {
      opts.hist_buckets = (int)strtol(argv[++i], NULL, 10);
      if (opts.hist_buckets < 0) opts.hist_buckets = 0;
    } else if (strcmp(argv[i], "--compare-libc") == 0) {
      opts.compare_libc = 1;
    } else if (strcmp(argv[i], "--seccomp-probe") == 0) {
      opts.seccomp_probe = 1;
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Unknown arg: %s\n", argv[i]);
      usage(argv[0]);
      return 1;
    }
  }

  vdso_info vi;
  int rc = vdso_init(&vi);
  print_vdso_info(&vi, rc);

  run_syscall_fingerprint(&vi, &opts);

  return 0;
}


