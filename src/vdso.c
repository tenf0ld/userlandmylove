#include "../include/vdso.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifdef __LP64__
typedef Elf64_Ehdr EhdrW;
typedef Elf64_Phdr PhdrW;
typedef Elf64_Dyn DynW;
typedef Elf64_Sym SymW;
#else
typedef Elf32_Ehdr EhdrW;
typedef Elf32_Phdr PhdrW;
typedef Elf32_Dyn DynW;
typedef Elf32_Sym SymW;
#endif

static inline uint64_t timespec_to_ns(const struct timespec *ts) {
  return (uint64_t)ts->tv_sec * 1000000000ull + (uint64_t)ts->tv_nsec;
}

static int clock_gettime_syscall(clockid_t clk, struct timespec *ts) {
  long ret = syscall(SYS_clock_gettime, clk, ts);
  return (int)ret;
}

static int gettimeofday_syscall(struct timeval *tv, struct timezone *tz) {
  long ret = syscall(SYS_gettimeofday, tv, tz);
  return (int)ret;
}

static uint32_t gnu_hash_compute(const char *s) {
  uint32_t h = 5381u;
  for (; *s; ++s) {
    h = (h << 5) + h + (uint8_t)(*s);
  }
  return h;
}

static uint32_t sysv_elf_hash(const unsigned char *name_bytes) {
  uint32_t h = 0, g;
  while (*name_bytes) {
    h = (h << 4) + *name_bytes++;
    g = h & 0xF0000000u;
    if (g) h ^= g >> 24;
    h &= ~g;
  }
  return h;
}

static const SymW *lookup_gnu_hash(const char *name,
                                   const void *unused_base,
                                   const uint32_t *gnu_hash,
                                   const SymW *symtab,
                                   const char *strtab) {
  (void)unused_base;
  if (!gnu_hash || !symtab || !strtab) return NULL;

  const uint32_t nbuckets = gnu_hash[0];
  const uint32_t symoffset = gnu_hash[1];
  const uint32_t bloom_size = gnu_hash[2];
  const uint32_t bloom_shift = gnu_hash[3];

  const uintptr_t *bloom = (const uintptr_t *)(gnu_hash + 4);
  const uint32_t *buckets = (const uint32_t *)(bloom + bloom_size);
  const uint32_t *chain = buckets + nbuckets;

  uint32_t hash = gnu_hash_compute(name);

  const size_t ptr_size_bits = sizeof(uintptr_t) * 8u;
  const uintptr_t word = bloom[(hash / ptr_size_bits) % bloom_size];
  const uintptr_t mask = ((uintptr_t)1 << (hash % ptr_size_bits)) |
                         ((uintptr_t)1 << ((hash >> bloom_shift) % ptr_size_bits));
  if ((word & mask) != mask) return NULL;

  const uint32_t bucket = buckets[hash % nbuckets];
  if (bucket < symoffset) return NULL;

  for (uint32_t i = bucket; ; ++i) {
    const uint32_t h2 = chain[i - symoffset];
    if ((h2 | 1u) == (hash | 1u)) {
      const SymW *sym = &symtab[i];
      const char *symname = strtab + sym->st_name;
      if (strcmp(symname, name) == 0) {
        return sym;
      }
    }
    if (h2 & 1u) break;
  }
  return NULL;
}

static const SymW *lookup_sysv_hash(const char *name,
                                    const uint32_t *sysv_hash,
                                    const SymW *symtab,
                                    const char *strtab) {
  if (!sysv_hash || !symtab || !strtab) return NULL;

  const uint32_t nbucket = sysv_hash[0];
  const uint32_t nchain = sysv_hash[1];
  const uint32_t *buckets = sysv_hash + 2;
  const uint32_t *chains = buckets + nbucket;

  uint32_t h = sysv_elf_hash((const unsigned char *)name);
  for (uint32_t idx = buckets[h % nbucket]; idx != 0; idx = chains[idx]) {
    if (idx >= nchain) break;
    const SymW *sym = &symtab[idx];
    const char *symname = strtab + sym->st_name;
    if (strcmp(symname, name) == 0) return sym;
  }
  return NULL;
}

static int parse_vdso_and_resolve(vdso_info *info) {
  if (!info || !info->base_address) return -EINVAL;

  const uint8_t *base = (const uint8_t *)info->base_address;
  const EhdrW *eh = (const EhdrW *)base;

  if (eh->e_ident[EI_MAG0] != ELFMAG0 || eh->e_ident[EI_MAG1] != ELFMAG1 ||
      eh->e_ident[EI_MAG2] != ELFMAG2 || eh->e_ident[EI_MAG3] != ELFMAG3) {
    return -ENOEXEC;
  }

  const PhdrW *ph = (const PhdrW *)(base + eh->e_phoff);
  const PhdrW *ph_end = ph + eh->e_phnum;

  const DynW *dynamic = NULL;
  size_t dynamic_count = 0;
  for (const PhdrW *p = ph; p < ph_end; ++p) {
    if (p->p_type == PT_DYNAMIC) {
      dynamic = (const DynW *)(base + p->p_vaddr);
      dynamic_count = p->p_memsz / sizeof(DynW);
      break;
    }
  }
  if (!dynamic) return -ENOENT;

  const char *strtab = NULL;
  const SymW *symtab = NULL;
  const uint32_t *gnu_hash = NULL;
  const uint32_t *sysv_hash = NULL;

  for (size_t i = 0; i < dynamic_count; ++i) {
    switch (dynamic[i].d_tag) {
    case DT_STRTAB:
      strtab = (const char *)(base + dynamic[i].d_un.d_ptr);
      break;
    case DT_SYMTAB:
      symtab = (const SymW *)(base + dynamic[i].d_un.d_ptr);
      break;
    case DT_GNU_HASH:
      gnu_hash = (const uint32_t *)(base + dynamic[i].d_un.d_ptr);
      break;
    case DT_HASH:
      sysv_hash = (const uint32_t *)(base + dynamic[i].d_un.d_ptr);
      break;
    default:
      break;
    }
  }

  const char *targets[] = {
      "__vdso_clock_gettime",
      "__kernel_clock_gettime",
      "__vdso_gettimeofday",
  };

  for (size_t t = 0; t < sizeof(targets) / sizeof(targets[0]); ++t) {
    const SymW *sym = NULL;
    if (!sym && gnu_hash) sym = lookup_gnu_hash(targets[t], base, gnu_hash, symtab, strtab);
    if (!sym && sysv_hash) sym = lookup_sysv_hash(targets[t], sysv_hash, symtab, strtab);

    if (sym) {
      const void *addr = base + sym->st_value;
      const char *name = targets[t];
      info->resolved_symbol_name = name;
      if (strcmp(name, "__vdso_clock_gettime") == 0 || strcmp(name, "__kernel_clock_gettime") == 0) {
        info->clock_gettime_fn = (vdso_clock_gettime_t)addr;
        return 0;
      } else if (strcmp(name, "__vdso_gettimeofday") == 0) {
        info->gettimeofday_fn = (vdso_gettimeofday_t)addr;
        return 0;
      }
    }
  }

  return -ESRCH;
}

int vdso_init(vdso_info *info) {
  if (!info) return -EINVAL;
  memset(info, 0, sizeof(*info));

  unsigned long at = getauxval(AT_SYSINFO_EHDR);
  if (at == 0) return -ENOSYS;
  info->base_address = (const void *)at;

  int rc = parse_vdso_and_resolve(info);
  return rc == 0 ? 0 : rc;
}

int vdso_clock_gettime(const vdso_info *info, clockid_t clk, struct timespec *ts) {
  if (info && info->clock_gettime_fn) {
    return info->clock_gettime_fn(clk, ts);
  }
  return clock_gettime_syscall(clk, ts);
}

int vdso_gettimeofday(const vdso_info *info, struct timeval *tv, struct timezone *tz) {
  if (info && info->gettimeofday_fn) {
    return info->gettimeofday_fn(tv, tz);
  }
  return gettimeofday_syscall(tv, tz);
}

uint64_t now_ns_monotonic(const vdso_info *info) {
  struct timespec ts;
  if (vdso_clock_gettime(info, CLOCK_MONOTONIC, &ts) != 0) {
    if (vdso_clock_gettime(info, CLOCK_REALTIME, &ts) != 0) return 0;
  }
  return timespec_to_ns(&ts);
}

uint64_t now_ns_realtime(const vdso_info *info) {
  struct timespec ts;
  if (vdso_clock_gettime(info, CLOCK_REALTIME, &ts) != 0) return 0;
  return timespec_to_ns(&ts);
}


