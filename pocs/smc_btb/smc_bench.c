// smc_bench.c -- does an EL3 (secure-world) SMC round trip flush or perturb the normal-world BTB? Prime
// one EL0 indirect-branch BTB entry, do one privileged op between prime and probe, and report whether
// the entry survived, against a self-flood positive control and a NOP-ioctl baseline. See README.md.
// Needs raw_pmu.ko + smc_probe.ko. Build: make bench.  Run: sudo taskset -c 1 ./smc_bench
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>
#include <getopt.h>
#include <stdarg.h>

static FILE *g_save = NULL;

static void tee_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    if (g_save) {
        va_start(args, fmt);
        vfprintf(g_save, fmt, args);
        va_end(args);
    }
}

// ---- CFP RCTX from EL0 (FEAT_SPECRES). Executable in userspace only if SCTLR_EL1.EnRCTX=1, else SIGILL.
// CFP RCTX, Xt  ==  SYS #3, C7, C3, #4, Xt  (encoding 0xD50B7380 | Rt). Xt = target-context operand.
static sigjmp_buf g_cfpjb;
static volatile sig_atomic_t g_cfptrap = 0;
static int g_cfp_el0_ok = 0;

static void sigill_handler(int sig) {
    (void)sig;
    g_cfptrap = 1;
    siglongjmp(g_cfpjb, 1);
}
static int probe_cfp_el0(void) {                // 1 if EL0 may execute CFP RCTX, 0 if it SIGILLs
    struct sigaction action = { 0 };
    struct sigaction old_action = { 0 };
    memset(&action, 0, sizeof action);
    action.sa_handler = sigill_handler;
    sigaction(SIGILL, &action, &old_action);
    int allowed = 1;
    g_cfptrap = 0;
    if (0 == sigsetjmp(g_cfpjb, 1)) {
        asm volatile("sys #3, c7, c3, #4, xzr\n isb\n":::"memory");
    } else {
        allowed = 0;
    }
    sigaction(SIGILL, &old_action, NULL);
    return allowed;
}
static inline void cfp_el0_run(void) {          // sweep plausible EL0/EL1/NS context operands, then barrier
    unsigned long contexts[6] = {0, (1UL<<27), (1UL<<27)|(1UL<<25), (1UL<<25), (1UL<<26), (1UL<<27)|(1UL<<26)};
    for (int context_index = 0; context_index < 6; context_index++) {
        asm volatile("sys #3, c7, c3, #4, %0"::"r"(contexts[context_index]):"memory");
    }
    asm volatile("dsb sy\n isb\n":::"memory");
}

#define SMC_DO     0x5301u
#define SMC_NOP    0x5302u
#define OP_ICIALLU 0x5303u
#define OP_TLBI    0x5304u
#define OP_SCTLR   0x5305u
#define OP_BARRIER 0x5306u
#define OP_MMUTOGGLE 0x5307u
#define OP_CFPRCTX   0x5308u
#define OP_WA1_FEAT  0x5309u
#define OP_WA1_DO    0x530Au

static volatile uint64_t sink = 0;
#define NUM_TOUCH_FNS 8
#define STRIDE_BYTES 4096
#define ACCESS_IDX 3
#define LEAK_IDX 6
static uint8_t *marker_pages = NULL;
#define TF(fn_index) \
    static void __attribute__((noinline)) tf##fn_index(void) { \
        sink += marker_pages[(fn_index) * STRIDE_BYTES]; \
        asm volatile(""); \
    }
TF(0) TF(1) TF(2) TF(3) TF(4) TF(5) TF(6) TF(7)
typedef void(*touch_fn_t)(void);
static touch_fn_t touch_pool[NUM_TOUCH_FNS] = { tf0, tf1, tf2, tf3, tf4, tf5, tf6, tf7 };
static inline uint64_t sign(uint64_t addr, uint64_t modifier) {
    asm volatile("pacia %0,%1":"+r"(addr):"r"(modifier));
    return addr;
}

static uint64_t decoy_ptr = 0;
static uint64_t decoy_mod = 0x9999;
static uint64_t signed_decoy = 0;
static uint64_t retpad = 0;
static uint64_t target_slots[4] __attribute__((aligned(64))) = { 0 };
static uint64_t cand_slots[4]   __attribute__((aligned(64))) = { 0 };

static inline void wr_pmcr(uint64_t value) {
    asm volatile("msr pmcr_el0,%0"::"r"(value));
    asm volatile("isb");
}
static inline uint64_t rd_pmcr(void) {
    uint64_t value = 0;
    asm volatile("mrs %0,pmcr_el0":"=r"(value));
    return value;
}
static inline uint64_t rd_ref(void) {
    uint64_t value = 0;
    asm volatile("mrs %0,pmevcntr0_el0":"=r"(value));
    return value;
}
static void pmu_init(void) {
    wr_pmcr(0);
    asm volatile("msr pmcntenclr_el0,%0"::"r"((uint64_t)0xffffffff));
    asm volatile("isb");
    asm volatile("msr pmevtyper0_el0,%0"::"r"((uint64_t)0x03));   // L1D_CACHE_REFILL
    asm volatile("isb");
    asm volatile("msr pmevcntr0_el0,%0"::"r"((uint64_t)0));
    asm volatile("isb");
    asm volatile("msr pmcntenset_el0,%0"::"r"((uint64_t)1));
    asm volatile("isb");
    wr_pmcr(rd_pmcr() | 7);
}
static inline void flush(void *line) {
    asm volatile("dc civac,%0"::"r"(line):"memory");
}
static inline void fence(void) {
    asm volatile("dsb sy\n isb\n":::"memory");
}
static inline int resident(volatile uint8_t *line) {
    fence();
    uint64_t before = rd_ref();
    uint8_t value = *line;             // touch the line
    asm volatile(""::"r"(value));
    fence();
    return (rd_ref() - before) == 0;   // no refill event => it was already cached
}
static void pin(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof set, &set);
}

typedef void(*branch_fn_t)(void);
#define STUB_BYTES 64
static void emit_stub(void *addr, uint64_t base) {
    uint32_t *words = (uint32_t*)addr;
    words[0] = 0xF81F0FFEu;
    words[1] = 0xD2800011u|(uint32_t)((base&0xffff)<<5);
    words[2] = 0xF2A00011u|(uint32_t)(((base>>16)&0xffff)<<5);
    words[3] = 0xF2C00011u|(uint32_t)(((base>>32)&0xffff)<<5);
    words[4] = 0xF9400230u;
    words[5] = 0xF9400629u;
    words[6] = 0xDAC10130u;
    words[7] = 0xF9400A29u;
    words[8] = 0x8A090210u;
    words[9] = 0xF9400E29u;
    words[10] = 0xCA090210u;
    words[11] = 0xD63F0200u;
    words[12] = 0xF84107FEu;
    words[13] = 0xD65F03C0u;
    __builtin___clear_cache((char*)addr,(char*)addr+STUB_BYTES);
}
static long spec_flag[512] __attribute__((aligned(4096))) = { 0 };
static long spec_index[512] __attribute__((aligned(4096))) = { 0 };
static inline void v4call(branch_fn_t branch_fn) {
    spec_flag[0] = 1;
    spec_index[0] = 0;
    flush(&spec_index[0]);
    fence();
    long index = *(volatile long *)&spec_index[0];
    *(volatile long *)&spec_flag[index] = 0;
    if (*(volatile long *)&spec_flag[0]) {
        branch_fn();
    }
}

static uint8_t *code_arena = NULL;
#define ARENA (64UL*1024*1024)
#define SETSTRIDE (1UL<<13)
static branch_fn_t target_stub = 0;
static uint64_t target_addr = 0;
#define NFLOOD 64
static branch_fn_t alias_stub[NFLOOD] = { 0 };
static void build_flood(void) {
    for (int flood_index = 0; flood_index < NFLOOD; ++flood_index) {
        uint64_t addr = target_addr + (uint64_t)(flood_index + 1) * SETSTRIDE;
        emit_stub((void *)addr, (uint64_t)cand_slots);
        alias_stub[flood_index] = (branch_fn_t)addr;
    }
}
static inline void self_flood(void) {
    for (int flood_index = 0; flood_index < NFLOOD; ++flood_index) {
        alias_stub[flood_index]();
    }
}

#define TRAIN 24
static void prime_target(void) {
    target_slots[2] = ~0UL;
    target_slots[3] = signed_decoy ^ (uint64_t)touch_pool[ACCESS_IDX];
    for (int train_index = 0; train_index < TRAIN; ++train_index) {
        target_stub();
    }
}
static int readout_target(void) {
    flush(&marker_pages[ACCESS_IDX * STRIDE_BYTES]);
    target_slots[2] = ~(0xFFFFUL << 48);
    target_slots[3] = (1UL << 48) | (1UL << 47);
    v4call(target_stub);
    target_slots[2] = ~0UL;
    target_slots[3] = signed_decoy ^ (uint64_t)touch_pool[LEAK_IDX];
    v4call(target_stub);
    fence();
    return resident(&marker_pages[ACCESS_IDX * STRIDE_BYTES]);
}

static int smcfd = 0;
enum { M_BASE, M_SELF, M_NOP, M_SMC, M_ICIALLU, M_TLBI, M_SCTLR, M_BAR, M_MMUTOG, M_CFP, M_WA1, M_CFP_EL0 };
// One measurement mode: prime the entry, do the op `ops` times, probe survival, averaged over `samples`.
static double run(int mode, int ops, int samples) {
    long survived = 0;
    for (int trial = 0; trial < samples; ++trial) {
        prime_target();
        if (mode == M_SELF) {
            self_flood();
        } else if (mode == M_NOP) {
            ioctl(smcfd, SMC_NOP, ops);
        } else if (mode == M_SMC) {
            ioctl(smcfd, SMC_DO, ops);
        } else if (mode == M_ICIALLU) {
            ioctl(smcfd, OP_ICIALLU, ops);
        } else if (mode == M_TLBI) {
            ioctl(smcfd, OP_TLBI, ops);
        } else if (mode == M_SCTLR) {
            ioctl(smcfd, OP_SCTLR, ops);
        } else if (mode == M_BAR) {
            ioctl(smcfd, OP_BARRIER, ops);
        } else if (mode == M_MMUTOG) {
            if (ioctl(smcfd, OP_MMUTOGGLE, 1) < 0) {
                return -1.0;
            }
        } else if (mode == M_CFP) {
            if (ioctl(smcfd, OP_CFPRCTX, 1) < 0) {
                return -1.0;
            }
        } else if (mode == M_WA1) {
            if (ioctl(smcfd, OP_WA1_DO, ops) < 0) {
                return -1.0;
            }
        } else if (mode == M_CFP_EL0) {
            if (!g_cfp_el0_ok) {
                return -1.0;
            }
            cfp_el0_run();
        }
        survived += readout_target();
    }
    return (double)survived / samples;
}

int main(int argc, char **argv) {
    setvbuf(stdout,NULL,_IONBF,0);
    int ops = 64;
    int samples = 2000;
    int cpu = 1;
    const char *savepath = NULL;
    enum { O_SAMPLES=1000 };   // long-only (short -s is --save)
    static struct option opts[] = {
        {"ops",1,0,'o'},{"cpu",1,0,'c'},{"save",1,0,'s'},{"samples",1,0,O_SAMPLES},{"help",0,0,'h'},{0,0,0,0}
    };
    int opt = 0;
    while(-1!=(opt=getopt_long(argc,argv,"o:c:s:h",opts,0))){
        switch(opt){
            case 'o':
                ops = atoi(optarg);
                break;
            case 'c':
                cpu = atoi(optarg);
                break;
            case 's':
                savepath = optarg;
                break;
            case O_SAMPLES:
                samples = atoi(optarg);
                break;
            default:
                printf("usage: %s [--ops N] [--samples N] [--cpu N] [--save FILE]\n"
                       "\n"
                       "Measures whether an EL3 SMC round trip (and other privileged ops) flushes a primed\n"
                       "normal-world BTB entry. Needs /dev/smc_probe and raw_pmu.ko; run with sudo.\n"
                       "\n"
                       "  --ops N      how many times the privileged op is issued between prime and probe,\n"
                       "               per measurement (default 64) -- one crossing may not perturb the BTB,\n"
                       "               so the op is repeated to give any flushing effect a chance to show.\n"
                       "  --samples N  measurements averaged per mode (default 2000); higher = less noise, slower.\n"
                       "  --cpu N      core to pin to (default 1); use an isolated core.\n"
                       "  --save FILE  also write the results to FILE. No env vars are used.\n",
                       argv[0]);
                return 0;
        }
    }
    if(ops<1){
        ops = 1;
    }
    if(samples<1){
        samples = 1;
    }
    if(savepath){
        g_save = fopen(savepath,"w");
        if(!g_save){
            perror("--save");
            return 1;
        }
        setvbuf(g_save, NULL, _IOLBF, 0);   // line-buffered: --save lands live and survives an interrupt
    }
    pin(cpu);
    pmu_init();
    smcfd = open("/dev/smc_probe",O_RDWR);
    if(smcfd<0){
        perror("open /dev/smc_probe");
        return 1;
    }
    long version = ioctl(smcfd,SMC_DO,1);
    tee_printf("SMCCC_VERSION from EL3 = 0x%lx  (sanity: SMC path works)\n",(unsigned long)version);

    code_arena = mmap(NULL,ARENA,PROT_READ|PROT_WRITE|PROT_EXEC,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(code_arena==MAP_FAILED){
        perror("mmap");
        return 1;
    }
    *(uint32_t*)code_arena = 0xD65F03C0u;
    __builtin___clear_cache((char*)code_arena,(char*)code_arena+4);
    retpad = (uint64_t)code_arena;
    marker_pages = mmap(NULL,NUM_TOUCH_FNS*STRIDE_BYTES,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    for(int i=0;i<NUM_TOUCH_FNS;++i){
        marker_pages[i*STRIDE_BYTES] = 1;
    }
    uint8_t *decoy = mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    decoy[0] = 1;
    decoy_ptr = (uint64_t)decoy;
    signed_decoy = sign(decoy_ptr,decoy_mod);
    target_slots[0] = decoy_ptr;
    target_slots[1] = decoy_mod;
    target_slots[2] = ~0UL;
    cand_slots[0] = decoy_ptr;
    cand_slots[1] = decoy_mod;
    cand_slots[2] = ~0UL;
    cand_slots[3] = signed_decoy^retpad;
    target_addr = (uint64_t)code_arena+(ARENA/2);
    emit_stub((void*)target_addr,(uint64_t)target_slots);
    target_stub = (branch_fn_t)target_addr;
    build_flood();

    double base = run(M_BASE,ops,samples);
    double self = run(M_SELF,ops,samples);
    double nop = run(M_NOP,ops,samples);
    double smc = run(M_SMC,ops,samples);
    double icu = run(M_ICIALLU,ops,samples);
    double tlbi = run(M_TLBI,ops,samples);
    double sctlr = run(M_SCTLR,ops,samples);
    double bar = run(M_BAR,ops,samples);
    double mtog = run(M_MMUTOG,ops,samples);
    long wa1feat = ioctl(smcfd,OP_WA1_FEAT,0);   // <0 or 1 => not implemented/needed; 0 => implemented
    double cfp = run(M_CFP,ops,samples);
    double wa1 = run(M_WA1,ops,samples);
    g_cfp_el0_ok = probe_cfp_el0();
    double cfp0 = run(M_CFP_EL0,ops,samples);

    tee_printf("\nops per trial=%d  samples=%d   (survived = primed EL0 BTB entry still predicts A)\n",ops,samples);
    tee_printf("  baseline (nothing)       survived=%.3f\n", base);
    tee_printf("  self-flood (EL0 evict)   survived=%.3f   [positive control: entry IS evictable]\n", self);
    tee_printf("  NOP ioctl (EL0<->EL2)    survived=%.3f\n", nop);
    tee_printf("  SMC ioctl (EL0<->EL3)    survived=%.3f\n", smc);
    tee_printf("  --- EL2 BTB-flush candidates (does any instruction invalidate the BTB like BPIALL did?) ---\n");
    tee_printf("  IC IALLU (EL2)           survived=%.3f   [instruction-cache invalidate, A15-era BP trick]\n", icu);
    tee_printf("  TLBI VMALLE1 (EL2)       survived=%.3f   [TLB maintenance]\n", tlbi);
    tee_printf("  SCTLR_EL1 rewrite (EL2)  survived=%.3f   [same value, M stays 1: safe MMU-reg touch]\n", sctlr);
    tee_printf("  DSB;ISB barrier (EL2)    survived=%.3f   [negative control]\n", bar);
    if(mtog<0){
        tee_printf("  MMU M-toggle (EL2)       UNSUPPORTED (idmap geometry) -- not attempted\n");
    } else {
        tee_printf("  MMU M-toggle (EL2)       survived=%.3f   [SCTLR.M 1->0->1, the A57/A72 firmware trick]\n", mtog);
    }
    tee_printf("  --- architected BP-restriction primitives (the RIGHT levers) ---\n");
    if(cfp<0){
        tee_printf("  CFP RCTX (EL2)           UNSUPPORTED (no FEAT_SPECRES)\n");
    } else {
        tee_printf("  CFP RCTX (EL2)           survived=%.3f   [FEAT_SPECRES control-flow pred restriction, 6-ctx sweep]\n", cfp);
    }
    if(cfp0<0){
        tee_printf("  CFP RCTX (EL0, userspace) TRAPS (SCTLR_EL1.EnRCTX=0 -> SIGILL; kernel didn't enable EL0 access)\n");
    } else {
        tee_printf("  CFP RCTX (EL0, userspace) survived=%.3f   [self-flush, no kernel]\n", cfp0);
    }
    tee_printf("  SMCCC_ARCH_WORKAROUND_1  feature=%ld  (%s)\n", wa1feat,
        wa1feat==0?"implemented+needed" : wa1feat==1?"NOT required (core not vulnerable)" : "NOT supported");
    if(wa1<0){
        tee_printf("  SMCCC_ARCH_WORKAROUND_1  survived=(call failed)\n\n");
    } else {
        tee_printf("  SMCCC_ARCH_WORKAROUND_1  survived=%.3f   [firmware BP-invalidation SMC]\n\n", wa1);
    }
    if(base-self < 0.3){
        tee_printf("  => control WEAK (self-flood didn't evict); disregard.\n");
    } else {
        double threshold = 0.3;
        int any_flushed = 0;
        if(base-icu   > threshold){
            tee_printf("  => IC IALLU FLUSHES the BTB (usable BPIALL substitute).\n");
            any_flushed = 1;
        }
        if(base-tlbi  > threshold){
            tee_printf("  => TLBI perturbs the BTB.\n");
            any_flushed = 1;
        }
        if(base-sctlr > threshold){
            tee_printf("  => SCTLR_EL1 rewrite FLUSHES the BTB (side effect keys off writing SCTLR).\n");
            any_flushed = 1;
        }
        if(base-bar   > threshold){
            tee_printf("  => barrier perturbs the BTB.\n");
            any_flushed = 1;
        }
        if(cfp>=0 && base-cfp > threshold){
            tee_printf("  => CFP RCTX flushes the BTB (FEAT_SPECRES invalidates on N3).\n");
            any_flushed = 1;
        }
        if(cfp>=0 && base-cfp <= threshold){
            tee_printf("  => CFP RCTX does NOT evict the primed BTB entry (restriction is not a full invalidation on N3).\n");
        }
        if(wa1>=0 && base-wa1 > threshold){
            tee_printf("  => SMCCC_ARCH_WORKAROUND_1 FLUSHES the BTB (firmware BP-hardening active).\n");
            any_flushed = 1;
        }
        if(mtog>=0 && base-mtog > threshold){
            tee_printf("  => MMU M-TOGGLE FLUSHES the BTB (A57/A72 side effect present on N3!).\n");
            any_flushed = 1;
        }
        if(mtog>=0 && base-mtog <= threshold){
            tee_printf("  => MMU M-toggle does NOT flush the N3 BTB (A57/A72 side effect absent, as expected for a CSV2 core).\n");
        }
        if(!any_flushed){
            tee_printf("  => NO EL2 instruction/op flushes the N3 BTB; only eviction (self-flood) does.\n");
        }
    }
    if(g_save){
        fclose(g_save);
    }
    return 0;
}
