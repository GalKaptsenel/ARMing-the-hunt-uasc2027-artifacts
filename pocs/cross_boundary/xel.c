// xel.c -- cross EL (EL2 to EL0). The victim is aut_xel.ko at EL2 under VHE. The EL0 attacker recovers the
// field by prime and probe of its own dTLB/iTLB eviction set, and for L1D by Flush+Reload of the page the
// module maps into it.
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "channel.h"

#define AX_MAGIC 0xBA
struct ax_g {
    uint32_t sw;
    uint32_t medium;
    uint32_t bit;
    uint32_t profile;
    uint32_t control;
};
#define AX_SETUP  _IO (AX_MAGIC, 0)
#define AX_GADGET _IOW(AX_MAGIC, 1, struct ax_g)
#define AX_REVEAL _IOR(AX_MAGIC, 2, uint64_t)
#define PROFILE_SECRET 2

struct xel_ctx {
    int         fd;
    struct ax_g req;
};

static void xel_next_round(void *ctx) {
    struct xel_ctx *xel = ctx;
    if (0 != ioctl(xel->fd, AX_SETUP, 0)) {
        perror("AX_SETUP");
        exit(1);
    }
}
static void xel_set_bit(void *ctx, int bit) {
    ((struct xel_ctx *)ctx)->req.bit = (uint32_t)bit;
}
static void xel_set_mode(void *ctx, int mode) {
    ((struct xel_ctx *)ctx)->req.profile = (0 > mode) ? PROFILE_SECRET : (uint32_t)mode;
}
static void xel_transmit(void *ctx) {
    struct xel_ctx *xel = ctx;
    if (0 != ioctl(xel->fd, AX_GADGET, &xel->req)) {
        perror("AX_GADGET");
        exit(1);
    }
}
static unsigned xel_reveal(void *ctx) {
    struct xel_ctx *xel = ctx;
    uint64_t value = 0;
    if (0 != ioctl(xel->fd, AX_REVEAL, &value)) {
        perror("AX_REVEAL");
        exit(1);
    }
    return (unsigned)((value >> 48) & 0x7f);
}

// L1D cross-EL over the page the module maps into the attacker. The kernel address is unknown at EL0, so the
// attacker Flush and Reloads the shared physical page: the victim's canonical load leaves the line resident,
// seen as a fast reload.
#define FR_LINES 16
static inline uint64_t read_pmu_counter(void) {
    uint64_t v = 0;
    asm volatile("mrs %0, pmevcntr0_el0" : "=r"(v));
    return v;
}
static double fr_shot(struct xel_ctx *ctx, enum timer tmr, uint8_t *shared) {
    for (int line = 0; line < FR_LINES; ++line) {
        flush_line(shared + (size_t)line * 64);
    }
    fence();
    if (0 != ioctl(ctx->fd, AX_GADGET, &ctx->req)) {
        perror("AX_GADGET");
        exit(1);
    }
    fence();
    double sum = 0;
    for (int line = FR_LINES - 1; 0 <= line; --line) {
        volatile uint8_t *p = shared + (size_t)line * 64;
        if (T_PMU == tmr) {
            asm volatile("isb");
            uint64_t before = read_pmu_counter();
            uint8_t v = *p;
            asm volatile("" :: "r"(v));
            asm volatile("isb");
            sum += (double)((read_pmu_counter() - before) > 0);
        } else {
            uint64_t t0 = cntvct();
            uint8_t v = *p;
            asm volatile("" :: "r"(v));
            sum += (double)(cntvct() - t0);
        }
    }
    fence();
    return sum;
}

static int run_xel_l1d_fr(const struct cfg *cfg, struct chan_stats *out) {
    int fd = open("/dev/aut_xel", O_RDWR);
    if (0 > fd) {
        perror("open /dev/aut_xel (load aut_xel.ko)");
        return 1;
    }
    pin_to_core(cfg->cpu);
    if (T_PMU == cfg->tmr) {
        pmu_init(M_L1D);
    }
    uint8_t *shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (MAP_FAILED == shared) {
        perror("mmap /dev/aut_xel");
        return 1;
    }
    struct xel_ctx ctx = {
        .fd = fd,
        .req = { .sw = (uint32_t)cfg->sw, .medium = (uint32_t)M_L1D, .profile = PROFILE_SECRET,
                 .control = (uint32_t)cfg->control },
    };

    struct chan_stats stats = { .rounds = cfg->rounds, .bits_total = (long)cfg->rounds * SECRET_BITS };
    struct timespec t0 = { 0 };
    struct timespec t1 = { 0 };
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int round = 0; round < cfg->rounds; ++round) {
        if (0 != ioctl(fd, AX_SETUP, 0)) {
            perror("AX_SETUP");
            return 1;
        }
        unsigned recovered = 0;
        for (int bit = 0; bit < SECRET_BITS; ++bit) {
            ctx.req.bit = (uint32_t)bit;
            double profile0 = 0;
            double profile1 = 0;
            double secret_sum = 0;
            for (int sample = 0; sample < cfg->samples; ++sample) {
                ctx.req.profile = 0;
                profile0 += fr_shot(&ctx, cfg->tmr, shared);
                ctx.req.profile = 1;
                profile1 += fr_shot(&ctx, cfg->tmr, shared);
                ctx.req.profile = PROFILE_SECRET;
                secret_sum += fr_shot(&ctx, cfg->tmr, shared);
            }
            recovered |= (unsigned)classify(secret_sum, profile0, profile1) << bit;
        }
        uint64_t value = 0;
        if (0 != ioctl(fd, AX_REVEAL, &value)) {
            perror("AX_REVEAL");
            return 1;
        }
        unsigned truth = (unsigned)((value >> 48) & 0x7f);
        int hit = (recovered == truth);
        stats.full += hit;
        stats.bits_correct += bits_match(recovered, truth, SECRET_BITS);
        tee_printf("  %3d  | secret=0x%02x  recovered=0x%02x  %d/7  %s\n",
                   round, truth, recovered, bits_match(recovered, truth, SECRET_BITS), hit ? "WIN" : "lose");
    }
    clock_gettime(CLOCK_MONOTONIC, &t1);
    stats.seconds = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
    munmap(shared, 4096);
    close(fd);
    *out = stats;
    return 0;
}

int run_xel(const struct cfg *cfg, struct chan_stats *out) {
    if (M_L1D == cfg->med) {
        return run_xel_l1d_fr(cfg, out);
    }
    int fd = open("/dev/aut_xel", O_RDWR);
    if (0 > fd) {
        perror("open /dev/aut_xel (load aut_xel.ko)");
        return 1;
    }
    pin_to_core(cfg->cpu);
    struct attacker att = { 0 };
    attacker_setup(&att, cfg->med, cfg->tmr, 0);

    struct xel_ctx ctx = {
        .fd = fd,
        .req = { .sw = (uint32_t)cfg->sw, .medium = (uint32_t)cfg->med, .profile = PROFILE_SECRET,
                 .control = (uint32_t)cfg->control },
    };
    struct victim_io io = {
        .ctx = &ctx, .next_round = xel_next_round, .set_bit = xel_set_bit,
        .set_mode = xel_set_mode, .transmit = xel_transmit, .reveal = xel_reveal,
    };
    recover_rounds(&att, &io, cfg, out);
    close(fd);
    return 0;
}
