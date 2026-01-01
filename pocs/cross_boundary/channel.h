#ifndef CHANNEL_H
#define CHANNEL_H
#include <stdint.h>
#include "leak.h"

#define PAGE_BYTES   4096UL
#define LINE_BYTES   64UL
#define POOL_LINES   2048
#define SLED_PAGES   24
#define DTLB_PAGES   40
#define SLED_LINES   16

// The victim slot the gadget reads. canon uses raw and and_mask; aut uses raw, bit_index, and base.
struct slot {
    uint64_t raw;
    uint64_t and_mask;
    uint64_t bit_index;
    uint64_t base;
} __attribute__((aligned(64)));

typedef void (*gadget_fn)(struct slot *);

// Copy the position-independent victim gadget for (sw, med) to an executable region and return it.
gadget_fn emit_gadget(void *dst, enum pac_switch sw, enum medium med);

// One speculative transmit. control closes the window.
void victim_transmit(gadget_fn gadget, struct slot *slot, int control);

void *victim_base_alloc(enum medium med);

// Eviction-set attacker for L1D, dTLB, iTLB.
struct attacker {
    enum medium med;
    enum timer  tmr;
    void       *prime[POOL_LINES];
    int         nprime;
};

void   attacker_setup(struct attacker *att, enum medium med, enum timer tmr, uint64_t victim_base);

typedef void (*transmit_fn)(void *ctx);
double channel_shot(struct attacker *att, transmit_fn tx, void *ctx);   // one prime, transmit, measure

int    classify(double signal, double centroid0, double centroid1);

// A victim the recovery drives. set_mode selects a secret transmit (-1) or a known profile (0 or 1).
// next_round re-signs. reveal returns the round's truth after the guess.
struct victim_io {
    void    *ctx;
    void   (*next_round)(void *ctx);
    void   (*set_bit)(void *ctx, int bit);
    void   (*set_mode)(void *ctx, int mode);
    void   (*transmit)(void *ctx);
    unsigned (*reveal)(void *ctx);
};

// Recover the 7-bit field over cfg->rounds, each bit interleaving a secret transmit with the two profiles.
void recover_rounds(struct attacker *att, struct victim_io *io, const struct cfg *cfg, struct chan_stats *out);

uint64_t pac_sign(uint64_t ptr, uint64_t mod);
uint64_t rand_u64(void);
// Fill the slot for one transmit. slot_secret probes bit `bit` of the signature. slot_profile drives that
// bit to a known `value`.
void slot_secret(struct slot *slot, enum pac_switch sw, uint64_t signature, uint64_t base, int bit);
void slot_profile(struct slot *slot, enum pac_switch sw, uint64_t base, int bit, int value);

void pin_to_core(int core);
void flush_line(const void *line);
void fence(void);
void pmu_init(enum medium med);
uint64_t cntvct(void);
void enable_store_bypass(void);

#endif
