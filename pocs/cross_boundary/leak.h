// Unified speculative PAC leak. A victim signs a pointer and, inside one Spectre-v4 store-bypass window,
// forms an address from the signature and accesses it. One signature bit decides whether the address is in
// range or out of range. The attacker recovers the 7-bit field [54:48] through the chosen medium and timer.
#ifndef LEAK_H
#define LEAK_H
#include <stdint.h>
#include <stdio.h>

enum pac_switch { SW_AUT, SW_CANON };
enum boundary { B_SAME, B_XTHREAD, B_XPROC, B_XEL, B_XVM };
enum medium { M_L1D, M_DTLB, M_ITLB, M_BTB };
enum timer { T_PMU, T_CNTVCT };

#define SECRET_BITS  7
#define SECRET_FIELD (0x7fUL << 48)

struct cfg {
    enum pac_switch sw;
    enum boundary   bnd;
    enum medium     med;
    enum timer      tmr;
    int             cpu;
    int             rounds;
    int             samples;
    int             control;   // 1 closes the speculation window (barrier)
};

struct chan_stats {
    int    rounds;
    int    full;           // rounds with the whole leaked field recovered
    long   bits_total;
    long   bits_correct;
    double seconds;
    int    nbits;                     // field width this run
    long   pos_correct[SECRET_BITS];  // per native position [48+k] correct
    long   pos_total[SECRET_BITS];
};

extern FILE *g_save;
extern int g_move48;   // dtlb+canon: relocate each PAC bit to index 48 before the canonicality access
void tee_printf(const char *fmt, ...);

const char *switch_name(enum pac_switch sw);
const char *medium_name(enum medium med);
const char *timer_name(enum timer tmr);
const char *boundary_name(enum boundary bnd);

void report(const struct cfg *cfg, const struct chan_stats *stats);
int  bits_match(unsigned recovered, unsigned truth, int width);

int run_same(const struct cfg *cfg, struct chan_stats *out);
int run_same_btb(const struct cfg *cfg, struct chan_stats *out);   // same-thread BTB eviction-set (same_btb.c)
int run_xthread_btb(const struct cfg *cfg, struct chan_stats *out);// cross-thread BTB eviction-set (same_btb.c)
int run_xthread(const struct cfg *cfg, struct chan_stats *out);
int run_xproc(const struct cfg *cfg, struct chan_stats *out);
int run_xel(const struct cfg *cfg, struct chan_stats *out);
int run_xvm(const struct cfg *cfg, struct chan_stats *out);

#endif
