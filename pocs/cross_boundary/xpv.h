// Shared control page between the xproc attacker and the standalone pac_victim image. The two processes
// share only this page, over an inherited memfd. The victim holds its own pointer-authentication key and
// its own code image.
#ifndef XPV_H
#define XPV_H
#include <stdint.h>

#define XPV_VBRANCHES 16
#define XPV_SECRET_P  0x0000007a00000000UL

enum xpv_mode { XPV_BTB, XPV_L1D };

struct xpv_ctl {
    volatile int      params_ready;              // attacker filled the setup fields
    volatile int      mode;                      // xpv_mode
    volatile int      sw;                        // pac_switch
    volatile int      med;                       // medium
    volatile int      control;                   // close the window (barrier)
    volatile int      nvbranch;                  // btb: victim co-set branch count
    volatile uint64_t victim_va[XPV_VBRANCHES];  // btb: victim branch sites
    volatile uint64_t base_va;                   // l1d: victim base pointer

    volatile int      turn;                      // 1 run once, 2 done
    volatile int      done;
    volatile int      round;
    volatile int      ack;
    volatile int      skip;                      // btb floor: run no victim branch
    volatile uint64_t and_mask;                  // btb: the victim's AND mask this shot
    volatile int      sel;                       // l1d: -1 secret, 0 or 1 known profile
    volatile int      bit;                       // l1d: field bit under test
    volatile int      ready;                     // l1d: victim drew this round
    volatile int      reveal_req;
    volatile int      reveal_ack;
    volatile unsigned truth;
};

#endif
