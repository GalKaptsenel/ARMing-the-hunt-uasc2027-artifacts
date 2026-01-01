// The pipe carries the victim's public key (n, e) and the ground-truth d. The corrector and the
// RSA-inversion proof use only the public key. The ground truth is read only to score the leak.
#ifndef SCORING_H
#define SCORING_H
#include <stdint.h>
#include "donor.h"

extern uint64_t g_key_limbaddr;      // address of d's limb array in the victim's heap (the leak target)
extern int g_key_limbs;
extern unsigned long *g_key_truth;   // attacker-side copy of d, for scoring only
extern OBIGNUM *g_d, *g_n, *g_e;
extern BN_CTX *g_ctx;

void send_key_to_parent(int fd);     // child: serialize the key onto the scoring pipe
void recv_key_from_parent(int fd);   // parent: receive the target address + ground truth
void verify_key(const unsigned long *rec_limb, int nl);
int correct_key(unsigned long *limbs, int num_limbs, const double *bit_conf, int max_errors);

#endif
