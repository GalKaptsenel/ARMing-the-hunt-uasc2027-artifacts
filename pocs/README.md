# Proof-of-Concept Artifacts

Proof-of-concept programs accompanying the paper. They demonstrate the speculative leaks the paper
reports and their reach.

Each program is **self-scoring**: the victim generates a fresh random secret each round, and the
harness compares it to the recovered value only to report accuracy. All measurements are taken on an
Arm Neoverse N3, each pinned to a single isolated core. The attacker runs unprivileged at EL0, and
for the cross-process and guest-to-host cases the attacker and victim share one physical core. No
elevated privilege, special instruction, or configuration is required beyond a vulnerable code
pattern in the target and the ability to co-locate on a core.

These are research proofs of concept that isolate the channel rather than packaging complete
exploits.

## Layout

| directory | proof of concept | invocation |
|-----------|------------------|-----------|
| `cross_boundary/` | Unified speculative PAC leak (AUT\* and canonicality) | `cross_boundary --switch {aut\|canon} --boundary {same\|xthread\|xproc\|xel\|xvm} ...` |
| `stack_leak/` | Blind stack-canary recovery | `canary_leak_blind -w {v1\|v4\|rsb}` |
| `openssl_rsa/` | RSA-2048 key recovery through OpenSSL | `rsa_leak` |
| `smc_btb/` | An EL3 round trip does not flush the BTB | `smc_bench` |
| `common/` | shared read-out and timing helpers | n/a |

Each directory has its own `README.md` with the build and run specifics. The summaries below give
the structure and attacker model.

## Unified speculative PAC leak (`cross_boundary`)

A single binary recovers the 7-bit pointer-authentication field [54:48] of a signed pointer, a fresh
random field the attacker does not know in advance, through two speculative mechanisms selected by
`--switch`, across five isolation boundaries, four media, and two read-out timers. Each round the victim
signs a pointer with a fresh key and, inside one Spectre-v4 store-bypass window, forms an address from the
signature and accesses it. One field bit decides whether the address stays in range, leaving a
microarchitectural footprint, or falls out of range and is fast rejected, and the attacker reads that
footprint to sweep the seven bits.

The `canon` switch masks the signature so a field bit leaves the address canonical or non-canonical. The
`aut` switch places a field bit at bit 55 and authenticates, so the pointer stays in the user half or
sign-extends into the kernel half. The boundaries run same-thread, cross-thread, cross-process (EL0 to
EL0), cross-EL (an EL2 kernel module under VHE to EL0), and guest-to-host. The media are the L1 data
cache, the data and instruction TLBs, and the branch-target buffer, read with either a PMU event counter
or the rootless `cntvct_el0` virtual counter, the latter needing no PMU access, driver, or privilege. The
branch-target buffer allocates for any canonical target regardless of range, which the canonicality leak
uses across the process and VM boundaries, whereas the AUT\* leak needs the cache and TLBs that gate on an
in-range access. The directory's README has the full matrix.

## Blind stack-canary recovery (`stack_leak/`)

Recovers a process's own stack canary with no prior knowledge of its value. The gadget is a
two-dimensional array dereference, `rows[i][sizes[i] - 1]`, whose out-of-bounds inner index reads the
canary from the local `sizes[]` array while `rows[i]` is an attacker-controlled base pointer, so only
the mispredicted path forms the offending address and the access stays in bounds architecturally. The
same gadget is driven three independent ways: a mistrained bounds check (Spectre-v1), a store-bypassed
bound (Spectre-v4), and a return shadow (Spectre-RSB). Recovery reads the canonicality oracle through
Flush+Reload over a pre-mapped page scaffold, combining an additive sweep for the high bits with a
top-down carry-trick for the low bits, and recovers the full `[55:0]` value.

## RSA-2048 key recovery through OpenSSL (`openssl_rsa/`)

An end-to-end attack through OpenSSL built with its anti-ROP mitigations disabled and a single
vulnerable `memcpy` planted in it. A plain stack-buffer overflow drives a return-oriented chain built
entirely from gadgets found within the OpenSSL library itself, with no attacker code in the victim.
The chain sets up and fires a Spectre-v4 window inside the real victim and transmits over the BTB
channel, read with the rootless `cntvct_el0` timer. Because the read primitive walks OpenSSL's own
heap, it recovers the bytes of an in-use RSA-2048 private key.

## An EL3 round trip does not flush the BTB (`smc_btb/`)

Tests a necessary precondition for crossing the secure / non-secure boundary. A victim cannot be
placed in the secure world on this hardware, so instead of demonstrating the crossing the harness
tests whether entering EL3 disturbs the normal-world branch-target buffer. It primes one EL0 BTB
entry, performs an EL3 round trip between the prime and the probe, and reports whether the entry
survived. It survives intact across many round trips, so an EL3 world switch does not by itself
destroy the prediction state the BTB channel relies on.

## Platform

All measurements are on an Arm Neoverse N3 (Armv9.2-A), one isolated core. The canonicality cache and
TLB channels also reproduce on a Google Pixel 8 (Cortex-A715 and Cortex-X3); the BTB-mediated
canonicality channel reproduces on the Cortex-A715 but not the Cortex-X3.
