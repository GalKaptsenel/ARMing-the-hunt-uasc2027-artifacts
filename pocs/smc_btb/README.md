# An EL3 (secure-world) round trip does not flush the normal-world BTB

Tests a necessary precondition for crossing the secure / non-secure boundary. A victim cannot be
placed in the secure world on this hardware (EL3 firmware is present, PSCIv1.1 and SMCCC v1.5, but
there is no OP-TEE or TEE driver, so no vehicle for S-EL0 code). What is testable is whether entering
EL3 flushes or perturbs the normal-world BTB. If it does not, a boundary crossing does not by itself
destroy the prediction state the BTB Prime+Probe channel relies on.

## The channel: SET reuse, not ENTRY reuse

The channel is BTB **capacity / set-eviction** Prime+Probe - the attacker owns a BTB *set*, the
victim's branch evicts a way, the attacker detects the miss. It is **not** target injection
(Spectre-BTI / entry reuse). This matters:

- **Entry reuse** is what **CSV2 kills** (a victim-context prediction cannot be consumed by an
  attacker-context branch). This N3 implements CSV2.
- **Set reuse** is contention on the shared physical array. CSV2 tags predictor *use*, not the array,
  so it does not stop set-eviction; on N3 the BTB is neither VMID- nor ASID-partitioned. The only
  things that would stop a cross-world variant are NS way/set partitioning of the array, or a BTB
  flush on the world switch. This PoC rules out the flush for the EL3 transition.

## What it does

`smc_probe.ko` issues controlled privileged operations from an ioctl (EL0 cannot execute `SMC`); on
this platform the kernel runs at **EL2 (VHE)**, so the SMCs are issued EL2->EL3. `smc_bench` primes one
normal-world EL0 BTB entry, performs one operation between prime and probe, and reports whether the
primed entry survived. `SMC_DO` does real EL3 round trips (`SMCCC_VERSION`, read-only); `SMC_NOP` is
the identical loop without the `SMC` (the kernel-round-trip baseline).

## Build / run

Building `smc_probe.ko` (and `raw_pmu.ko` in `../common`) needs the matching kernel headers
installed (`apt install linux-headers-$(uname -r)`).

```
make KDIR=/usr/src/linux-headers-$(uname -r)     # smc_probe.ko
make bench                                        # smc_bench
sudo insmod smc_probe.ko ; sudo chmod 666 /dev/smc_probe
sudo insmod ../common/raw_pmu.ko                  # EL0 PMU read-out helper
sudo taskset -c 1 ./smc_bench --ops 64 --samples 2000 --cpu 1
```

- `--ops N` - privileged ops per trial between prime and probe (default 64).
- `--samples N` - trials averaged per mode (default 2000).
- `--cpu N` - core to pin to (default 1). `--save FILE` also writes the results to FILE.

No environment variables; `--help` lists the flags.

## Measured result (`--ops 64 --samples 2000`)

```
SMCCC_VERSION from EL3 = 0x10005  (sanity: SMC path works)
  baseline (nothing)       survived=1.000
  self-flood (EL0 evict)   survived=0.029   [positive control: the entry IS evictable]
  NOP ioctl (EL0<->EL2)    survived=1.000
  SMC ioctl (EL0<->EL3)    survived=1.000
  ...
  CFP RCTX (EL2)           survived=0.000   [FEAT_SPECRES: the BTB CAN be flushed by the right op]
  SMCCC_ARCH_WORKAROUND_1  survived=1.000   [feature=1: not required, core not vulnerable]
```

`SMC effect = survived(NOP) - survived(SMC) = 1.000 - 1.000 = 0.000`.

A secure-world (EL3) round trip does not flush or disturb the normal-world BTB - the primed entry
survives 64 SMC round trips intact. The controls make this meaningful: the entry *is* evictable
(self-flood -> 0.029), the ioctl round trip alone does not evict it (NOP -> 1.000), and the BTB *can* be
flushed by an architected primitive (CFP RCTX -> 0.000). The firmware does not BP-harden on the SMC
world switch, and `SMCCC_ARCH_WORKAROUND_1` reports not-required on this core.

This rules out a flush wall on the EL3 transition. It does not by itself demonstrate a cross-NS leak
(EL3 is a different exception level, not a same-EL secure victim); confirming NS array partitioning for
a real S-EL0 victim is the open item flagged in §8.
