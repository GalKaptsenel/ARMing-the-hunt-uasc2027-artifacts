# OpenSSL RSA-2048 private-key leak (rootless ROP + Spectre-v4, BTB channel)

A no-canary stack overflow in a victim process drives a ROP chain built entirely from the
victim's own libcrypto gadgets (a build compiled without branch protection, so classic ROP
gadgets remain). The chain opens a Spectre-v4 store-bypass window and
speculatively branches to a target carrying one secret bit in its high field: a **canonical**
target allocates a BTB entry, a **non-canonical** one is fast-rejected. The attacker reads that
1-bit oracle over a BTB Prime+Probe channel timed by the rootless `cntvct_el0` counter (no PMU,
no driver, no root) and sweeps every bit of the RSA private exponent `d` out of the child's live
`EVP_PKEY` heap. The child builds a genuine 2048-bit key in its own memory, and the leak path never
reads it. A side pipe hands the attacker the child's heap address of `d` (an assume-known-target
simplification: the leak recovers the bit *values*, not their location) together with the ground
truth used only to score.

## Layout

| file | role |
|------|------|
| `victim.c`   | the target: the `read()` overflow, and the real RSA key it builds |
| `attacker.c` | the leak: the BTB Prime+Probe channel, delivery, and per-bit measurement |
| `donor.c`    | glue: dlopen libcrypto, verify gadgets, resolve the OpenSSL API, build the ROP payload |
| `scoring.c`  | the public-key corrector and the RSA-inversion proof, plus the scoring pipe (d's heap address + ground truth), which is **not** the attack |
| `main.c`     | CLI, fork wiring, the bit-leak loop, the corrector call, the report |

## Build & run

```
make
taskset -c 1 ./rsa_leak --samples 1500 --cpu 1
```

- `--samples N` - prime/probe iterations averaged per secret bit (default 1500). Each shot is noisy
  across a cross-process context switch, so many are averaged per bit. At `--samples 1500` the full
  key takes about 3 hours at ~0.19 bits/s. Higher counts raise per-bit accuracy.
- `--cpu N` - core to pin both processes to (they must share a core, use an isolated one).
- `--save FILE` - also write the per-limb progress and final report to FILE.

No environment variables. `--help` lists the flags.

## Expected output (measured, Neoverse N3, `--samples 1500`)

```
==== KEYLEAK AGGREGATE ====
  bits 2047/2048 = 99.95%   limbs 31/32 exact   wall=10785.19s  0.190 bits/s
  corrector: 1 residual bit corrected via RSA inversion oracle
==== PRIVATE-KEY RECOVERY ====
  exponent hex exact-match : YES (full 2048-bit d recovered byte-exact)
  RSA inversion m==(m^e)^d mod n : YES, recovered exponent DECRYPTS -> genuine private key
```

The raw channel recovers 2047/2048 bits of `d` in about 3 hours. The corrector then ranks the bits by
the leak's per-bit decision confidence and flips the least-confident ones against the RSA inversion
oracle, recovering the exact exponent whenever at most 4 bits remain wrong. The self-check then
confirms the recovered `d` decrypts.

- **Raw leak 2047/2048 bits = 99.95%**, **31/32** 64-bit limbs exact, wall time **3.00 h**, **0.190 bits/s**.
- **Corrected key byte-exact**, RSA inversion passes.

## Donor

Two files ship in `donor/` next to the binary and are loaded from there at runtime (resolved
relative to the executable, so the working directory does not matter):

- `libcrypto.so.3` - stock OpenSSL 3.5.6, built with branch protection disabled, supplies both the ROP gadgets and the OpenSSL API.
  SHA-256 `5f0979383a385b1a88a0c36f79dfbbcbd203e7129a0900ca4094177303a72e39`, upstream source: <https://github.com/openssl/openssl/releases/tag/openssl-3.5.6>.
- `ovf_openssl_v3_template.bin` - the ROP chain, relocated to the donor's runtime base.

The shipped `libcrypto.so.3` was built from the OpenSSL 3.5.6 source with:

```
export SOURCE_DATE_EPOCH=$(date -u -d "2026-08-26 17:33:52 UTC" +%s)
./Configure linux-aarch64 enable-shared no-pie -mbranch-protection=none \
            --prefix=/usr --openssldir=/usr/lib/ssl
make build_libs
```

The gadget offsets in `donor.c` are specific to this build. `donor.c` verifies each gadget's
first opcode at startup and aborts if the donor does not match, so a rebuilt donor is usable only
if it reproduces the same offsets.

## ROP chain

Every gadget is an instruction sequence found within the OpenSSL library itself (a libcrypto
build compiled without branch protection). The overflow only supplies the return addresses and
the data words between them.
The load-bearing steps, in the order they run:

| gadget | instruction | why it is there |
|--------|-------------|-----------------|
| `G_DEREF`   | `ldr x0, [x0]`          | read one secret word out of the child's live key heap into x0 |
| `G_AND`     | `and x0, x0, x19`       | mask x0 down to the single bit currently being guessed (x19 = the bit mask) |
| `G_CSEL` + `G_ADD` | `csel x0, x19, xzr, ne` then `add x0, x0, x19` | turn that one bit into a branch target whose high field is canonical for one value of the bit and non-canonical for the other |
| `OPENER`    | `ldr x0, [x19]`         | a load that bypasses a just-issued slow store: this is the Spectre-v4 store-bypass window, so everything after it runs speculatively |
| `TRANS_BLR` | `blr x0`                | the transmit, a speculative indirect branch to x0. A canonical target allocates a BTB entry, a non-canonical one is fast-rejected |

So the chain reads a secret word, collapses it to one bit, encodes that bit into the canonicality
of a branch target, opens a store-bypass window, and takes an indirect branch to that target - the
1-bit oracle the attacker then reads over the BTB. The remaining gadgets are plumbing: they reload
x0/x19 between steps and, via `PIVOT` (`mov sp, x29`), reanchor the stack in the donor `.bss` so
each bit reuses an identical frame and loops back into the victim.
