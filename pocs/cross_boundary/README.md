# Unified speculative PAC leak (`cross_boundary`)

One binary recovers the 7-bit pointer-authentication field [54:48] of a signed pointer through two
speculative mechanisms, selected by `--switch`, across isolation boundaries, media, and read-out
timers. Each round the victim signs a pointer with a fresh key and, inside one Spectre-v4
store-bypass window, forms an address from the signature and accesses it. One field bit decides
whether the address stays in range (a microarchitectural footprint) or falls out of range (fast
rejected). The attacker reads that footprint through the chosen medium and timer and sweeps the
seven bits.

The window is speculative, so the out-of-range address is never architecturally dereferenced and
never faults. `--control barrier` resolves the store before the access, which closes the window and
drops the recovery to chance.

## The two switches

- `canon` applies only an AND mask to the signature in place. The mask keeps bit 48+b and clears
  the rest of the field, so field bit b at 0 leaves the address canonical and at 1 leaves a lone set
  bit above the 48-bit virtual address, which is non-canonical and fast rejected.
- `aut` extracts field bit b, places it at bit 55, and authenticates. Bit 55 clear keeps the pointer
  in the user half and set sign-extends it into the kernel half, which is fast rejected.

## Matrix

`same`, `xthread`, and `xel` carry both switches on the cache and TLBs. `xproc` and `xvm` carry the
canonicality leak on the branch-target buffer. The branch-target buffer allocates for any canonical
target regardless of range, which the canonicality leak uses, whereas the AUT* leak needs the cache
and TLBs that gate on an in-range access. The command refuses a non-physical cell and prints the
hardware reason.

| boundary | l1d | dtlb | itlb | btb |
|---|---|---|---|---|
| same (one thread)            | aut, canon | aut, canon | aut, canon | — same-address-space branch eviction reads at chance |
| xthread (two threads, one core) | aut, canon | aut, canon (bit 48, 100%) | aut, canon | canon |
| xproc (forked victim)        | canon | — TLBs are per-core and address-space tagged | — same | canon |
| xel (EL2 module)             | — | aut, canon (bit 48, 100%) | aut | — |
| xvm (KVM guest)              | — | — | — | canon |

Across a boundary the speculative dTLB fill checks only bit 48, so the canonicality leak over the
dTLB recovers bit 48 there while the AUT* leak recovers the whole field through bit 55.

## Measured channel rates

Measured on a Neoverse N3, one isolated core, as the median of 20 runs. Per-bit error rate and
throughput for the canonicality switch. The AUT* switch gives essentially the same rates on the same
channels, and the branch-target buffer carries only the canonicality switch.

| boundary | medium | timer  | per-bit error | bits/s |
|----------|--------|--------|---------------|--------|
| xthread  | dtlb   | pmu    | 0%            | 3922   |
| xthread  | dtlb   | cntvct | 24%           | 144    |
| xthread  | itlb   | pmu    | 37%           | 12856  |
| xthread  | itlb   | cntvct | 3%            | 1269   |
| xthread  | btb    | pmu    | 0%            | 450    |
| xthread  | btb    | cntvct | 31%           | 6      |
| xproc    | dtlb   | pmu    | 49%           | 7978   |
| xproc    | dtlb   | cntvct | 51%           | 1613   |
| xproc    | itlb   | pmu    | 48%           | 1501   |
| xproc    | itlb   | cntvct | 49%           | 1080   |
| xproc    | btb    | pmu    | 4%            | 10980  |
| xproc    | btb    | cntvct | 0%            | 18     |
| xel      | dtlb   | pmu    | 0%            | 3922   |
| xel      | dtlb   | cntvct | 31%           | 97     |
| xel      | itlb   | pmu    | 0%            | 109120 |
| xel      | itlb   | cntvct | 1%            | 1400   |
| xel      | btb    | pmu    | 100%          | 0      |
| xel      | btb    | cntvct | 100%          | 0      |
| xvm      | dtlb   | pmu    | 48%           | 155    |
| xvm      | dtlb   | cntvct | 48%           | 23     |
| xvm      | itlb   | pmu    | 49%           | 1685   |
| xvm      | itlb   | cntvct | 45%           | 169    |
| xvm      | btb    | pmu    | 10%           | 120    |
| xvm      | btb    | cntvct | 0%            | 11     |

## Build

```
make                               # cross_boundary and guest.elf
make module                        # aut_xel.ko, against KDIR
sudo insmod ../common/raw_pmu.ko   # grants the attacker the PMU read-out
sudo insmod aut_xel.ko             # xel only
sudo chmod 666 /dev/aut_xel        # xel only
```

The kernel module is specific to the running kernel and builds against
`/usr/src/linux-headers-$(uname -r)`. The PMU timer needs `raw_pmu.ko`. The cntvct timer needs
neither root nor a module. `xvm` needs `/dev/kvm`.

## Run

```
./cross_boundary --switch canon --boundary same    --medium l1d  --timer pmu    --cpu 90 --rounds 20 --samples 2
./cross_boundary --switch aut   --boundary xthread --medium dtlb --timer pmu    --cpu 90 --rounds 20 --samples 6
./cross_boundary --switch canon --boundary xproc   --medium btb  --timer pmu    --cpu 90 --rounds 20 --samples 20
./cross_boundary --switch aut   --boundary xel     --medium itlb --timer pmu    --cpu 90 --rounds 20 --samples 6
sudo ./cross_boundary --switch canon --boundary xvm --medium btb --timer cntvct --cpu 90 --rounds 20 --samples 300
```

`--help` lists every option and one example per boundary. Every argument is explicit. The scoreboard
prints one line per round and a summary with the per-bit rate, the full-field rate, and the
throughput, and `--save FILE` also writes it to a file.

## Expected output

A round prints the signed field, the recovered field, and the matching bits, followed by the per-bit
rate, the full-field rate, and the throughput.

```
    0  | secret=0x53  recovered=0x53  7/7  WIN
    1  | secret=0x0d  recovered=0x0d  7/7  WIN
    2  | secret=0x15  recovered=0x15  7/7  WIN
    3  | secret=0x5f  recovered=0x5f  7/7  WIN
    4  | secret=0x46  recovered=0x46  7/7  WIN
    5  | secret=0x40  recovered=0x40  7/7  WIN
    6  | secret=0x60  recovered=0x60  7/7  WIN
    7  | secret=0x76  recovered=0x76  7/7  WIN

canon PAC leak : same thread (EL0), L1D medium, pmu timer
  per-bit rate : 56/56 bits (100.00%)
  full PAC rate: 8/8 rounds (100.0%)
  throughput   : 23070 bits/s
```
