# civiclight CPU 2-way: benchmark + profiling + prefetch findings (2026-08-18)

Machine: AMD Ryzen 9 7950X3D (16 physical cores, dual CCD), 2-way kernel,
`-t 16`, uncontended (production miners stopped during measurement).

## Headline numbers (uncontended, steady-state)
| config | total kH/s | per-core H/s |
|---|---|---|
| baseline (no V[j] prefetch) | 26.4 - 26.9 | ~1650-1680 |
| **+ T0 1-ahead V[j] prefetch (smix1)** | **27.2 - 27.5** | **~1700-1720** |

The 2-way IS the ~28k path. Earlier "12.4 kH/s" readings were contamination:
the two production instances were running simultaneously, saturating all 16
physical cores, so single-instance benchmarks measured leftover capacity.

## Where the time goes (perf, uncontended, 16 threads)
```
yp2_blockmix_xor        72.4%   (smix2 random V[j] read + Salsa20/2)
yp2_blockmix_xor_save  24.7%   (smix1 fill, random V[j] read + write)
yespower_2way_fixed     2.0%
SHA256_Transform       ~0.5%
```
~97% in blockmix. Memory-bound on the random V[j] scratchpad access
(L1-dcache-load-misses dominate; IPC ~2.67; frontend stalls <1%).
This is inherent to yespower's memory-hard random walk over the 2MB scratchpad.

## Experiments tried (all A/B on this chip)
| change | result | verdict |
|---|---|---|
| T0 1-ahead prefetch of V[j] in smix1 | 26.9 -> 27.4 kH/s | **KEEP (+2%)** |
| same prefetch in smix2 (xor_save) | no gain, slightly worse | reject |
| 2-ahead distance | 27.4 (same) | reject (extra instr, no win) |
| T1 hint vs T0 | 27.4 (same) | reject (T0 simpler) |
| AVX512VL `_mm256_rol_epi32` | SLOWER than AVX2 shift/xor on Zen4 | reject |
| NT-store on V-fill | known loss at r=8 (L3-resident, not DRAM) | reject |
| 4-way / wider SIMD | working set 8MB/thread > L2/L3 budget | reject |

## Why the winners/losers
- Prefetch helps ONLY in smix1: it has two interleaved lanes, so the prefetched
  load overlaps the other lane's independent work. smix2 is a tight dependent
  do/while with nothing to hide behind -> prefetch just adds instructions.
- AVX512VL is slower on Zen4: `vprold` runs on the 256-bit datapath with worse
  latency than AVX2 shift/xor. (Verified microbench: 1.508s vs 1.398s.)
- NT-store at r=8: 2MB scratchpad is L3-resident, not DRAM-streaming. NT-store
  machinery is built for r=32/8MB DRAM and hurts here.

## Current state
- Change in working tree: `algo/yespower/yespower-opt.c` (T0 1-ahead V[j]
  prefetch in the 2-way smix1 loop, 2 `_mm_prefetch` calls).
- Prefetch is a cache hint only -> correctness unchanged (hash identical).
- Backup of pre-prefetch file: /tmp/yespower-opt.c.prefetch_backup
- Production miners were STOPPED for these measurements and NOT relaunched.
