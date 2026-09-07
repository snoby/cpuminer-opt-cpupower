# CivicLight (yespower 1.0) GPU Miner — Implementation Plan (Rev 2)

**Goal:** Port the civiclight yespower-1.0 (N=2048, r=8) hashing to CUDA for
both the RTX 5090 (sm_120, 32GB GDDR7) and A100-class cards (sm_80, 64GB HBM2e),
with the PRIMARY objective being **latency hiding** of the memory-hard smix random-access
pattern.

**Why GPU:** civiclight is memory-latency-bound. On CPU, the 7950X3D wins by hiding
2MB-scratchpad random access in L3 at 5 GHz (~1660 H/s/core). A GPU hides latency with
sheer warp concurrency: many warps each walk independent scratchpads in VRAM, overlapping the
random `V[j]` loads. The A100's 64GB HBM2e and the 5090's 32GB both hold far more
concurrent scratchpads than any CPU. This is the textbook latency-hiding regime.

---

## 1. Algorithm Recap & Memory Footprint

CivicLight v2 = `SHA256(header) -> yespower-1.0(N=2048, r=8, pers=NULL)`.

Per-hash memory (from `algo/yespower/yespower-opt.c`):
- `V` scratchpad: `128 * r * N` = `128*8*2048` = **2,097,152 B = 2 MB** (dominant)
- `B` (128r) = 1 KB, `XY` ≈ 2 KB, S-box `S` ≈ 96 KB (3 × 32 KB) — negligible vs V

Per-hash working set: **2 MB** (1-way). 2-way interleave doubles it to 4 MB.

**Bandwidth ceiling (optimistic traffic-floor estimate, NOT a hard wall):**
Each hash does ~2 MB written (smix1 fill V) + ~0.67 MB read (smix2, 1/3 of V) ≈ **2.7 MB VRAM traffic**.
- 5090 (~1.8 TB/s): optimistic ~660K H/s at 100% BW
- A100 (~2.0 TB/s): optimistic ~740K H/s at 100% BW
- Realistic 25-40% efficiency (incl. write-allocate, sector/replay overhead, aux traffic,
  clock variation): **~165-300 K H/s per GPU** — vs 27 kH/s on the 7950X3D.
- Treat these as upper-bound targets, not guarantees.

**CORRECTED occupancy framing (Rev 2):** The limiting resource is NOT raw VRAM capacity
(it dwarfs any scratchpool we'd use). The limiting resource is **resident warps per SM**,
bounded by registers and shared memory — NOT the 16K/32K scratchpad counts. The earlier
"concurrent scratchpads" table overstated the design; what matters is active warps × scratchpad
per active context, sized to fit the achievable occupancy.

---

## 2. Target Hardware Profiles

### RTX 5090 (sm_120, Blackwell)
- 32 GB GDDR7, ~1.8 TB/s, 128 SMs, 64K regs/SM, ~228 KB shared/SM
- Memory-bound; tune independently (different shared/reg limits than sm_80)

### A100 64GB (sm_80, Ampere)
- 64 GB HBM2e, ~2.0 TB/s, 108 SMs, 64K regs/SM, 164 KB shared/SM
- Best scratchpad capacity; also memory-bound
- **Requirement: identify the EXACT A100 SKU** (A100-40GB vs A100-80GB vs SXM vs PCIe —
  bandwidth and SM count differ; "64GB HBM2e" must be confirmed per card)

---

## 3. Kernel Design — Latency-Hiding First

### 3.1 Thread-to-hash mapping — WARP-PER-HASH is the PRIMARY baseline

**Primary: warp-per-hash.** One warp (32 threads) cooperatively walks one hash's 2 MB
scratchpad. Rationale (per Codex review):
- Scratchpad cost is 2 MB per hash-warp, a practical resident population.
- The smix2 dependent-load chain is serialized WITHIN a warp, but latency is hidden ACROSS
  warps (the scheduler switches warps while one waits on `V[j]`).
- Warp-per-hash lets each warp issue wide coalesced-ish loads across its 32 lanes for the
  2r-blocks, improving sector utilization vs scattered per-thread 64-byte reads.

**Comparison: thread-per-hash** (1 thread = 1 hash, 2 MB/thread). Retain as an
experimental alternative. It maximizes warp count but each lane does isolated random 64-byte reads
(uncoalesced). **Measure both; warp-per-hash is the baseline.**

### 3.2 Persistent / bounded kernel with grid-stride nonce loop

Use a **bounded persistent kernel or long batch loop** (NOT an infinite kernel just to avoid
launch overhead):
```
civiclight_kernel(header, target, scratchpool, nonce_base, batch_len, ...):
    wid = global warp id
    scratch = &scratchpool[wid * SCRATCH_BYTES]   # 2 MB per warp (warp-per-hash)
    for nonce in (nonce_base + wid; nonce < nonce_base + batch_len; nonce += total_warps):
        hash = civiclight_powhash80(header, nonce, scratch)
        if hash < target: atomic hit-record
```
- Launch config: **resource-constrained**, chosen by measurement (registers, shared mem,
  warps/SM), NOT an arbitrary "1 block/SM" or "max occupancy" preset.
- Include: scratchpad per active context, job-generation/restart checks, atomic/bounded hit
  reporting, nonce-overflow handling, and watchdog-safe batches (esp. display-attached 5090).

### 3.3 Two-way interleave — EMPIRICAL, not prescriptive

The earlier "2-way ON for 5090, OFF for A100" is NOT sound. 2-way doubles scratchpad and
registers, may cut occupancy. With warp-per-hash, scheduler-level interleaving already supplies
latency hiding, so intra-thread 2-way may add little. **Make 2-way a compile-time option
(`-DCIVIC_2WAY`) selected by measurement, not by GPU class.**

### 3.4 Memory access & prefetch (corrected)

- **Coalescing:** random `V[j]` accesses are inherently uncoalesced across warps. With
  warp-per-hash, the 32 lanes read the 2r-block cooperatively → better sector utilization.
- **Prefetch:** prefetching the NEXT `V[j]` one blockmix step ahead is largely IMPOSSIBLE —
  `j` is data-dependent on the current blockmix result. Only **intra-block prefetch** (within
  the current 1 KB block) is testable. Measure, don't assume.
- **S-box:** a 96 KB shared-memory S-box is NOT free — it can cut blocks/SM and add bank
  conflicts on sm_80. Compare shared vs constant/read-only-cache vs L2-resident variants.
- **`__ldg`:** not a universal win; verify generated transactions on each arch.

---

## 4. Implementation Phases

### Phase 0 — Feasibility spike (VALIDATE, with real pattern + correctness)
- **Step 0a:** Identify the EXACT GPU SKUs (A100-40GB/80GB, SXM/PCIe; 5090) and record
  clock, ECC state, thermal/watchdog conditions for reproducible bandwidth results.
- **Step 0b:** Complete-chain correctness-checked hash kernel (warp-per-hash) — must match
  the FULL civiclight chain `SHA256d(header80) -> SHA256 -> yespower-1.0 -> XOR -> SHA256`
  bit-exact vs `test_civiclight_differential.c` for 10K random nonces.
- **Step 0c:** Real-pattern bandwidth measurement (fill V + smix2 read of V) on BOTH GPUs.
- **Gate:** GO only if (1) full-chain correctness passes, AND (2) achieved BW suggests
  meaningful CPU-beating H/s. Synthetic-only traffic is insufficient.
- **Batch-size sweep:** specify initial batch-length sweep + max watchdog-safe duration; poll
  restart/job-generation state between hashes at a bounded interval.

### Phase 1 — Correct 1-way warp-per-hash kernel
- Port civiclight_powhash80 → CUDA (warp-per-hash), grid-stride batch loop.
- Verify bit-exact vs `test_civiclight_differential.c` for 10K random nonces.

### Phase 2 — Occupancy & bandwidth tuning (THE latency-hiding phase)
- Sweep blocks/SM and warps/SM by register cap / shared-mem carveout (measured, not preset).
- Nsight metrics: achieved DRAM BW %, sectors/request, replay overhead, active warps/SM,
  shared-bank conflicts, L2 hit rate.
- Tune sm_80 and sm_120 SEPARATELY.

### Phase 3 — 2-way interleave (empirical variant)
- `-DCIVIC_2WAY`, compare vs 1-way after occupancy measurement. Adopt only if it wins.

### Phase 4 — Integration
- Stratum client (reuse cpuminer/ccminer stratum), share submission, difficulty.
- Multi-GPU (5090 + A100 fleet).

### Phase 5 — Production hardening
- Hit recording, job rotation, sticky-nonce, watchdog, logging discipline (1 line/iter).

---

## 5. Verification Strategy

- **Correctness:** differential vs CPU `civiclight_hash_v2`, 10K random nonces, bit-exact.
- **Live pool proof:** real share to `lab.viporlab.net:5090` (definitive end-to-end test).
- **Perf:** Nsight Compute — confirm memory-bound (DRAM throughput) + active warps/SM.

---

## 6. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Bandwidth-bound below CPU parity | High | Phase 0 spike with real pattern gates investment |
| Random access defeats coalescing | Med | Warp-per-hash cooperative 2r-block loads |
| Register/shared pressure cuts occupancy | Med | Resource-constrained launch, 1-way first |
| Correctness drift from CPU ref | High | Differential test + live pool proof |
| Unknown exact A100 SKU | Med | Identify exact SKU before tuning |

---

## 7. Success Criteria

- **Correctness:** 100% match vs CPU ref; live pool share accepted.
- **Performance:** ≥ 60 kH/s on 5090, ≥ 100 kH/s on A100 (conservative vs ~740K theoretical;
  anything ≥ 3× the 7950X3D's 27 kH/s is a win).
- **Latency hiding demonstrated:** Nsight shows high DRAM throughput + high active warps/SM.

---

## 8. Open Questions for Review

1. Warp-per-hash confirmed as primary (Codex GO). Hybrid (warp-per-hash smix2 / thread-per-hash
   smix1) is a Phase 2 experiment, not a blocker.
2. **Exact A100 SKU(s) must be identified** before Phase 2 tuning (precondition).
3. Phase 0 now REQUIRES the full correctness-checked hash (resolved per Codex).
4. Bounded batch loop resolved (per Codex); batch-length sweep specified in Phase 0.
