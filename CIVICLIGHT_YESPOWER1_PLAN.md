# YESPOWER 1.0 and Civiclight v2 implementation plan

## Scope and non-goals

This document plans two related changes on branch `feat/civiclight-yespower1`:

1. expose and verify canonical Openwall YESPOWER 1.0 in the existing `algo/yespower/` core; and
2. add CivicNet's Civiclight v2 proof-of-work as `-a civiclight` by reusing that core.

This is an implementation plan only. It does not contain production changes. Consensus output must be derived from and tested against pinned upstream sources before any pool or mainnet use.

Authoritative references:

- Openwall yespower project and parameter guidance: <https://www.openwall.com/yespower/>
- Openwall 1.0.1 release archive: <https://download.openwall.net/pub/projects/yespower/yespower-1.0.1.tar.gz>
- Openwall reference/optimized sources and official vectors: <https://github.com/openwall/yespower>
- CivicNet v2 core: <https://github.com/CivicLight/CivicNet/blob/master/src/crypto/civiclight_hash.cpp>
- CivicNet `CBlockHeader::GetPoWHash()` caller: <https://github.com/CivicLight/CivicNet/blob/master/src/primitives/block.h>
- CivicLight's published cpuminer implementation: <https://github.com/CivicLight/civiclight-miner-windows/tree/main/cpuminer-opt-source/algo/civiclight>

## Findings that drive the design

### Current repo path

- `algo/yespower/yespower.h` exposes `YESPOWER_0_5 = 5` and `YESPOWER_0_9 = 9` only.
- `algo/yespower/yespower-opt.c` recursively compiles two passes. Pass 1 is 0.5; pass 2 is named `*_0_9` and is the only non-0.5 path called by `yespower()`.
- `algo/yespower/yespower.c` selects parameter presets with global `verstring`, hashes through `yespower_tls()`, and scans 80-byte headers in `scanhash_yespower()`.
- `algo/yespower/yespower-platform.c` owns aligned/thread-local allocation and explicit 2 MiB `MAP_HUGETLB` allocation with normal-page fallback.
- `Makefile.am` already builds `yespower.c`, `sha256-P.c`, and `yespower-opt.c`.
- `miner.h` owns the algorithm enum, parallel `algo_names[]` array, and CLI help. `algo-gate-api.c` owns the registration switch.
- This checkout's `yespower-opt.c` directly uses x86 intrinsics (`__m128i` and related operations); it does not include `simd-utils.h` or `simd-128.h`. The current optimized binary nevertheless contains AVX512VL `vprold xmm,...` instructions. Preserve the actual intrinsic/compiler path and verify the emitted instructions; do not assume a source include that is not present.

### 0.9 versus canonical 1.0

The local 0.9-labeled pass is the prerelease naming of the mechanics published as yespower 1.0, not a different parameter set that needs to be invented. Source comparison gives the following result:

| Property | Local `*_0_9` pass | Canonical YESPOWER 1.0 | Required action |
|---|---:|---:|---|
| public version value | 9 | 10 | retain 9; add 10 |
| S-box width | 11 | 11 | no numeric change |
| S-box regions | 3 x 32 KiB | 3 x 32 KiB | no numeric change |
| Salsa in non-0.5 pass | Salsa20/2 | Salsa20/2 | no numeric change |
| pwxform | 3 logical rounds with writes and S0/S1/S2 rotation | same | rename/generalize, then prove equivalence |
| SMix seed expansion for `r > 1` | present | present | preserve |
| `Nloop_rw` | `(N+2)/3`, rounded up to even | same | preserve |
| non-0.5 PBKDF2/HMAC glue | 128-byte PBKDF2 then final HMAC | same | preserve |
| error output | may leave `dst` unchanged | 1.0.1 fills `dst` with `0xff` | add fail-safe behavior |

Therefore, the implementation should share one optimized non-0.5 pass between legacy enum value 9 and canonical enum value 10, but accept that equivalence only after the differential tests below pass. Do not duplicate the full SIMD core merely to change symbol suffixes.

The larger contrast is between 0.5 and 1.0. Keep that distinction explicit in comments and tests so future work does not accidentally route 0.5 into the 1.0 path.

### CivicNet has two hashing layers

The supplied `civiclight_hash_v2(input, len, output)` function is the v2 core. CivicNet's actual `CBlockHeader::GetPoWHash()` first serializes the six standard header fields, computes `SHA256d(header80)`, and passes that 32-byte `uint256` buffer to the v2 core.

Thus the full current-network PoW path is:

```text
serialized 80-byte header
  -> SHA256d(header80)                         [CivicNet GetPoWHash outer layer]
  -> hash1 = SHA256(previous 32 bytes)         [civiclight_hash_v2]
  -> yp = yespower-1.0(hash1, N=2048, r=8,
                       pers=NULL, perslen=0)
  -> xor_buf = yp XOR hash1
  -> SHA256(xor_buf)
  -> 256-bit PoW value checked against target
```

This distinction is consensus-critical. Calling the v2 core directly on the raw 80-byte header would not match CivicNet. Keep separate function names for the core and the header-level PoW wrapper.

The requested scope is Civiclight v2. Do not silently add Civiclight v1 or timestamp activation policy to `-a civiclight`. If historical pre-fork support is later required, add it as a separately reviewed requirement using CivicNet's activation time and v1 algorithm.

## Part A: implement and expose YESPOWER 1.0

### A1. File changes

Modify:

- `algo/yespower/yespower.h`
  - add `YESPOWER_1_0 = 10` while retaining `YESPOWER_0_5 = 5` and `YESPOWER_0_9 = 9`;
  - keep `yespower_params_t` ABI/layout unchanged;
  - document value 9 as the fork's legacy prerelease selector and value 10 as the canonical selector;
  - optionally expose a miner-private max-target helper only if Civiclight reuses it; do not mix algo-gate types into the standalone core API.
- `algo/yespower/yespower-opt.c`
  - sync the algorithm-bearing non-0.5 path to pinned Openwall 1.0.1 semantics;
  - generalize or rename `Swidth_0_9`, `Smask2_0_9`, and `smix_0_9` to `*_1_0` (or an explicitly shared `*_0_9_1_0` name);
  - accept versions 5, 9, and 10 in parameter validation;
  - route 9 and 10 through the same proven-equivalent optimized pass;
  - add Openwall 1.0.1's failure behavior: initialize/fill `dst` with `0xff` on invalid parameters or allocation failure;
  - preserve local prefetches, compiler/intrinsic tuning, TLS allocation, and platform include;
  - avoid wholesale replacement with unoptimized `yespower-ref.c`.
- `algo/yespower/yespower-ref.c`
  - update the readable oracle to accept `YESPOWER_1_0` and, if legacy testing is desired, map `YESPOWER_0_9` to the same 1.0 behavior;
  - keep it out of the production link because it defines the same public symbols;
  - use it in a separate test executable for differential testing.
- `algo/yespower/yespower.c`
  - add a named preset for plain 1.0: `{ YESPOWER_1_0, 2048, 8, NULL, 0 }`;
  - extend `yespower_hash()` dispatch with a named variant constant instead of another unexplained integer where practical;
  - add `register_yespower1_algo()` and set the selector to the new preset;
  - leave all existing 0.9 presets and registrations unchanged to prevent regressions in Cranepay/Yenten/CPUchain/UraniumX/Sugarchain/LightBit/Intercoin behavior.
- `miner.h`
  - add `ALGO_YESPOWER1` before `ALGO_COUNT`;
  - add exactly one matching `"yespower1"` entry at the same ordinal in `algo_names[]`;
  - add `yespower1  Openwall yespower 1.0 (N=2048,r=8,no personalization)` to CLI help.
- `algo-gate-api.h`
  - declare `register_yespower1_algo(algo_gate_t *)` after `algo_gate_t` is defined; this avoids relying on the repo's suppressed implicit-declaration warnings.
- `algo-gate-api.c`
  - add `case ALGO_YESPOWER1: register_yespower1_algo(gate); break;`.
- `Makefile.am`
  - no production core source is needed if 1.0 shares `yespower-opt.c`;
  - add test targets described below;
  - regenerate checked-in `Makefile.in` with the repo's Autotools flow rather than hand-maintaining divergent source lists.

Do not add a copied `algo/yespower1/` directory. A second allocator, SHA implementation, or static yespower core would risk symbol collisions, output drift, and twice the optimization maintenance.

### A2. Exact YESPOWER 1.0 behavior to preserve

#### Parameter validation

- `N` is a power of two in `[1024, 512*1024]`.
- `r` is in `[8, 32]`.
- There is no public `p`; yespower fixes parallelism to one lane.
- `pers == NULL` is valid only when `perslen == 0`.
- A non-NULL personalization is a byte string; do not use `strlen()` inside the core.
- Integer overflow must be checked before computing or allocating `128*r*N` and the combined scratch size.
- Invalid input returns `-1`, sets `errno = EINVAL` where appropriate, and leaves an all-ones destination so a neglected return check cannot create a false low hash.

#### SHA/PBKDF2/HMAC glue

For versions 9 and 10, preserve the canonical successful path:

1. `sha256 = SHA256(src[0..srclen-1])`.
2. Select PBKDF2 salt as `pers/perslen`, or the empty string when `pers == NULL`.
3. Run PBKDF2-HMAC-SHA256 with password `sha256`, one iteration, and output length exactly 128 bytes into the start of `B`. `PBKDF2_SHA256_P` is an optimized equivalent and may remain if vectors prove it.
4. Copy the first 32 bytes of `B` back to the saved `sha256` buffer.
5. Run the 1.0 SMix path over logical `B_size = 128*r` and `V_size = 128*r*N`.
6. Produce `dst = HMAC-SHA256(key=B+B_size-64, keylen=64, message=saved_sha256, messagelen=32)`.

Do not use the 0.5 glue for 1.0. Version 0.5 PBKDF2-fills all `B_size`, uses its own SMix pass, finishes with PBKDF2 over `B`, and applies personalization as a separate HMAC/SHA stage.

#### 1.0 cache and mixing behavior

- `PWXsimple = 2`, `PWXgather = 4`, and `PWXbytes = 64` remain fixed algorithm constants.
- `Swidth_1_0 = 11` makes each S region `2^11 * 2 * 8 = 32,768` bytes.
- Allocate three regions (`S0`, `S1`, `S2`), total 98,304 bytes. This is the CPU-L2-heavy state that distinguishes 1.0 from 0.5's two 4 KiB regions.
- The 1.0 pwxform performs three logical rounds. During the write schedule it updates S0/S1, advances/wraps `w`, and rotates `(S0,S1,S2)`; preserve exact write order and masking.
- Use Salsa20/2 in the 1.0 pass. Keep Salsa20/8 for 0.5.
- Preserve the 1.0 `smix1()` sequential expansion from the first 128-byte block across `r` before the main memory fill.
- Preserve wrap/integerify behavior, read/write versus non-save BlockMix selection, and the final possible two-loop SMix2 call.
- For 1.0, `Nloop_all = ceil(N/3)` rounded up to even and `Nloop_rw = ceil(N/3)` rounded up to even. Do not apply 0.5's round-down rule to `Nloop_rw`.

#### Scratch sizing and lifecycle

For version 1.0:

```text
B_size  = 128*r
V_size  = 128*r*N
XY_size = 128*r + 64
S_size  = 3 * 32768 = 98304
need    = 128*r*N + 256*r + 64 + 98304
```

For CivicNet's `N=2048,r=8`, `need` is 2,197,568 bytes (2.095764 MiB), while the dominant V array alone is 2 MiB. Under this repo's explicit 2 MiB `MAP_HUGETLB` allocator, the mapping is rounded up to 4 MiB. Report these separately in diagnostics so “2 MiB yespower” is not mistaken for exact mapped RSS.

Keep one `yespower_local_t` per thread and reuse its allocation. `yespower_tls()` already provides that behavior. Never allocate/free the 2+ MiB region inside the nonce loop.

### A3. SIMD, hugepage, and TLB preservation

- Start from a source diff against Openwall 1.0.1, then reapply only this repo's measured local changes. Keep an audit note for every algorithm-bearing deviation.
- Keep the recursive two-pass compilation model so 0.5 remains Salsa20/8 and the shared 0.9/1.0 pass remains Salsa20/2.
- Preserve the 128-bit X0..X3 pwxform and Salsa operations, the scalar/SIMD balance, prefetch behavior, and any AVX2-assisted loads/XORs that are actually reachable.
- Build the same compiler/ISA variants currently used by the project and compare disassembly. For the AVX512VL build, require `objdump -d -M intel ./cpuminer | rg 'vprold'` to show packed 128-bit rotates in the yespower text range. Also verify the AVX2 and baseline SSE2 builds contain no unsupported instructions.
- Do not advertise runtime `AVX2_OPT`/`AVX512_OPT` gate capabilities unless there is a real runtime-dispatch build. Match the existing yespower gate flags (`SSE2_OPT | SHA_OPT`) until the build architecture is deliberately changed.
- Retain `algo/yespower/yespower-platform.c` as the single allocator: 64-byte alignment, `MAP_HUGETLB` attempt at/above 2 MiB, correct rounded `base_size` for `munmap()`, and 4 KiB/malloc fallback.
- Test both hugepage-success and fallback paths. A hugepage allocation failure must affect performance/logging only, never the hash output.
- Keep `yespower_local_t.aligned_size` as the requested usable size and `base_size` as the actual mapped size; this is necessary for correct reuse and unmapping.

### A4. Plain 1.0 algo-gate wiring

The new diagnostic/plain algorithm name is `yespower1`:

```text
-a yespower1
  -> ALGO_YESPOWER1
  -> register_algo_gate() case
  -> register_yespower1_algo()
  -> existing scanhash_yespower()
  -> yespower_hash() 1.0 preset
  -> yespower_tls(... YESPOWER_1_0, N=2048, r=8, NULL, 0 ...)
```

Registration should mirror existing yespower variants:

- `gate->scanhash = scanhash_yespower`;
- `gate->hash = yespower_hash`;
- `gate->get_max64 = yespower_get_max64`;
- `gate->set_target = scrypt_set_target`;
- `gate->optimizations = SSE2_OPT | SHA_OPT`.

Use a named internal variant enum or constants for all `verstring` values. At minimum, reserve a new value for the 1.0 preset and add a default/error path so an unknown selector cannot leave output uninitialized.

## Part B: Civiclight v2 requirements

### B1. New file layout

Add:

- `algo/civiclight/civiclight_hash.h`
  - declare `civiclight_hash_v2(const void *input, size_t len, void *output)` (or an error-returning equivalent);
  - declare the 80-byte `civiclight_powhash80()` helper;
  - declare the gate-compatible `civiclight_gate_hash()`, `scanhash_civiclight()`, and `register_civiclight_algo()` signatures.
- `algo/civiclight/civiclight_hash.c`
  - implement the v2 core exactly;
  - implement the outer `SHA256d(header80)` layer required by CivicNet's caller;
  - implement this repo's single-lane scanner and registration.

Reuse:

- `algo/yespower/yespower.h` and the Part A optimized core;
- `algo/yespower/sha256-P.h` / `SHA256_Buf()` for single SHA-256 operations;
- the existing global `sha256d()` declared by `miner.h` for the outer header hash, after a byte-for-byte vector confirms it matches CivicNet's `CHashWriter::GetHash()` output.

Do not copy CivicNet's yespower directory into `algo/civiclight/`, and do not use CivicLight's published per-hash `init_local/free_local` pattern. This repo's reusable TLS allocation is required for acceptable nonce-loop performance.

### B2. Exact v2 core

Implement `civiclight_hash_v2(input,len,output)` as:

1. `hash1 = SHA256(input[0..len-1])`.
2. Call `yespower_tls(hash1, 32, &params, &yp_out)` with a file-static constant:

   ```c
   { YESPOWER_1_0, 2048, 8, NULL, 0 }
   ```

3. Check the yespower return value. On failure, return an error and/or fill `output` with `0xff`; never continue with an uninitialized `yp_out`.
4. For each byte `i` in `[0,31]`, compute `xor_buf[i] = yp_out.uc[i] ^ hash1[i]`.
5. `output = SHA256(xor_buf, 32)`.

This is not plain yespower. It adds a SHA-256 prehash, XORs the yespower result with that prehash, and SHA-256-hashes the XOR. Also remember that yespower internally starts by SHA-256-hashing its own 32-byte input as part of canonical yespower.

Implement `civiclight_powhash80(header80,output)` as:

1. require exactly 80 serialized header bytes;
2. compute `raw_hash = SHA256d(header80)`;
3. call `civiclight_hash_v2(raw_hash, 32, output)`.

Keep these functions separately testable. The gate-facing hash callback must use this repo's output-first signature from `algo-gate-api.h`, not copy the different signature used by newer JayDDee forks.

### B3. 80-byte nonce scanner

Implement `scanhash_civiclight(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)` by mirroring `algo/yespower/yespower.c::scanhash_yespower()`:

1. allocate 64-byte-aligned `uint32_t vhash[8]` and `uint32_t endiandata[20]`;
2. set `pdata = work->data`, `ptarget = work->target`, `Htarg = ptarget[7]`, `first_nonce = pdata[19]`, and `n = first_nonce`;
3. once per work item, serialize words 0..18 with `be32enc(&endiandata[k], pdata[k])` so the byte buffer is the expected little-endian Bitcoin/Litecoin header serialization;
4. for each candidate, serialize the nonce with `be32enc(&endiandata[19], n)`;
5. call `civiclight_powhash80(endiandata, vhash)`;
6. accept only when the cheap high-word filter passes and the complete target comparison passes:

   ```text
   vhash[7] < Htarg && fulltest(vhash, ptarget)
   ```

7. on a solution, call `work_set_target_ratio(work, vhash)`, set `*hashes_done = n-first_nonce+1`, store `pdata[19] = n`, and return true;
8. otherwise increment until `n >= max_nonce` or `work_restart[thr_id].restart` is set;
9. on exhaustion, update `*hashes_done` and `pdata[19]` exactly like `scanhash_yespower()` and return false.

Add boundary tests for first nonce, `max_nonce-1`, immediate restart, an easy target that accepts the first hash, and a target whose high word passes but `fulltest()` rejects. The last case proves the scanner does not submit false shares.

### B4. Algo registration and build wiring

Modify:

- `miner.h`
  - add `ALGO_CIVICLIGHT` before `ALGO_COUNT`;
  - add `"civiclight"` at the identical `algo_names[]` ordinal;
  - add a CLI help line identifying CivicNet v2.
- `algo-gate-api.h`
  - declare `register_civiclight_algo(algo_gate_t *)`.
- `algo-gate-api.c`
  - add `case ALGO_CIVICLIGHT: register_civiclight_algo(gate); break;`.
- `Makefile.am`
  - add `algo/civiclight/civiclight_hash.c` to `cpuminer_SOURCES`;
  - optionally list the header for distribution completeness;
  - regenerate `Makefile.in` through Autotools.

`register_civiclight_algo()` should set:

- `gate->scanhash = scanhash_civiclight`;
- `gate->hash = civiclight_gate_hash`;
- `gate->set_target = scrypt_set_target`;
- a local `get_max64` equivalent to the existing yespower value, or the existing helper if cleanly exposed;
- `gate->optimizations = SSE2_OPT | SHA_OPT`, matching the reused core rather than claiming nonexistent runtime dispatch.

Civiclight must not use or mutate `verstring`; its parameters are fixed in its own wrapper and cannot be changed by registering another yespower preset.

## Verification plan

### V1. Pin and record upstream inputs

- Download Openwall `yespower-1.0.1.tar.gz`, verify its published signature, record its SHA-256, and keep the tarball outside production source or under test fixtures with license/provenance.
- Record the exact CivicNet commit/tag used to derive vectors, including `src/crypto/civiclight_hash.cpp` and `src/primitives/block.h`.
- Record the CivicLight miner commit only as a secondary interoperability reference; CivicNet node consensus is authoritative.

### V2. YESPOWER 1.0 unit and differential tests

Add a separate check executable under a new `tests/` directory (for example `tests/test_yespower1.c`) and wire it through `Makefile.am`'s `check_PROGRAMS`/`TESTS`.

Mandatory official vector:

- input is 80 bytes with `src[i] = i*3`;
- params are `{YESPOWER_1_0, 2048, 8, NULL, 0}`;
- expected output is:

  ```text
  69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46
  ```

Also import the remaining official 1.0 `TESTS-OK` vectors for `N/r` coverage, the personalization vector, and the aggregate XOR loop. Run the same input corpus through:

1. pinned Openwall `yespower-ref.c`;
2. pinned Openwall `yespower-opt.c`;
3. this repo's optimized core using version 10;
4. this repo's legacy selector 9 where equivalence is expected.

Require byte-for-byte equality for fixed and randomized inputs across `N={1024,2048,4096}`, representative `r={8,16,32}`, NULL/empty/non-empty personalization, and repeated calls that reuse TLS scratch. Add invalid-parameter tests for non-power-of-two N, out-of-range N/r, `NULL` plus nonzero `perslen`, allocation failure, and all-ones error output.

Build and run the vectors in baseline SSE2, AVX2, and AVX512VL configurations. Run ASan/UBSan on the smallest legal settings and a multithreaded test proving each thread has independent scratch and deterministic output.

Before/after regression vectors for all existing `verstring` presets are a merge gate. Version 0.9 outputs must not change.

### V3. Civiclight vectors and consensus comparison

Create `tests/test_civiclight.c` with two levels of vectors:

1. **Core vectors:** fixed 32-byte inputs passed directly to CivicNet's `civiclight_hash_v2()` and this repo's `civiclight_hash_v2()`. Record `hash1`, raw yespower output, XOR buffer, and final SHA-256 to localize mismatches.
2. **Header vectors:** fixed serialized 80-byte headers passed to CivicNet `CBlockHeader::GetPoWHash()` and this repo's `civiclight_powhash80()`. Record the outer SHA256d intermediate and final PoW bytes.

Include at least one real post-activation CivicNet block header, one synthetic header with nonce zero, and the same header at adjacent nonces. Store both raw 32-byte output order and human-displayed reversed `uint256` hex so byte-order mistakes are obvious.

For scanner verification, use a known vector/target pair to prove:

- a known valid nonce is found and `fulltest()` accepts it;
- the nonce placed back in `work->data[19]` is the expected host value;
- hashes below/above the target agree with CivicNet's `CheckProofOfWork` numeric comparison;
- an end-to-end share constructed by the miner is accepted by a local CivicNet regtest/testnet node or a controlled pool instance.

Do not use “the miner and its own test agree” as the sole oracle. At least one vector must be generated by the CivicNet node executable at the pinned commit.

### V4. Build and CLI acceptance

- Run the repo's clean Autotools build in each supported ISA configuration.
- Confirm `./cpuminer --help` lists `yespower1` and `civiclight` exactly once.
- Confirm `./cpuminer -a yespower1 --benchmark` and `./cpuminer -a civiclight --benchmark` register without the unknown-algo/default-gate error.
- Confirm existing yespower algorithm names still map to their original enum/name ordinals and presets.
- Inspect the final diff to ensure only the planned production sources, generated build files, and tests are included; do not include local profiles, logs, or benchmark artifacts.

## Benchmark plan

### M1. Method

Benchmark both plain 1.0 and the complete Civiclight wrapper on the actual target CPU:

```text
./cpuminer -a yespower1 --benchmark -t <threads>
./cpuminer -a civiclight --benchmark -t <threads>
```

For every result record CPU model/microcode, NUMA topology, physical/logical core count, L2/L3 sizes, memory configuration, compiler/version, exact CFLAGS, commit, hugepage state, affinity, governor/fixed frequency, temperature, and whether SMT/turbo are enabled.

- Warm up until frequency and allocation stabilize; measure at least 60 seconds and repeat at least five times.
- Report median H/s plus min/max or standard deviation, not a single startup sample.
- Test 1 thread, one thread per physical core in a cache group, all physical cores, and SMT threads.
- Pin threads (`taskset`/`numactl` or this repo's affinity support) and compare `--cache-fit` behavior using the actual 2.096 MiB requested / 4 MiB hugepage-mapped footprint.
- Compare hugepages enabled versus forced fallback, but never compare different algorithms or compiler flags as if the delta were from hugepages alone.
- Use the same nonce/work stream and build for plain 1.0 versus Civiclight; the delta measures outer SHA256d, two Civic SHA-256 operations, and XOR overhead.

Collect `perf stat` counters for cycles, instructions, IPC, cache references/misses, L1/L2/LLC misses where supported, page faults, and dTLB load misses. Use `perf record` or the repo's existing profiling workflow only after correctness passes, to confirm time remains in the shared SMix/pwxform core and no mmap/free appears in the hot loop.

### M2. Acceptance criteria

- All correctness vectors pass in every supported ISA build.
- Legacy 0.9 hashes are unchanged.
- Each mining thread allocates at most once per required scratch size during steady-state scanning.
- AVX2/AVX512VL builds retain their expected optimized instruction paths; baseline builds remain runnable on their declared CPUs.
- Civiclight reports stable H/s with no allocation/log spam per nonce and no material regression in plain 1.0 caused by the wrapper.
- A known CivicNet header/nonce is accepted by both `fulltest()` and the pinned CivicNet node.

## Recommended implementation sequence

1. Pin upstream commits/releases and add the Openwall/CivicNet vector fixtures first.
2. Add `YESPOWER_1_0 = 10`, fail-safe errors, and shared 9/10 dispatch in `algo/yespower/`.
3. Pass official, differential, legacy, sanitizer, and multi-ISA tests.
4. Add `-a yespower1` registration and run the plain benchmark baseline.
5. Add the Civiclight v2 core and independently validate its stage outputs.
6. Add the outer header SHA256d wrapper and validate against `CBlockHeader::GetPoWHash()`.
7. Add `scanhash_civiclight`, algo-gate/CLI/build wiring, and target-boundary tests.
8. Run local-node/pool interoperability, then the controlled target-CPU benchmark matrix.
9. Review provenance, generated files, dirty-worktree scope, and the final production/test diff before commit.
