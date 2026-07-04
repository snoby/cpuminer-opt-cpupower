/* Vendored from github.com/CereblixCRB/cereblix (MIT License).
 * Copyright (c) 2026 Cereblix (CRB). See LICENSE-neuromorph for the full text.
 */
/* nm_fast — high-performance NeuroMorph core.
 *
 * Two code paths, both byte-identical to the consensus reference:
 *   nm_fast_hash      : single nonce, optimized (direct __m128i fill, AVX2 fold,
 *                       computed-goto VM). ~1.5x the reference per thread.
 *   nm_fast_hash_batch: K nonces in lockstep. Because prog_size/loops are fixed
 *                       per EPOCH (identical for every nonce), all lanes march in
 *                       lockstep and the per-loop 64-deep dataset read chains of
 *                       the K lanes are interleaved -> K independent DRAM reads in
 *                       flight -> the 64 MiB latency wall is hidden. This is the
 *                       memory-level-parallelism trick that beats every existing
 *                       one-hash-at-a-time NeuroMorph miner on the dataset phase.
 */
#ifndef NM_FAST_H
#define NM_FAST_H
#include <stdint.h>
#include "nm_neuromorph.h"

#ifdef __cplusplus
extern "C" {
#endif

#define NM_FAST_MAXLANES 16

/* Shared, per-epoch, read-only state (params + AES key schedule + 64 MiB dataset).
 * One instance per NUMA node is enough; many lane workers point at the same one. */
typedef struct {
    nm_params params;
    nm_aes128 aes;
    uint64_t *dataset;   /* 64 MiB, owned elsewhere (NUMA-local), may be NULL pre-activation */
} nm_epoch;

/* Per-lane scratch buffers (2 MiB scratchpad + program). One per concurrent lane. */
typedef struct {
    uint64_t *scratch;   /* NM_SCRATCH_WORDS */
    nm_instr *prog;      /* NM_PROG_MAX */
    uint8_t  *taken;     /* NM_PROG_MAX */
} nm_lane;

/* Initialise epoch state from a 32-byte epoch seed. Does NOT build the dataset
 * (attach it with nm_fast_set_dataset); params/aes are ready immediately. */
void nm_fast_epoch_init(nm_epoch *e, const uint8_t seed[32]);
void nm_fast_set_dataset(nm_epoch *e, uint64_t *dataset);

/* Allocate/free a lane's scratch buffers. */
int  nm_fast_lane_init(nm_lane *l);
void nm_fast_lane_free(nm_lane *l);
void nm_fast_lane_attach(nm_lane *l, void *scratch); /* use externally-owned (huge-page) scratch */

/* Single-nonce hash. header is NM_HEADER_LEN bytes (nonce already embedded). */
void nm_fast_hash(const nm_epoch *e, nm_lane *l, const uint8_t *header,
                  uint64_t height, uint8_t out[32]);

/* K-lane batch. headers points at K contiguous NM_HEADER_LEN-byte headers,
 * lanes is K lane buffers, out is K*32 bytes. 1 <= K <= NM_FAST_MAXLANES. */
void nm_fast_hash_batch(const nm_epoch *e, nm_lane *lanes, int K,
                        const uint8_t *headers, uint64_t height, uint8_t *out);

/* Build the 64 MiB dataset for this epoch's dataset_key (deterministic). */
void nm_fast_build_dataset(const nm_epoch *e, uint64_t *dataset);

/* Name of the runtime-selected scratch-fill path ("VAES-256" or "AES-NI"). */
const char *nm_fast_fill_name(void);

#ifdef __cplusplus
}
#endif
#endif
