#ifndef CIVICLIGHT_HASH_H
#define CIVICLIGHT_HASH_H

#include <stdint.h>
#include <stddef.h>
#include "../yespower/yespower.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * civiclight_hash_v2(input, len, output):
 * CivicNet's v2 core: SHA256(input) -> yespower-1.0(N=2048,r=8,pers=NULL)
 *   -> XOR(yp_out, sha256(input)) -> SHA256(xor_buf).
 * Writes 32 bytes to output. Returns 0 on success, -1 on error.
 */
int civiclight_hash_v2(const void *input, size_t len, void *output);

/*
 * civiclight_powhash80(header80, output):
 * Full CivicNet PoW path: SHA256d(header80) -> civiclight_hash_v2.
 * header80 must be exactly 80 serialized header bytes. Writes 32 bytes.
 * Returns 0 on success, -1 on error.
 */
int civiclight_powhash80(const void *header80, void *output);

/*
 * gate-compatible one-shot hash (algo_gate_t.hash signature).
 * output = civiclight_powhash80(input).
 */
void civiclight_gate_hash(void *output, const void *input, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* CIVICLIGHT_HASH_H */
