/*-
 * CivicNet (CIVIC) Civiclight v2 proof-of-work for cpuminer-opt-cpupower.
 *
 * Implements CivicNet's civiclight v2 exactly:
 *   civiclight_hash_v2(input, len):
 *     hash1  = SHA256(input)
 *     yp     = yespower-1.0(hash1, N=2048, r=8, pers=NULL, perslen=0)
 *     xor_buf = yp XOR hash1
 *     output = SHA256(xor_buf)
 *   civiclight_powhash80(header80):
 *     output = civiclight_hash_v2(SHA256d(header80))
 *
 * The outer SHA256d(header80) is required by CivicNet's CBlockHeader::GetPoWHash();
 * calling the v2 core directly on the raw header would NOT match the network.
 */

#include "civiclight_hash.h"
#include "../yespower/sha256-P.h"
#include "../../algo-gate-api.h"
#include <string.h>

/* yespower thread-local scratch, initialized once per thread */
static __thread yespower_local_t civiclight_yp_local;
static __thread int civiclight_yp_initialized = 0;

static const yespower_params_t civiclight_yp_params = {
    YESPOWER_1_0, 2048, 8, NULL, 0
};

int civiclight_hash_v2(const void *input, size_t len, void *output)
{
	uint8_t hash1[32];
	uint8_t xor_buf[32];
	yespower_binary_t yp_out;

	if (!civiclight_yp_initialized) {
		if (yespower_init_local(&civiclight_yp_local))
			return -1;
		civiclight_yp_initialized = 1;
	}

	/* hash1 = SHA256(input) */
	SHA256_Buf(input, len, hash1);

	/* yp = yespower-1.0(hash1, 32).
	 * Optimized core returns 1 on success, -1 on error (0 = restart abort). */
	if (yespower(&civiclight_yp_local, hash1, 32,
	    &civiclight_yp_params, &yp_out, 0) <= 0) {
		memset(output, 0xff, 32);
		return -1;
	}

	/* xor_buf = yp_out XOR hash1 */
	for (int i = 0; i < 32; i++)
		xor_buf[i] = yp_out.uc[i] ^ hash1[i];

	/* output = SHA256(xor_buf) */
	SHA256_Buf(xor_buf, 32, (uint8_t *)output);

	return 0;
}

int civiclight_powhash80(const void *header80, void *output)
{
	/* Match the official Soj-CivicLight miner (algo/civiclight/civiclight.c):
	 *   intermediate = sha256d(header80)          = SHA256(SHA256(header80))
	 *   then civiclight_core_v2(intermediate, 32):
	 *     hash1 = SHA256(intermediate, 32)
	 *     yp    = yespower(hash1, 32, {YESPOWER_1_0, N=2048, r=8, pers=NULL})
	 *     out   = SHA256(yp XOR hash1)
	 * civiclight_hash_v2 does the inner SHA256(intermediate,32)+yespower+XOR+SHA256. */
	uint8_t intermediate[32];
	sha256d(intermediate, (const unsigned char *)header80, 80);
	return civiclight_hash_v2(intermediate, 32, output);
}

void civiclight_gate_hash(void *output, const void *input, uint32_t len)
{
	/* gate-facing one-shot: expects an 80-byte serialized header */
	if (len != 80) {
		memset(output, 0xff, 32);
		return;
	}
	civiclight_powhash80(input, output);
}

int64_t civiclight_get_max64()
{
	return 0xfffLL;
}

/*
 * CivicNet's custom share-difficulty convention (official CivicLight miner
 * diff_to_hash): the share target is the 256-bit value
 *     T = (1/diff) * 2^224 + (2^128 - 1)
 * i.e. low  128 bits (target[0..3]) all 0xFF, and (1/diff) in the
 * upper portion.  fulltest() compares uint32 target[8] with target[7] as the
 * MOST-significant limb.  (1/diff)*2^224 puts (1/diff) at bit 224, so
 * target[7] = (uint32)(1/diff), target[6..4] = 0, target[3..0] = 0xFF.
 */
void civiclight_set_target(struct work *work, double diff)
{
	uint32_t *t = (uint32_t *)work->target;
	/* Honor --diff-multiplier (-m): opt_diff_factor divides the effective
	 * difficulty, tightening the share target so fewer (fresher) shares are
	 * found -> fewer stale submissions at ultra-low pool diff.  Previously this
	 * ignored opt_diff_factor, so -m had no effect. */
	double effective_diff = diff / opt_diff_factor;
	/* Pool (BitcoinConstants.Diff1 = 2^224) accepts iff hash <= Diff1/diff,
	 * so the most-significant limb t[7] = 1/diff.  Matches the official
	 * CivicNet/Soj miner (diff_to_hash: targ[1]=(1/diff)*2^96 -> t[7]=1/diff). */
	unsigned long long one_over = (unsigned long long)(1.0 / effective_diff);

	t[0] = 0xFFFFFFFFU;
	t[1] = 0xFFFFFFFFU;
	t[2] = 0xFFFFFFFFU;
	t[3] = 0xFFFFFFFFU;
	t[4] = 0;
	t[5] = 0;
	t[6] = 0;
	t[7] = (uint32_t)one_over;
	/* DEBUG: dump the target the miner computes for this diff */
	fprintf(stderr, "CIVDIFF set_target diff=%.17g eff=%.17g t[7]=0x%08x t[6]=0x%08x\n",
	        diff, effective_diff, t[7], t[6]);
	work->targetdiff = effective_diff;
}

int scanhash_civiclight(int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done)
{
	uint32_t vhash[8] __attribute__((aligned(64)));
	uint32_t endiandata[20] __attribute__((aligned(64)));
	uint32_t *pdata = work->data;
	const uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	uint32_t n = pdata[19];
	const uint32_t first_nonce = n;

	/* serialize header words 0..18 once per work item (little-endian) */
	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], n);
		if (civiclight_powhash80(endiandata, vhash))
			break;
		if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
			work_set_target_ratio(work, vhash);
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

bool register_civiclight_algo(algo_gate_t *gate)
{
	gate->optimizations = SSE2_OPT | SHA_OPT;
	gate->get_max64     = (void*)&civiclight_get_max64;
	gate->scanhash      = (void*)&scanhash_civiclight;
	gate->hash          = (void*)&civiclight_gate_hash;
	gate->set_target    = (void*)&civiclight_set_target;
	return true;
}
