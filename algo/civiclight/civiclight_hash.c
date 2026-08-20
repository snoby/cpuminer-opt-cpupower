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

	/* yp = yespower-1.0(hash1, 32).  Returns 0 on success, -1 on error. */
	if (yespower(&civiclight_yp_local, hash1, 32,
	    &civiclight_yp_params, &yp_out) != 0) {
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

int civiclight_hash_v2_2way(const void *input0, const void *input1,
    size_t len, void *output0, void *output1)
{
	uint8_t hash1[2][32];
	uint8_t xor_buf[2][32];
	yespower_binary_t yp_out[2];

	SHA256_Buf(input0, len, hash1[0]);
	SHA256_Buf(input1, len, hash1[1]);
	if (yespower_2way_tls(hash1[0], hash1[1], 32,
	    &civiclight_yp_params, &yp_out[0], &yp_out[1]) != 0) {
		memset(output0, 0xff, 32);
		memset(output1, 0xff, 32);
		return -1;
	}

	for (int i = 0; i < 32; i++) {
		xor_buf[0][i] = yp_out[0].uc[i] ^ hash1[0][i];
		xor_buf[1][i] = yp_out[1].uc[i] ^ hash1[1][i];
	}
	SHA256_Buf(xor_buf[0], 32, output0);
	SHA256_Buf(xor_buf[1], 32, output1);
	return 0;
}

int civiclight_powhash80(const void *header80, void *output)
{
	/* CivicNet civiclight (verified against official CivicNet reference):
	 *   raw_hash = SHA256d(header80)              (Bitcoin double-SHA256)
	 *   hash1    = SHA256(raw_hash, 32)          (done inside civiclight_hash_v2)
	 *   yp       = yespower(hash1, 32, {YESPOWER_1_0, N=2048, r=8, pers=NULL})
	 *   out      = SHA256(yp XOR hash1)
	 * The outer SHA256d(header80) wrapper is REQUIRED — without it the miner
	 * hashes different bytes than the pool and every share fails. */
	uint8_t raw_hash[32];
	sha256d(raw_hash, (const unsigned char *)header80, 80);
	return civiclight_hash_v2(raw_hash, 32, output);
}

static void civiclight_sha256d_80_midstate(uint8_t output[32],
    const void *header80, const SHA256_CTX *midstate)
{
	SHA256_CTX ctx = *midstate;
	uint8_t first[32];

	SHA256_Update(&ctx, (const uint8_t *)header80 + 64, 16);
	SHA256_Final(first, &ctx);
	SHA256_Buf(first, sizeof(first), output);
}

static int civiclight_powhash80_from_midstate(const void *header80,
    const SHA256_CTX *midstate, void *output)
{
	uint8_t raw_hash[32];

	civiclight_sha256d_80_midstate(raw_hash, header80, midstate);
	return civiclight_hash_v2(raw_hash, sizeof(raw_hash), output);
}

static int civiclight_powhash80_2way_midstate(const void *header0,
    const void *header1, const SHA256_CTX *midstate,
    void *output0, void *output1)
{
	uint8_t raw_hash[2][32];

	civiclight_sha256d_80_midstate(raw_hash[0], header0, midstate);
	civiclight_sha256d_80_midstate(raw_hash[1], header1, midstate);
	return civiclight_hash_v2_2way(raw_hash[0], raw_hash[1],
	    sizeof(raw_hash[0]), output0, output1);
}

int civiclight_powhash80_2way(const void *header0, const void *header1,
    void *output0, void *output1)
{
	SHA256_CTX midstate;

	if (memcmp(header0, header1, 64) != 0) {
		int rc0 = civiclight_powhash80(header0, output0);
		int rc1 = civiclight_powhash80(header1, output1);
		return rc0 | rc1;
	}

	SHA256_Init(&midstate);
	SHA256_Update(&midstate, header0, 64);
	return civiclight_powhash80_2way_midstate(header0, header1, &midstate,
	    output0, output1);
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
	work->targetdiff = effective_diff;
}

int scanhash_civiclight(int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done)
{
#if defined(__AVX2__)
	uint32_t hash_pair[2][8] __attribute__((aligned(64)));
	uint32_t header_pair[2][20] __attribute__((aligned(64)));
	uint32_t tail_hash[8] __attribute__((aligned(64)));
	SHA256_CTX header_midstate;
	uint32_t *pdata = work->data;
	const uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	uint32_t n = pdata[19];
	const uint32_t first_nonce = n;
	int num_found = 0;

	/* Pool-proven convention: hash be32enc(n), submit numeric n unchanged. */
	for (int k = 0; k < 19; k++)
		be32enc(&header_pair[0][k], pdata[k]);
	header_pair[0][19] = 0;
	memcpy(header_pair[1], header_pair[0], sizeof(header_pair[0]));
	SHA256_Init(&header_midstate);
	SHA256_Update(&header_midstate, header_pair[0], 64);

	while (n < max_nonce && max_nonce - n >= 2 &&
	    !work_restart[thr_id].restart) {
		be32enc(&header_pair[0][19], n);
		be32enc(&header_pair[1][19], n + 1);
		if (civiclight_powhash80_2way_midstate(header_pair[0],
		    header_pair[1], &header_midstate,
		    hash_pair[0], hash_pair[1]) != 0)
			break;

		for (unsigned lane = 0; lane < 2; lane++) {
			uint32_t candidate = n + lane;
			if (hash_pair[lane][7] < Htarg &&
			    fulltest(hash_pair[lane], ptarget)) {
				work->nonces[num_found++] = candidate;
				work_set_target_ratio(work, hash_pair[lane]);
#ifdef CIVICLIGHT_SHARE_DEBUG
				fprintf(stderr, "CIVSHARE header80=");
				for (int k = 0; k < 80; k++)
					fprintf(stderr, "%02x",
					    ((const uint8_t *)header_pair[lane])[k]);
				fprintf(stderr, " vhash=");
				for (int k = 0; k < 32; k++)
					fprintf(stderr, "%02x",
					    ((const uint8_t *)hash_pair[lane])[k]);
				fprintf(stderr, " v7=0x%08x\\n",
				    hash_pair[lane][7]);
#endif
			}
		}
		n += 2;
		if (num_found)
			break;
	}

	if (!num_found && n < max_nonce && max_nonce - n == 1 &&
	    !work_restart[thr_id].restart) {
		be32enc(&header_pair[0][19], n);
		if (civiclight_powhash80_from_midstate(header_pair[0],
		    &header_midstate, tail_hash) == 0) {
			if (tail_hash[7] < Htarg && fulltest(tail_hash, ptarget)) {
				work->nonces[num_found++] = n;
				work_set_target_ratio(work, tail_hash);
#ifdef CIVICLIGHT_SHARE_DEBUG
				fprintf(stderr, "CIVSHARE header80=");
				for (int k = 0; k < 80; k++)
					fprintf(stderr, "%02x",
					    ((const uint8_t *)header_pair[0])[k]);
				fprintf(stderr, " vhash=");
				for (int k = 0; k < 32; k++)
					fprintf(stderr, "%02x",
					    ((const uint8_t *)tail_hash)[k]);
				fprintf(stderr, " v7=0x%08x\\n", tail_hash[7]);
#endif
			}
			n++;
		}
	}

	*hashes_done = n - first_nonce;
	if (num_found == 1)
		pdata[19] = work->nonces[0];
	else if (num_found == 0)
		pdata[19] = n;
	return num_found;
#else
	uint32_t vhash[8] __attribute__((aligned(64)));
	uint32_t endiandata[20] __attribute__((aligned(64)));
	uint32_t *pdata = work->data;
	const uint32_t *ptarget = work->target;
	const uint32_t Htarg = ptarget[7];
	uint32_t n = pdata[19];
	const uint32_t first_nonce = n;

	/* serialize header words 0..18 once per work item (little-endian), matching
	 * Soj's v128_bswap32_80.  Nonce: vipor pool accepts when hashing
	 * be32enc(endiandata[19], n) and submitting n raw (this had more accepts
	 * on vipor than Soj's LE+bswap convention). */
	for (int k = 0; k < 19; k++)
		be32enc(&endiandata[k], pdata[k]);

	do {
		be32enc(&endiandata[19], n);
		if (civiclight_powhash80(endiandata, vhash))
			break;
		if (vhash[7] < Htarg && fulltest(vhash, ptarget)) {
			work_set_target_ratio(work, vhash);
#ifdef CIVICLIGHT_SHARE_DEBUG
			/* DEBUG: dump the EXACT 80-byte header buffer passed to
			 * civiclight_powhash80 (endiandata[0..19] as bytes), + vhash.
			 * Hash these exact bytes against the reference to test whether
			 * the print path == the hash-input path (possibility #1). */
			fprintf(stderr, "CIVSHARE header80=");
			for (int k = 0; k < 20; k++) {
				unsigned char b0 = (unsigned char)(endiandata[k]);
				unsigned char b1 = (unsigned char)(endiandata[k]>>8);
				unsigned char b2 = (unsigned char)(endiandata[k]>>16);
				unsigned char b3 = (unsigned char)(endiandata[k]>>24);
				fprintf(stderr, "%02x%02x%02x%02x", b0, b1, b2, b3);
			}
			fprintf(stderr, " vhash=");
			for (int k = 0; k < 32; k++)
				fprintf(stderr, "%02x", ((unsigned char*)vhash)[k]);
			fprintf(stderr, " v7=0x%08x\n", vhash[7]);
#endif
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;
	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
#endif
}

bool register_civiclight_algo(algo_gate_t *gate)
{
	gate->optimizations = SSE2_OPT | SHA_OPT;
#if defined(__AVX2__)
	gate->optimizations |= AVX2_OPT;
#endif
	gate->get_max64     = (void*)&civiclight_get_max64;
	gate->scanhash      = (void*)&scanhash_civiclight;
	gate->hash          = (void*)&civiclight_gate_hash;
	gate->set_target    = (void*)&civiclight_set_target;
	return true;
}
