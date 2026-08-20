/* Differential test for CivicNet civiclight v2 and nonce serialization.
 *
 * The reference path mirrors CivicLight/civiclight-miner-windows:
 *   SHA256(SHA256(header80)) -> SHA256 -> yespower 1.0 -> XOR -> SHA256
 * SHA256_Buf is a separate SHA-256 implementation from sha256d().
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "civiclight_hash.h"
#include "../yespower/sha256-P.h"

extern void sha256d(unsigned char *hash, const unsigned char *data, int len);
extern int ref_yespower(yespower_local_t *local,
    const uint8_t *src, size_t srclen,
    const yespower_params_t *params, yespower_binary_t *dst);

/* yespower-opt.c reports allocator fallbacks through the miner logger. */
void applog(int priority, const char *format, ...)
{
    (void)priority;
    (void)format;
}

static uint32_t swap32(uint32_t x)
{
    return ((x & 0x000000ffU) << 24) |
           ((x & 0x0000ff00U) << 8)  |
           ((x & 0x00ff0000U) >> 8)  |
           ((x & 0xff000000U) >> 24);
}

static void put_be32(void *dst, uint32_t x)
{
    uint8_t *p = dst;
    p[0] = (uint8_t)(x >> 24);
    p[1] = (uint8_t)(x >> 16);
    p[2] = (uint8_t)(x >> 8);
    p[3] = (uint8_t)x;
}

static void put_le32(void *dst, uint32_t x)
{
    uint8_t *p = dst;
    p[0] = (uint8_t)x;
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}

static int official_v2_reference(const uint8_t header[80], uint8_t out[32])
{
    uint8_t first[32], intermediate[32], hash1[32], mixed[32];
    yespower_binary_t yp;
    const yespower_params_t params = {
        YESPOWER_1_0, 2048, 8, NULL, 0
    };

    SHA256_Buf(header, 80, first);
    SHA256_Buf(first, 32, intermediate);
    SHA256_Buf(intermediate, 32, hash1);

    /* yespower-ref.c is deliberately independent of yespower-opt.c. */
    if (ref_yespower(NULL, hash1, 32, &params, &yp))
        return -1;

    for (int i = 0; i < 32; i++)
        mixed[i] = yp.uc[i] ^ hash1[i];
    SHA256_Buf(mixed, 32, out);
    return 0;
}

static int test_hash_vector(unsigned int vector)
{
    uint8_t header[80], sha2d[32], sha_ref[32], first[32];
    uint8_t got[32], expected[32];

    for (int i = 0; i < 80; i++)
        header[i] = (uint8_t)(i * (vector * 2 + 1) + vector * 29);
    /* nTime = 1784797200, little-endian: force the official v2 branch. */
    put_le32(header + 68, UINT32_C(1784797200));

    sha256d(sha2d, header, 80);
    SHA256_Buf(header, 80, first);
    SHA256_Buf(first, 32, sha_ref);
    if (memcmp(sha2d, sha_ref, 32)) {
        fprintf(stderr, "FAIL vector %u: sha256d byte order differs\n", vector);
        return 1;
    }
    if (civiclight_powhash80(header, got) ||
        official_v2_reference(header, expected) ||
        memcmp(got, expected, 32)) {
        fprintf(stderr, "FAIL vector %u: final 32 bytes differ\n", vector);
        return 1;
    }

    printf("PASS vector %u: ", vector);
    for (int i = 0; i < 32; i++)
        printf("%02x", got[i]);
    putchar('\n');
    return 0;
}

static int test_nonce_equivalence(void)
{
    const uint32_t ours = UINT32_C(0x11223344);
    const uint32_t official = swap32(ours);
    uint8_t ours_header[4], official_header[4];
    uint8_t ours_submit[4], official_submit[4];

    /* Ours: be32enc(header, n), then pdata[19] = n and std_le submit. */
    put_be32(ours_header, ours);
    put_le32(ours_submit, ours);

    /* Official: edata[19] = n_official, then pdata[19] = bswap(n_official). */
    put_le32(official_header, official);
    put_le32(official_submit, swap32(official));

    if (memcmp(ours_header, official_header, 4) ||
        memcmp(ours_submit, official_submit, 4)) {
        fputs("FAIL: nonce header/submission serialization differs\n", stderr);
        return 1;
    }
    puts("PASS nonce: header bytes 11223344, submitted hex 44332211");
	return 0;
}

static int check_yespower_pair(const uint8_t input0[32],
    const uint8_t input1[32], yespower_local_t local[2],
    const yespower_params_t *params, const char *label)
{
	yespower_binary_t expected[2], got[2];

	if (yespower(&local[0], input0, 32, params, &expected[0]) ||
	    yespower(&local[1], input1, 32, params, &expected[1]) ||
	    yespower_2way_tls(input0, input1, 32, params, &got[0], &got[1]) ||
	    memcmp(expected[0].uc, got[0].uc, 32) ||
	    memcmp(expected[1].uc, got[1].uc, 32)) {
		fprintf(stderr, "FAIL yespower 2way: %s\n", label);
		return 1;
	}
	return 0;
}

static int test_yespower_2way_equivalence(void)
{
	const yespower_params_t params = {
		YESPOWER_1_0, 2048, 8, NULL, 0
	};
	yespower_local_t local[2];
	uint8_t a[32], b[32];
	uint32_t rng = UINT32_C(0x6d2b79f5);
	int failed = 0;

	if (yespower_init_local(&local[0]) || yespower_init_local(&local[1])) {
		fputs("FAIL yespower 2way: local init\n", stderr);
		return 1;
	}

	memset(a, 0, sizeof(a));
	memset(b, 0, sizeof(b));
	failed |= check_yespower_pair(a, b, local, &params, "identical zero");
	memset(a, 0xff, sizeof(a));
	memset(b, 0xff, sizeof(b));
	failed |= check_yespower_pair(a, b, local, &params, "identical ff");
	for (int i = 0; i < 32; i++) {
		a[i] = (uint8_t)(i * 7 + 3);
		b[i] = (uint8_t)(i * 13 + 11);
	}
	failed |= check_yespower_pair(a, b, local, &params, "different");
	failed |= check_yespower_pair(b, a, local, &params, "reversed");

	for (unsigned pair = 0; pair < 32; pair++) {
		for (unsigned i = 0; i < 32; i++) {
			rng ^= rng << 13;
			rng ^= rng >> 17;
			rng ^= rng << 5;
			a[i] = (uint8_t)rng;
			rng ^= rng << 13;
			rng ^= rng >> 17;
			rng ^= rng << 5;
			b[i] = (uint8_t)rng;
		}
		char label[32];
		snprintf(label, sizeof(label), "random %u", pair);
		failed |= check_yespower_pair(a, b, local, &params, label);
	}

	yespower_free_local(&local[0]);
	yespower_free_local(&local[1]);
	if (!failed)
		puts("PASS yespower 2way equivalence");
	return failed;
}

static void make_patterned_header(uint8_t header[80], unsigned vector)
{
	for (int i = 0; i < 80; i++)
		header[i] = (uint8_t)(i * (vector * 2 + 1) + vector * 29);
	put_le32(header + 68, UINT32_C(1784797200));
}

static int check_civiclight_pair(const uint8_t base[80],
    uint32_t nonce0, uint32_t nonce1, const char *label)
{
	uint8_t header[2][80], expected[2][32], got[2][32];

	memcpy(header[0], base, 80);
	memcpy(header[1], base, 80);
	put_be32(header[0] + 76, nonce0);
	put_be32(header[1] + 76, nonce1);
	if (civiclight_powhash80(header[0], expected[0]) ||
	    civiclight_powhash80(header[1], expected[1]) ||
	    civiclight_powhash80_2way(header[0], header[1], got[0], got[1]) ||
	    memcmp(expected[0], got[0], 32) ||
	    memcmp(expected[1], got[1], 32)) {
		fprintf(stderr, "FAIL civiclight 2way: %s\n", label);
		return 1;
	}
	return 0;
}

static int test_civiclight_2way_equivalence(void)
{
	uint8_t base[80];
	int failed = 0;

	make_patterned_header(base, 0);
	failed |= check_civiclight_pair(base, 0, 1, "nonce 0/1");
	failed |= check_civiclight_pair(base, UINT32_C(0x11223344),
	    UINT32_C(0x11223345), "nonce 11223344/11223345");
	failed |= check_civiclight_pair(base, UINT32_C(0xfffffffe),
	    UINT32_C(0xffffffff), "nonce fffffffe/ffffffff");
	for (unsigned vector = 0; vector < 3; vector++) {
		char label[32];
		make_patterned_header(base, vector);
		snprintf(label, sizeof(label), "pattern %u", vector);
		failed |= check_civiclight_pair(base,
		    UINT32_C(0x01020304) + vector * 2,
		    UINT32_C(0x01020305) + vector * 2, label);
	}
	if (!failed)
		puts("PASS civiclight 2way equivalence");
	return failed;
}

static int test_midstate_prefix_guard(void)
{
	uint8_t header[2][80], expected[2][32], got[2][32];

	make_patterned_header(header[0], 1);
	memcpy(header[1], header[0], 80);
	header[1][17] ^= UINT8_C(0x5a);
	put_be32(header[0] + 76, UINT32_C(41));
	put_be32(header[1] + 76, UINT32_C(42));
	if (civiclight_powhash80(header[0], expected[0]) ||
	    civiclight_powhash80(header[1], expected[1]) ||
	    civiclight_powhash80_2way(header[0], header[1], got[0], got[1]) ||
	    memcmp(expected[0], got[0], 32) ||
	    memcmp(expected[1], got[1], 32)) {
		fputs("FAIL midstate prefix guard\n", stderr);
		return 1;
	}
	puts("PASS midstate prefix guard");
	return 0;
}

int main(void)
{
	int failed = test_nonce_equivalence();
	for (unsigned int i = 0; i < 3; i++)
		failed |= test_hash_vector(i);
	failed |= test_yespower_2way_equivalence();
	failed |= test_civiclight_2way_equivalence();
	failed |= test_midstate_prefix_guard();
	return failed ? 1 : 0;
}
