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

int main(void)
{
    int failed = test_nonce_equivalence();
    for (unsigned int i = 0; i < 3; i++)
        failed |= test_hash_vector(i);
    return failed ? 1 : 0;
}
