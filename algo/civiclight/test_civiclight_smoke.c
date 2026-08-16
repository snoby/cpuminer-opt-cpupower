/* Smoke test: civiclight_powhash80 + civiclight_hash_v2 run and are deterministic.
 * Also confirms the v2 core produces a 32-byte output and the full PoW path works.
 */
#include <stdio.h>
#include <string.h>
#include "civiclight_hash.h"

int main(void) {
    unsigned char header[80];
    unsigned char out1[32], out2[32];
    for (int i = 0; i < 80; i++) header[i] = (unsigned char)i;

    if (civiclight_powhash80(header, out1)) { printf("FAIL: powhash80\n"); return 1; }
    if (civiclight_powhash80(header, out2)) { printf("FAIL: powhash80 2\n"); return 1; }
    if (memcmp(out1, out2, 32) != 0) { printf("FAIL: not deterministic\n"); return 1; }

    printf("civiclight_powhash80 deterministic, 32 bytes: ");
    for (int i = 0; i < 8; i++) printf("%02x", out1[i]);
    printf("...\n");

    /* core: hash_v2 on a 32-byte input */
    unsigned char in32[32], c1[32], c2[32];
    for (int i = 0; i < 32; i++) in32[i] = (unsigned char)i;
    civiclight_hash_v2(in32, 32, c1);
    civiclight_hash_v2(in32, 32, c2);
    printf("civiclight_hash_v2 deterministic: %s\n",
           memcmp(c1, c2, 32) == 0 ? "PASS" : "FAIL");
    return 0;
}
