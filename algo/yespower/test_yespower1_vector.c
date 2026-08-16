/* Standalone correctness test for YESPOWER_1_0 against the official Openwall vector.
 * Vector (Openwall TESTS-OK:9): input 80 bytes src[i]=i*3, params
 * {YESPOWER_1_0, 2048, 8, NULL, 0} -> 69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46
 */
#include <stdio.h>
#include <string.h>
#include "yespower.h"

int main(void) {
    uint8_t src[80];
    for (int i = 0; i < 80; i++) src[i] = i * 3;

    yespower_params_t params;
    params.version = YESPOWER_1_0;
    params.N = 2048;
    params.r = 8;
    params.pers = NULL;
    params.perslen = 0;

    yespower_local_t local;
    yespower_binary_t out;
    memset(&out, 0, sizeof(out));

    if (yespower_init_local(&local)) { printf("FAIL: init_local\n"); return 1; }
    if (yespower(&local, src, 80, &params, &out)) { printf("FAIL: yespower\n"); return 1; }

    const char *expect = "69e0e895b3df7aeeb837d71fe199e9d34f7ec46ecbca7a2c4308e51857ae9b46";
    char got[65];
    for (int i = 0; i < 32; i++) sprintf(got + 2*i, "%02x", out.uc[i]);
    got[64] = 0;

    printf("got     : %s\n", got);
    printf("expected: %s\n", expect);
    printf("%s\n", strcmp(got, expect) == 0 ? "PASS: YESPOWER_1_0 matches official Openwall vector" : "FAIL: MISMATCH");
    yespower_free_local(&local);
    return strcmp(got, expect) == 0 ? 0 : 1;
}
