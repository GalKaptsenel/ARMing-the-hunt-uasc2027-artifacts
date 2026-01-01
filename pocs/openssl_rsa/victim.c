#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "poc.h"
#include "donor.h"
#include "scoring.h"
#include "victim.h"

static void __attribute__((noinline)) vuln(void) {
    char buf[64] = { 0 };
    (void)read(0, buf, PAYLEN);   // the bug: PAYLEN bytes read into a 64-byte buffer, overflowing this frame
    (void)buf;
}

// The overflow runs upward past vuln()'s own frame and overwrites THIS function's saved return address,
// at CHAIN_OFF (= 64-byte buf + 8-byte saved x29) above buf. vuln() returns normally, then control is hijacked
// here, at call_vuln()'s `ret`, into the ROP chain. no-optimize-sibling-calls keeps that saved LR on the
// stack (a tail call would elide this frame).
void __attribute__((noinline, optimize("no-optimize-sibling-calls"))) call_vuln(void) {
    vuln();
}

void gen_secret(void) {
    unsigned char *page = (unsigned char *)SECBASE;
    for (int offset = 0; offset < 0x1000; ++offset) {
        page[offset] = (unsigned char)rand();
    }
    *(uint64_t *)(page + CALIB_OFF) = 0x2ULL;   // the canonical reference the readout normalizes against
}

void build_key(void) {
    RSA *rsa = p_RSA_new();
    OBIGNUM *e = p_BN_new();
    p_BN_set_word(e, 65537);
    if (p_RSA_generate_key_ex(rsa, 2048, e, NULL) != 1) {
        printf("!! RSA keygen failed\n");
        _exit(1);
    }
    EVP_PKEY *pk = p_EVP_PKEY_new();
    if (p_EVP_PKEY_set1_RSA(pk, rsa) != 1) {
        printf("!! EVP_PKEY_set1_RSA failed\n");
        _exit(1);
    }
    p_RSA_get0_key(rsa, (const OBIGNUM **)&g_n, (const OBIGNUM **)&g_e, (const OBIGNUM **)&g_d);

    struct bignum_st *bn_d = (struct bignum_st *)g_d;
    g_key_limbaddr = (uint64_t)bn_d->d;   // heap address of d's 64-bit limb array, least-significant limb first
    g_key_limbs = bn_d->top;
    printf("[victim] EVP_PKEY built: 2048-bit RSA, e=65537; PRIVATE d = %d bits, %d limbs @ %#lx (own heap)\n",
           p_BN_num_bits(g_d), g_key_limbs, g_key_limbaddr);
}
