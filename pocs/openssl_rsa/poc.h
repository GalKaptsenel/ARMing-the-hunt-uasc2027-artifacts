// Cross-cutting constants and the --save tee, shared by every translation unit.
#ifndef POC_H
#define POC_H
#include <stdio.h>
#include <stdint.h>

#define PAYLEN 2048

// Fixed scratch pages (mapped before fork, inherited by the victim): the known-canonical
// calibration page and the Spectre-v4 window's working memory.
#define M_VA      0x10100000UL
#define A_VA      0x10101000UL
#define SLOT_VA   0x10102000UL
#define PTRS_VA   0x10103000UL
#define SECBASE   0x10200000UL
#define CALIB_OFF 0xFF8

#define SET_OF(pc) (((pc)>>6)&0x7f)   // Neoverse N3 BTB set index

extern FILE *g_save;
void tee_printf(const char *fmt, ...);       // print to stdout and, if --save was given, to the file

#endif
