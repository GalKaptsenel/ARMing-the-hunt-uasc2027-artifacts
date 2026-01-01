// The target: a process with one stack-buffer overflow whose secret is a real RSA private key.
#ifndef VICTIM_H
#define VICTIM_H

void call_vuln(void);   // the child runs only this, its overflowed return address enters the ROP
void gen_secret(void);  // write the known-canonical calibration page at SECBASE
void build_key(void);   // build a genuine 2048-bit RSA EVP_PKEY in this process's own heap

#endif
