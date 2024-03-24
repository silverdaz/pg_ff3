#ifndef __PG_FF3_H_INCLUDED__
#define __PG_FF3_H_INCLUDED__ 1

#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/random.h>
#include <signal.h>
#include <math.h>

#include <openssl/evp.h>
#include <openssl/bn.h>

#include "postgres.h"
#include "fmgr.h"
#include "utils/elog.h"


/* logging */
#define F(fmt, ...)  elog(FATAL,  "============ " fmt, ##__VA_ARGS__)
#define E(fmt, ...)  elog(ERROR,  "============ " fmt, ##__VA_ARGS__)
#define W(fmt, ...)  elog(WARNING,"============ " fmt, ##__VA_ARGS__)
#define N(fmt, ...)  elog(NOTICE, "| " fmt, ##__VA_ARGS__)
#define L(fmt, ...)  elog(LOG,    "============ " fmt, ##__VA_ARGS__)
#define D1(fmt, ...) elog(DEBUG1, "============ " fmt, ##__VA_ARGS__)
#define D2(fmt, ...) elog(DEBUG2, "============ " fmt, ##__VA_ARGS__)
#define D3(fmt, ...) elog(DEBUG3, "============ " fmt, ##__VA_ARGS__)
#define D4(fmt, ...) elog(DEBUG4, "============ " fmt, ##__VA_ARGS__)
#define D5(fmt, ...) elog(DEBUG5, "============ " fmt, ##__VA_ARGS__)

#define FF3_PREFIX      "ff3"
#define FF3_ROUNDS      8
#define FF3_TWEAK_SIZE  7 /* 56 bits for FF3-1 */
#define FF3_KEY_SIZE    32 /* 256 bits */


typedef struct ff3_engine_s {

  unsigned int id;

  uint8_t rev_key[FF3_KEY_SIZE];
  uint8_t tweak[FF3_TWEAK_SIZE+1];
  char* alphabet;
  unsigned int radix;

  unsigned int mintxtlen;
  unsigned int maxtxtlen;

  EVP_CIPHER_CTX *evp;
} ff3_engine_t;

void rev_bytes(unsigned char X[], int len);

int
ff3_encrypt(ff3_engine_t *engine,
	    const unsigned int * const plaintext,
	    unsigned int len,
	    unsigned int * const ciphertext);

int
ff3_decrypt(ff3_engine_t *engine,
	    const unsigned int * const ciphertext,
	    unsigned int len,
	    unsigned int * const plaintext);

#endif /* !__PG_FF3_H_INCLUDED__ */
