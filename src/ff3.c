/*-------------------------------------------------------------------------
 *
 * src/ff3.c
 *
 * Implementation of FF3-1:
 * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
 *
 * Inspired from: https://github.com/mysto/clang-fpe
 * Data: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/FF3samples.pdf
 *-------------------------------------------------------------------------
 */

#include "includes.h"

#define ceil2(x, bit) ( ((x) >> (bit)) + ( ((x) & ((1 << (bit)) - 1)) > 0 ) )

static void
pow_uv(BIGNUM *pow_u, BIGNUM *pow_v, unsigned int x, int u, int v, BN_CTX *ctx)
{
  BIGNUM *base = NULL;
  BIGNUM *e = NULL;

  BN_CTX_start(ctx);
  base = BN_CTX_get(ctx);
  e = BN_CTX_get(ctx);

  BN_set_word(base, x);
  if (u > v) {
    BN_set_word(e, v);
    BN_exp(pow_v, base, e, ctx);
    BN_mul(pow_u, pow_v, base, ctx);
  } else {
    BN_set_word(e, u);
    BN_exp(pow_u, base, e, ctx);
    if (u == v)    BN_copy(pow_v, pow_u);
    else    BN_mul(pow_v, pow_u, base, ctx);
  }
  
  BN_CTX_end(ctx);
}

void
rev_bytes(unsigned char X[], int len)
{
    unsigned char tmp;
    int hlen = len >> 1; /* half, rounded */
    for (int i = 0; i < hlen; ++i) {
      tmp = X[i];
      X[i] = X[len - i - 1];
      X[len - i - 1] = tmp;
    }
}

/* convert numeral string in reverse order to number */
static void
str2num_rev(BIGNUM *Y, const uint8_t *X, unsigned int radix, unsigned int len, BN_CTX *ctx)
{
  BIGNUM *r = NULL,
         *x = NULL;
  int i;

  BN_CTX_start(ctx);
  r = BN_CTX_get(ctx);
  x = BN_CTX_get(ctx);

  BN_set_word(Y, 0);
  BN_set_word(r, radix);
  for (i = len - 1; i >= 0; --i) {
    // Y = Y * radix + X[i]
    BN_set_word(x, X[i]);
    BN_mul(Y, Y, r, ctx);
    BN_add(Y, Y, x);
  }

  BN_CTX_end(ctx);
}

/* convert number to numeral string in reverse order */
static void
num2str_rev(const BIGNUM *X, uint8_t *Y, unsigned int radix, int len, BN_CTX *ctx)
{
  BIGNUM *dv = NULL,
         *rem = NULL,
         *r = NULL,
         *XX = NULL;
  int i;

  BN_CTX_start(ctx);
  dv = BN_CTX_get(ctx);
  rem = BN_CTX_get(ctx);
  r = BN_CTX_get(ctx);
  XX = BN_CTX_get(ctx);

  BN_copy(XX, X);
  BN_set_word(r, radix);
  memset(Y, 0, len);
    
  for (i = 0; i < len; ++i) {
    // XX / r = dv ... rem
    BN_div(dv, rem, XX, r, ctx);
    // Y[i] = XX % r
    Y[i] = BN_get_word(rem);
    // XX = XX / r
    BN_copy(XX, dv);
  }

  BN_CTX_end(ctx);
}

static inline int
do_encrypt(EVP_CIPHER_CTX *evp, unsigned char src[16], unsigned char dst[16])
{
  int outlen;
  return !EVP_EncryptUpdate(evp, dst, &outlen, src, 16);
}

int
ff3_encrypt(ff3_engine_t *engine,
	    const uint8_t * const plaintext,
	    unsigned int len,
	    uint8_t * const ciphertext)
{
    BIGNUM *bnum = NULL,
           *y = NULL,
           *c = NULL,
           *anum = NULL,
           *qpow_u = NULL,
           *qpow_v = NULL;
    BN_CTX *ctx = NULL;
    int u, v;
    uint8_t *A = NULL;
    uint8_t *B = NULL;
    uint8_t *C = NULL;
    unsigned int temp, i, m;
    uint8_t S[16], P[16];
    uint8_t *buf = NULL;
    int buflen;
    unsigned int err = 1;

    bnum   = BN_new();
    y      = BN_new();
    c      = BN_new();
    anum   = BN_new();
    qpow_u = BN_new();
    qpow_v = BN_new();
    ctx    = BN_CTX_new();

    // Calculate split point
    u = ceil2(len, 1);
    v = len - u;

    memcpy(ciphertext, plaintext, len);
    A = ciphertext;
    B = ciphertext + u;

    pow_uv(qpow_u, qpow_v, engine->radix, u, v, ctx);
    temp = (unsigned int)ceil(u * log2(engine->radix));
    
    buflen = ceil2(temp, 3);
    buf = (unsigned char *)palloc0( buflen * sizeof(char) );
    if(!buf) goto bailout;

    for (i = 0; i < FF3_ROUNDS; ++i) {

        // Step i : if i is even, let m = u and W = Tr, else let m = v and W = Tl.
        // Step ii: Let P = (W XOR i[-4:] || NUM_radix (REV(B))[:12]
        if (i & 1) {
            m = v;
            memcpy(P, engine->tweak, 4);
        } else {
            m = u;
            memcpy(P, engine->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        str2num_rev(bnum, B, engine->radix, len - m, ctx);
        memset(buf, 0, buflen);
        buflen = BN_bn2bin(bnum, buf);
        buflen = buflen > 12? 12: buflen;
        memset(P + 4, 0, 12);
        memcpy(P + 16 - buflen, buf, buflen);

        // Step iii
        rev_bytes(P, 16);
        //memset(S, 0, sizeof(S));
	do_encrypt(engine->evp, P, S);
        rev_bytes(S, 16);

        // Step iv
        BN_bin2bn(S, 16, y);

        // Step v
        str2num_rev(anum, A, engine->radix, m, ctx);
	BN_mod_add(c, anum, y, (i & 1) ? qpow_v : qpow_u, ctx);

        assert(A != B);
        A = (uint8_t *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (uint8_t *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (uint8_t *)( (uintptr_t)A ^ (uintptr_t)B );

        num2str_rev(c, B, engine->radix, m, ctx);

    }

    err = 0; /* success */

bailout:

    /* clean up */
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(ctx);

    if(buf) pfree(buf);
    return err;
}

int
ff3_decrypt(ff3_engine_t *engine,
	    const uint8_t * const ciphertext,
	    unsigned int len,
	    uint8_t * const plaintext)
{

    BIGNUM *bnum = NULL,
           *y = NULL,
           *c = NULL,
           *anum = NULL,
           *qpow_u = NULL,
           *qpow_v = NULL;
    BN_CTX *ctx = NULL;
    int u, v;
    uint8_t *A = NULL;
    uint8_t *B = NULL;
    unsigned int temp;
    int i;
    unsigned char S[16], P[16];
    unsigned char *buf = NULL;
    int buflen, m;
    unsigned int err = 1;

    bnum   = BN_new();
    y      = BN_new();
    c      = BN_new();
    anum   = BN_new();
    qpow_u = BN_new();
    qpow_v = BN_new();
    ctx    = BN_CTX_new();

    // Calculate split point
    u = ceil2(len, 1);
    v = len - u;

    memcpy(plaintext, ciphertext, len);
    A = plaintext;
    B = plaintext + u;

    pow_uv(qpow_u, qpow_v, engine->radix, u, v, ctx);
    temp = (unsigned int)ceil(u * log2(engine->radix));
    buflen = ceil2(temp, 3);
    buf = (unsigned char *)palloc0( buflen * sizeof(char) );
    if(!buf) goto bailout;

    for (i = FF3_ROUNDS - 1; i >= 0; --i) {

        // Step i
        if (i & 1) {
            m = v;
            memcpy(P, engine->tweak, 4);
        } else {
            m = u;
            memcpy(P, engine->tweak + 4, 4);
        }
        P[3] ^= i & 0xff;

        // Step ii
        str2num_rev(anum, A, engine->radix, len - m, ctx);
        memset(buf, 0, buflen);
        buflen = BN_bn2bin(anum, buf);
        buflen = buflen > 12? 12: buflen;
        memset(P + 4, 0, 12);
        memcpy(P + 16 - buflen, buf, buflen);

        // iii
        rev_bytes(P, 16);
        //memset(S, 0, sizeof(S));
	do_encrypt(engine->evp, P, S);
        rev_bytes(S, 16);

        // iv
        BN_bin2bn(S, 16, y);

	// v
        str2num_rev(bnum, B, engine->radix, m, ctx);
        if (i & 1)
	  BN_mod_sub(c, bnum, y, qpow_v, ctx);
        else
	  BN_mod_sub(c, bnum, y, qpow_u, ctx);

        assert(A != B);
        A = (uint8_t *)( (uintptr_t)A ^ (uintptr_t)B );
        B = (uint8_t *)( (uintptr_t)B ^ (uintptr_t)A );
        A = (uint8_t *)( (uintptr_t)A ^ (uintptr_t)B );

        num2str_rev(c, A, engine->radix, m, ctx);
    }

    err = 0;

bailout:

    /* clean up */
    BN_clear_free(anum);
    BN_clear_free(bnum);
    BN_clear_free(c);
    BN_clear_free(y);
    BN_clear_free(qpow_u);
    BN_clear_free(qpow_v);
    BN_CTX_free(ctx);

    if(buf) pfree(buf);

    return err;
}
