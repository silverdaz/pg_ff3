#include "includes.h"

#include "funcapi.h"
//#include "access/xact.h"
#include "executor/spi.h"
#include "lib/stringinfo.h"
#include "utils/builtins.h"
//#include "utils/snapmgr.h"
//#include "tcop/utility.h"
//#include "utils/memutils.h"
//#include "access/htup_details.h"
//#include "catalog/pg_type.h"
//#include "pgstat.h"
//#include "libpq/pqsignal.h" /* for pqsignal */
//#include "tcop/tcopprot.h" /* for "debug_query_string" */
#include "miscadmin.h"
#include "utils/acl.h"
#include "libpq/pqformat.h" /* for send/recv functions */
#include "catalog/pg_authid.h"
#include "utils/syscache.h"

#ifndef PG_MODULE_MAGIC /* only one time */
PG_MODULE_MAGIC; 
#endif

char *pg_ff3_group = NULL;
char *pg_ff3_passphrase = NULL;
char *pg_ff3_tweak = NULL;

ff3_engine_t pg_ff3_master_engine;
bool pg_ff3_master_engine_initialized = false;
static Oid last_oid = InvalidOid;

static int
ff3_create_engine(ff3_engine_t *engine, const char* username)
{

  OSSL_PARAM params[2];
  EVP_MAC *hmac = NULL;
  EVP_MAC_CTX *hmac_ctx = NULL;
  unsigned int mdlen;
  unsigned char digest[EVP_MAX_MD_SIZE];
  char t;
  int err=1;

  memset(engine, 0, sizeof(ff3_engine_t));
  
  //engine->id = 0;
  engine->radix = 10;
  engine->mintxtlen = 6;
  engine->maxtxtlen = 57;

  /* derive the master tweak */
  if(!EVP_Digest(pg_ff3_tweak, strlen(pg_ff3_tweak),
		 digest, &mdlen, EVP_sha256(), NULL)){
    N("pg_ff3 failed to create the master tweak context");
    err = 1;
    goto bailout;
  }

  /* we only take the first 56 bits */
  memcpy(engine->tweak, digest, FF3_TWEAK_SIZE+1);

  /* and adjust to 64 bits for FF3-1 */
  t = engine->tweak[3];
  engine->tweak[3] = (t & 0xF0);
  engine->tweak[7] = (t & 0x0F) << 4;

  /* derive the master key from the username */

  hmac = EVP_MAC_fetch(NULL, "HMAC", NULL);
  if (!hmac){
    N("pg_ff3 failed to fetch the master hmac");
    err = 2; 
    goto bailout;
  }
  
  hmac_ctx = EVP_MAC_CTX_new(hmac);
  if(!hmac_ctx){
    N("pg_ff3 failed to create the master hmac context");
    err = 3; 
    goto bailout;
  }

  params[0] = OSSL_PARAM_construct_utf8_string("digest", "sha256", 0);
  params[1] = OSSL_PARAM_construct_end();

  if(!EVP_MAC_init(hmac_ctx, (unsigned char*)pg_ff3_passphrase, strlen(pg_ff3_passphrase), params) ||
     !EVP_MAC_update(hmac_ctx, (unsigned char*)username, strlen(username)) ||
     !EVP_MAC_final(hmac_ctx, NULL, (size_t*)&mdlen, 0) ||
     mdlen != FF3_KEY_SIZE ||
     !EVP_MAC_final(hmac_ctx, engine->rev_key, (size_t*)&mdlen, FF3_KEY_SIZE)){
    D1(FF3_PREFIX " HMAC error | mdlen: %u | pseudo key size: %u", mdlen, FF3_KEY_SIZE);
    err = 4;
    goto bailout;
  }

#if 0
  {
    
    char *key = palloc0(FF3_KEY_SIZE*2);
    char *tweak = palloc0(FF3_TWEAK_SIZE*2+2);
    unsigned int i;
    for(i=0; i < FF3_KEY_SIZE; i++)
      sprintf(key+2*i, "%x", engine->rev_key[i]);
    for(i=0; i <= FF3_TWEAK_SIZE; i++)
      sprintf(tweak+2*i, "%x", engine->tweak[i]);
    
    N("ff3 master   key: %.*s", FF3_KEY_SIZE*2, key);
    N("ff3 master tweak: %.*s", FF3_TWEAK_SIZE*2+2, tweak);
    pfree(key);
    pfree(tweak);
  }
#endif

  rev_bytes(engine->rev_key, FF3_KEY_SIZE);

  engine->evp = EVP_CIPHER_CTX_new();
  if(!engine->evp ||
     !EVP_EncryptInit_ex2(engine->evp,
			  EVP_aes_256_ecb(),
			  (unsigned char*)engine->rev_key,
			  NULL, NULL)
     || !EVP_CIPHER_CTX_set_padding(engine->evp, 0) /* don't do any padding */ 
     ){
    D1("Couldn't initialize the AES cipher (ECB mode)");
    err = 5;
    goto bailout;
  }

  /* success */
  err = 0;

bailout:

  if(hmac_ctx) EVP_MAC_CTX_free(hmac_ctx);
  if(hmac) EVP_MAC_free(hmac);
  return err;
}

/*****************************************************************************
 * Input/Output functions
 *****************************************************************************
 *
 * We can't guarantee that the postgres non-negative int64 in base-10
 * won't be encrypted into another base-10 number that fits the range
 * of int64.  Postgres numeric values are signed.
 * 
 * max bigint is 9223372036854775807 = 2^63-1 = (~0) >> 1
 * In base 10, max bigint is 19 chars long = (MAXINT8LEN - 1) (accounting for negative numbers)
 *
 * Therefore, we choose to limit the encryptable number to a digit less, ie MAXBIGINT / 10.
 *
 * When we ouput the result, we always print it padded with zeros over 18 chars.
 */

#define FF3INT8LEN (MAXINT8LEN - 2) // 18 chars
static int64 max_ff3_int = 999999999999999999; // pow(10, FF3INT8LEN+1) - 1;

static void
ensure_master_engine()
{
  if( last_oid != GetUserId() || !pg_ff3_master_engine_initialized )
    {
      char *whoami = GetUserNameFromId(GetUserId(), false);
      //N(FF3_PREFIX " current user: %s", whoami);

      if(pg_ff3_master_engine.evp) EVP_CIPHER_CTX_free(pg_ff3_master_engine.evp);
      if(ff3_create_engine(&pg_ff3_master_engine, whoami))
	F("Couldn't initialize the pseudonymizer engine");

      last_oid = GetUserId();
      pg_ff3_master_engine_initialized = 1;
    }
}

static inline bool
has_replication(Oid role_id)
{
  bool		result = false;
  HeapTuple	utup;

  /* Superusers bypass all permission checking. */
  if (superuser_arg(role_id))
    return true;

  utup = SearchSysCache1(AUTHOID, ObjectIdGetDatum(role_id));
  if (HeapTupleIsValid(utup))
    {
      result = ((Form_pg_authid) GETSTRUCT(utup))->rolreplication;
      ReleaseSysCache(utup);
    }
  return result;
}

static inline bool
ff3_ignore(void)
{
  Oid current_id;
  Oid group_id;

  current_id = GetUserId(); // current user

  /* Superusers don't do pseudonymization */
  if(superuser_arg(current_id))
    return true;

  /* Replicators do pseudonymization */
  if(has_replication(current_id))
    return false;

  /* Group members of "pg_ff3_group" (if exists) do pseudonymization */
  group_id = get_role_oid(pg_ff3_group, true); // missing ok

  return (!OidIsValid(group_id) || !is_member_of_role(current_id, group_id));
}

PG_FUNCTION_INFO_V1(pg_ff3_int8in);
Datum
pg_ff3_int8in(PG_FUNCTION_ARGS)
{
  int64 val = pg_strtoint64_safe(PG_GETARG_CSTRING(0), fcinfo->context);
  // N(FF3_PREFIX " int8in: %ld", val);

  if( val > max_ff3_int || val < 0)
    E("FF3 out of range: %ld > %ld", val, max_ff3_int);
  
  PG_RETURN_INT64(val);
}

PG_FUNCTION_INFO_V1(pg_ff3_int8out);
Datum
pg_ff3_int8out(PG_FUNCTION_ARGS)
{
  int64	val = PG_GETARG_INT64(0);
  uint8_t ctext[FF3INT8LEN];
  uint8_t ptext[FF3INT8LEN];
  char *result = NULL;
  int	i;
  
  //N(FF3_PREFIX " int8out: %ld", val);

  if( val > max_ff3_int || val < 0)
    E("FF3 out of range: %ld > %ld", val, max_ff3_int);

  result = (char*)palloc0(FF3INT8LEN+1);
  if(!result)
    E("FF3 memory allocation error"); 
   
  result[FF3INT8LEN] = 0;
  /* Convert to decimal representation, padded with zeros */
  for (i = FF3INT8LEN-1; i >= 0; --i){
    ptext[i] = (uint8_t)(val % 10);
    result[i] = (char)(ptext[i] + '0');
    val /= 10;
  }

  if(ff3_ignore())
    goto skip;

  /* else we pseudonymize */
  ensure_master_engine();

  if(!EVP_CIPHER_CTX_reset(pg_ff3_master_engine.evp) ||
     !EVP_EncryptInit_ex2(pg_ff3_master_engine.evp,
			  EVP_aes_256_ecb(),
			  (unsigned char*)pg_ff3_master_engine.rev_key,
			  NULL, NULL)
     || !EVP_CIPHER_CTX_set_padding(pg_ff3_master_engine.evp, 0) /* don't do any padding */ 
     )
    F("Couldn't initialize the AES cipher (ECB mode)");

  if(ff3_encrypt(&pg_ff3_master_engine, ptext, FF3INT8LEN, ctext))
    E("FF3 encrypt error");

  for (i = 0; i < FF3INT8LEN; i++) result[i] = (char)(ctext[i] + '0');

skip:
  PG_RETURN_CSTRING(result);
}

PG_FUNCTION_INFO_V1(pg_ff3_int8recv);
Datum
pg_ff3_int8recv(PG_FUNCTION_ARGS)
{
  int64 val = pq_getmsgint64((StringInfo) PG_GETARG_POINTER(0));
  // N(FF3_PREFIX " int8recv");

  if( val > max_ff3_int || val < 0)
    E("FF3 out of range: %ld > %ld", val, max_ff3_int);
  
  PG_RETURN_INT64(val);
}

PG_FUNCTION_INFO_V1(pg_ff3_int8send);
Datum
pg_ff3_int8send(PG_FUNCTION_ARGS)
{
  int64	val = PG_GETARG_INT64(0);
  uint8_t ctext[FF3INT8LEN];
  uint8_t ptext[FF3INT8LEN];
  int	i;
  StringInfoData sbuf;

  if( val > max_ff3_int || val < 0)
    E("FF3 out of range: %ld > %ld", val, max_ff3_int);

  //N(FF3_PREFIX " int8send: %ld", val);

  if(ff3_ignore())
    goto skip;

  /* else we pseudonymize */
  ensure_master_engine();

  /* Convert to decimal representation, padded with zeros */
  for (i = FF3INT8LEN-1; i >= 0; --i){
    ptext[i] = (uint8_t)(val % 10);
    val /= 10;
  }

  if(!EVP_CIPHER_CTX_reset(pg_ff3_master_engine.evp) ||
     !EVP_EncryptInit_ex2(pg_ff3_master_engine.evp,
			  EVP_aes_256_ecb(),
			  (unsigned char*)pg_ff3_master_engine.rev_key,
			  NULL, NULL)
     || !EVP_CIPHER_CTX_set_padding(pg_ff3_master_engine.evp, 0) /* don't do any padding */ 
     )
    F("Couldn't initialize the AES cipher (ECB mode)");

  if(ff3_encrypt(&pg_ff3_master_engine, ptext, FF3INT8LEN, ctext))
    E("FF3 encrypt error");

  val = 0;
  for (i = 0; i < FF3INT8LEN; i++) val = val * 10 + ctext[i];

skip:

  pq_begintypsend(&sbuf);
  pq_sendint64(&sbuf, val);
  PG_RETURN_BYTEA_P(pq_endtypsend(&sbuf));
}


/*----------------------------------------------------------
 *	Relational operators for ff3.int8s
 *---------------------------------------------------------*/

PG_FUNCTION_INFO_V1(pg_ff3_int8_lt);
Datum
pg_ff3_int8_lt(PG_FUNCTION_ARGS)
{
  PG_RETURN_BOOL( PG_GETARG_INT64(0) < PG_GETARG_INT64(1) );
}

PG_FUNCTION_INFO_V1(pg_ff3_int8_le);
Datum
pg_ff3_int8_le(PG_FUNCTION_ARGS)
{
  PG_RETURN_BOOL( PG_GETARG_INT64(0) <= PG_GETARG_INT64(1) );
}

PG_FUNCTION_INFO_V1(pg_ff3_int8_eq);
Datum
pg_ff3_int8_eq(PG_FUNCTION_ARGS)
{
  PG_RETURN_BOOL( PG_GETARG_INT64(0) == PG_GETARG_INT64(1) );
}

PG_FUNCTION_INFO_V1(pg_ff3_int8_ge);
Datum
pg_ff3_int8_ge(PG_FUNCTION_ARGS)
{
  PG_RETURN_BOOL( PG_GETARG_INT64(0) >= PG_GETARG_INT64(1) );
}

PG_FUNCTION_INFO_V1(pg_ff3_int8_gt);
Datum
pg_ff3_int8_gt(PG_FUNCTION_ARGS)
{
  PG_RETURN_BOOL( PG_GETARG_INT64(0) > PG_GETARG_INT64(1) );
}

PG_FUNCTION_INFO_V1(pg_ff3_int8_cmp);
Datum
pg_ff3_int8_cmp(PG_FUNCTION_ARGS)
{
  int64 val1 = PG_GETARG_INT64(0);
  int64 val2 = PG_GETARG_INT64(1);
  PG_RETURN_INT32( (val1 < val2) ? -1 : ((val1 > val2) ? 1 : 0) );
}

PG_FUNCTION_INFO_V1(pg_ff3_int48);
Datum
pg_ff3_int48(PG_FUNCTION_ARGS)
{
  PG_RETURN_INT64( (int64)PG_GETARG_INT64(0) );
}


static int
bt_ff3_int8_fastcmp(Datum x, Datum y, SortSupport ssup)
{
  int64 val1 = DatumGetInt64(x);
  int64 val2 = DatumGetInt64(y);
  if (val1 < val2)
    return -1;
  else if (val1 > val2)
    return 1;
  else
    return 0;
}

PG_FUNCTION_INFO_V1(pg_ff3_int8_sortsupport);
Datum
pg_ff3_int8_sortsupport(PG_FUNCTION_ARGS)
{
  SortSupport ssup = (SortSupport) PG_GETARG_POINTER(0);
  ssup->comparator = bt_ff3_int8_fastcmp;
  PG_RETURN_VOID();
}



/*----------------------------------------------------------
 *	Re-indentification
 *---------------------------------------------------------*/

PG_FUNCTION_INFO_V1(pg_ff3_reidentify);
Datum
pg_ff3_reidentify(PG_FUNCTION_ARGS)
{
  int64	val;
  char* username = NULL;
  ff3_engine_t engine;
  uint8_t ptext[FF3INT8LEN];
  uint8_t ctext[FF3INT8LEN];
  int	i;
  char *err = NULL;

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1))
    E("Null arguments not accepted");

  val = PG_GETARG_INT64(1);

  if( val > max_ff3_int || val < 0)
    E("FF3 out of range: %ld > %ld", val, max_ff3_int);

  username = text_to_cstring(PG_GETARG_TEXT_PP(0)); /* clean on exiting the function */

  //N(FF3_PREFIX " reidentifying: %ld for %s", val, username);

  if(ff3_create_engine(&engine, username)){
    err = "Couldn't initialize the pseudonymizer engine";
    goto bailout;
  }

  engine.radix = 10;
  //engine.alphabet = "0123456789";

  /* Convert to decimal representation, padded with zeros */
  for (i = FF3INT8LEN-1; i >= 0; --i){
    ctext[i] = (uint8_t)(val % 10);
    val /= 10;
  }

  if(!EVP_CIPHER_CTX_reset(engine.evp) ||
     !EVP_EncryptInit_ex2(engine.evp,
			  EVP_aes_256_ecb(),
			  (unsigned char*)engine.rev_key,
			  NULL, NULL)
     || !EVP_CIPHER_CTX_set_padding(engine.evp, 0) /* don't do any padding */ 
     ){
    err = "Couldn't initialize the AES cipher (ECB mode)";
    goto bailout;
  }

  if(ff3_decrypt(&engine, ctext, FF3INT8LEN, ptext)){
    err = "FF3 encrypt error";
    goto bailout;
  }

  val = 0;
  for (i = 0; i < FF3INT8LEN; i++) val = val * 10 + ptext[i];

bailout:
  if(engine.evp) EVP_CIPHER_CTX_free(engine.evp);

  if(err) E("%s", err);

  PG_RETURN_INT64(val);
}
