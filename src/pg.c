/*-------------------------------------------------------------------------
 *
 * src/pg.c
 *
 * Implementation of FF3-1 inside PG.
 * See documentation: https://www.postgresql.org/docs/current/xfunc-c.include
 *
 *-------------------------------------------------------------------------
 */

#include "includes.h"

/* these headers are used by this particular worker's code */
#include "funcapi.h"
//#include "access/xact.h"
#include "executor/spi.h"
//#include "lib/stringinfo.h"
#include "utils/builtins.h" /* for hex_decode */
//#include "utils/snapmgr.h"
//#include "tcop/utility.h"
#include "utils/memutils.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "pgstat.h"
//#include "libpq/pqsignal.h" /* for pqsignal */
#include "tcop/tcopprot.h" /* for "debug_query_string" */
#include "miscadmin.h"
//#include "common/base64.h"
#include "utils/guc.h"


PG_MODULE_MAGIC; /* only one time */

/* global settings */
static char *pg_ff3_database = NULL;

static ff3_engine_t *engines = NULL;
static unsigned int nengines = 0;
static unsigned int invalid_cache = 1;

MemoryContext root_mctx = NULL;

void _PG_init(void);
void _PG_fini(void);

/*
 * This gets called when the library file is loaded.
 * Similar to dlopen
 */
void
_PG_init(void)
{
  if (!process_shared_preload_libraries_in_progress)
    {
      ereport(ERROR, (errmsg("pg_ff3 can only be loaded via shared_preload_libraries"),
		      errhint("Add pg_ff3 to the shared_preload_libraries "
			      "configuration variable in postgresql.conf.")));
    }

  // W("Shared libs: %s", shared_preload_libraries_string);

  DefineCustomStringVariable("ff3.database",
			     gettext_noop("Database in which pg_ff3 metadata is kept."),
			     NULL,
			     &pg_ff3_database,
			     "postgres",
			     PGC_SUSET, //PGC_USERSET, /* GucContext */
			     GUC_SUPERUSER_ONLY,
			     NULL, NULL, NULL);

  /* Init OPENSSL */
  //EVP_add_cipher(EVP_aes_256_cbc());
  EVP_add_cipher(EVP_aes_256_ecb());

  MarkGUCPrefixReserved(FF3_PREFIX);
}

#define FF3_CHECK_TYPE(p, t, n) \
  if(TupleDescAttr(SPI_tuptable->tupdesc, (p))->atttypid != (t)){ \
    F("SPI_execute: invalid type %d: %s", (p), (n)); }

/*
 * This gets called when the library file is unloaded.
 */
void
_PG_fini(void)
{
  D3("Postgres: cleaning");
}



/*
 * Build the list of ff3 engines.
 * assumes:
 *  - nengines == 0
 *  - engines == NULL
 *  - root_mctx == NULL
 */
static void
build_cache(void)
{
  int ret = 0;
  bool is_null;
  MemoryContext   oldcontext;
  unsigned int i;
  ff3_engine_t *curr = NULL;
  Datum d;
  unsigned char t; /* for adjusting the tweak */

  static char* ff3_keys_query = "SELECT id, key, tweak, alphabet "
		                "FROM ff3.keys WHERE is_enabled ";
                                // "ORDER BY id DESC";

  /* Allocate the memory context for long-lived objects */
  D3("Creating memory context");
  root_mctx = AllocSetContextCreate(TopMemoryContext,
				    "pg_ff3",
				    ALLOCSET_DEFAULT_MINSIZE,
				    ALLOCSET_DEFAULT_INITSIZE,
				    ALLOCSET_DEFAULT_MAXSIZE);

  /* Connect */
  ret = SPI_connect();
  if (ret != SPI_OK_CONNECT)
    F("SPI_connect failed: error code %d", ret);

  /* Execute the query */
  debug_query_string = ff3_keys_query;
  pgstat_report_activity(STATE_RUNNING, ff3_keys_query);

  /* We can now execute queries via SPI */
  ret = SPI_execute(ff3_keys_query, true /* read_only */, 0 /* count */);

  if(ret != SPI_OK_SELECT)
    F("SPI_execute failed: error code %d", ret);

  if(SPI_tuptable == NULL ||  SPI_processed == 0)
    goto bailout;

  /* Switch to long-lived memory context */
  oldcontext = MemoryContextSwitchTo(root_mctx);

  nengines = SPI_processed;
  engines = palloc0( nengines * sizeof(ff3_engine_t) );

  D3("Found %u FF3 contexts", nengines);
  
  for(i=0; i < nengines; i++){

    curr = &engines[i];

    /*
    FF3_CHECK_TYPE(1, INT4OID , "id");
    FF3_CHECK_TYPE(2, BYTEAOID, "key");
    FF3_CHECK_TYPE(3, BYTEAOID, "tweak");
    FF3_CHECK_TYPE(4, TEXTOID , "alphabet");
    */

    curr->id = DatumGetUInt32(SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 1, &is_null));
    if(is_null)
      F("The connection_id field can't be NULL for row %u", i);

    d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 2, &is_null);
    if(is_null)
      F("The key field can't be NULL for row %u", i);

    if(VARSIZE_ANY_EXHDR(d) != FF3_KEY_SIZE)
      F("The key field is expected to be %d bytes, but it is %d for row %u", i, FF3_KEY_SIZE, (unsigned int)VARSIZE_ANY_EXHDR(d));

    memcpy(curr->rev_key, VARDATA_ANY(d), FF3_KEY_SIZE);
    rev_bytes(curr->rev_key, FF3_KEY_SIZE);

    d = SPI_getbinval(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 3, &is_null);
    if(is_null)
      F("The tweak field can't be NULL for row %u", i);

    if(VARSIZE_ANY_EXHDR(d) != FF3_TWEAK_SIZE)
      F("The tweak field is expected to be %d bytes, but it is %d for row %u", i, FF3_TWEAK_SIZE, (unsigned int)VARSIZE_ANY_EXHDR(d));

    /* FF3-1: transform 56-bit to 64-bit tweak */
    memcpy(curr->tweak, VARDATA_ANY(d), FF3_TWEAK_SIZE);
    t = curr->tweak[3];
    curr->tweak[3] = (t & 0xF0);
    curr->tweak[7] = (t & 0x0F) << 4;

    if(!(curr->alphabet = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 4)))
      F("The radix field can't be NULL for row %u", i);

    curr->radix = (unsigned int) strlen(curr->alphabet); // less than 255
    
    //curr->username = SPI_getvalue(SPI_tuptable->vals[i], SPI_tuptable->tupdesc, 4);

    /*
     * maxlen for ff3-1:
     * = 2 * log_radix(2**96)
     * = 2 * log_radix(2**48 * 2**48)
     * = 2 * (log_radix(2**48) + log_radix(2**48))
     * = 2 * (2 * log_radix(2**48))
     * = 4 * log_radix(2**48)
     * = 4 * log2(2**48) / log2(radix)
     * = 4 * 48 / log2(radix)
     * = 192 / log2(radix)
     */
    curr->maxtxtlen = (double)192 / log2(curr->radix);

    /*
     * for ff3-1: radix**minlen >= 1000000
     *
     * therefore:
     *   minlen = ceil(log_radix(1000000))
     *          = ceil(log_10(1000000) / log_10(radix))
     *          = ceil(6 / log_10(radix))
     */
    curr->mintxtlen = ceil((double)6 / log10(curr->radix));
    if (curr->mintxtlen < 2 || curr->mintxtlen > curr->maxtxtlen)
      F("FF3 overflow");

    curr->evp = EVP_CIPHER_CTX_new();

    /* We use ECB mode, so we ignore the IV 
     * https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
     *
     * In this mode, we can afford to initialize the cipher once, and keep it around
     * In other modes, that would be different
     */
    if(!EVP_EncryptInit_ex2(curr->evp,
			    EVP_aes_256_ecb(),
			    (unsigned char*)curr->rev_key,
			    NULL, NULL)
       || !EVP_CIPHER_CTX_set_padding(curr->evp, 0) /* don't do any padding */ 
       )
      F("Couldn't initialize the AES cipher (ECB mode)");

  }

  invalid_cache = 0;
  MemoryContextSwitchTo(oldcontext);

bailout:

  SPI_finish();
  debug_query_string = NULL;
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);
}

static void
clean_cache(void)
{
  unsigned int i = 0;
  ff3_engine_t *engine = NULL;

  D3("Cleaning cache while destroying memory context");

  for(; i < nengines; i++){
    engine = &engines[i];
    EVP_CIPHER_CTX_free(engine->evp);
  }
  /* the rest is washed off when we clean the memory context */

  if(root_mctx) MemoryContextDelete(root_mctx);
  root_mctx = NULL;
  engines = NULL;
  nengines = 0;

  /* Don't bother unloading OpenSSL */
}


PG_FUNCTION_INFO_V1(pg_ff3_invalidate_cache_trigger);
Datum
pg_ff3_invalidate_cache_trigger(PG_FUNCTION_ARGS)
{
  TriggerData *trigdata = (TriggerData *) fcinfo->context;
  HeapTuple   rettuple;
   
  if (!CALLED_AS_TRIGGER(fcinfo))
    {
      ereport(ERROR, (errcode(ERRCODE_E_R_I_E_TRIGGER_PROTOCOL_VIOLATED),
		      errmsg("must be called as trigger")));
    }

  if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
    rettuple = trigdata->tg_newtuple;
  else
    rettuple = trigdata->tg_trigtuple;

  D3("Invalidating cache");
  invalid_cache = 1;

  return PointerGetDatum(rettuple);
}

PG_FUNCTION_INFO_V1(pg_ff3_rebuild_cache);
Datum
pg_ff3_rebuild_cache(PG_FUNCTION_ARGS)
{

  clean_cache();
  build_cache();

  PG_RETURN_NULL();
}

static ff3_engine_t *
find_engine(unsigned int id) {
  unsigned int i = 0;
  ff3_engine_t *c = NULL;

  if(invalid_cache){
    clean_cache();
    build_cache();
  }

  if(engines == NULL)
    return NULL;

  /* does handle nengines == 0 */
  for(; i < nengines; i++) {
    c = &engines[i];
    if(c->id == id) return c;
  }
  return NULL;
}


PG_FUNCTION_INFO_V1(pg_ff3_encrypt);
Datum
pg_ff3_encrypt(PG_FUNCTION_ARGS)
{
  text* plaintext = NULL;
  text* ciphertext = NULL;
  ff3_engine_t* engine = NULL;
  unsigned int key_id;
  unsigned int *ptext = NULL;
  unsigned int *ctext = NULL;
  unsigned int i, len;
  unsigned char *p = NULL;
  unsigned char *pos;


  if(PG_ARGISNULL(0) || PG_ARGISNULL(1)){
    E("Null arguments not accepted");
    PG_RETURN_NULL();
  }

  key_id = PG_GETARG_UINT32(0);

  if(!(engine = find_engine(key_id))){
    N("ff3 key %u not found", key_id);
    PG_RETURN_NULL(); /* not found */
  }

  plaintext = PG_GETARG_TEXT_PP(1);

  len = VARSIZE_ANY_EXHDR(plaintext);

  /* check the text length */
  if (len < engine->mintxtlen ||
      len > engine->maxtxtlen) {
    ereport(ERROR, (errmsg("FF3 invalid text size %u", len),
		    errhint("FF3 min: %u | max: %u", engine->mintxtlen, engine->maxtxtlen)));
    PG_RETURN_NULL();
  }

  ciphertext = (text *)palloc0(len + VARHDRSZ);
  /* cleaned with function context */

  if(!ciphertext){
    E("Can't allocate memory for the ciphertext");
    PG_RETURN_NULL();
  }
  SET_VARSIZE(ciphertext, len + VARHDRSZ);

  ptext = (unsigned int *)palloc0(len * sizeof(unsigned int));
  ctext = (unsigned int *)palloc0(len * sizeof(unsigned int));
  if(!ptext || !ctext)
    PG_RETURN_NULL(); /* clean up handled by function memory context */

  p = (unsigned char*)VARDATA_ANY(plaintext);

  D2("Initial plaintext: %.*s | len: %d", len, p, len);
  D2("Initial alphabet %s", engine->alphabet);

  /* map chars */
  for (i = 0; i < len; ++i){
    if(p[i] == '\0')
      ereport(ERROR, (errmsg("invalid NULL char in the text")));

    pos = (unsigned char*)strchr(engine->alphabet, p[i]);
    if(pos == NULL)
      ereport(ERROR, (errmsg("character %c not found in the alphabet %.*s", p[i], engine->radix, engine->alphabet)));

    ptext[i] = (unsigned int)(pos - (unsigned char*)engine->alphabet);
  }

  if(ff3_encrypt(engine, ptext, len, ctext))
    E("FF3 decrypt error");

  p = (unsigned char*)VARDATA_ANY(ciphertext);
  /* reverse map chars */
  for (i = 0; i < len; ++i){
    assert( ctext[i] < engine->radix );
    p[i] = engine->alphabet[ctext[i]];
  }
  
  PG_RETURN_TEXT_P(ciphertext);
}


PG_FUNCTION_INFO_V1(pg_ff3_decrypt);
Datum
pg_ff3_decrypt(PG_FUNCTION_ARGS)
{
  text* plaintext = NULL;
  text* ciphertext = NULL;
  ff3_engine_t* engine = NULL;
  unsigned int key_id;
  unsigned int *ptext = NULL;
  unsigned int *ctext = NULL;
  unsigned int i, len;
  unsigned char *p = NULL;
  unsigned char *pos;

  if(PG_ARGISNULL(0) || PG_ARGISNULL(1)){
    E("Null arguments not accepted");
    PG_RETURN_NULL();
  }

  key_id = PG_GETARG_UINT32(0);

  if(!(engine = find_engine(key_id))){
    N("ff3 key %u not found", key_id);
    PG_RETURN_NULL(); /* not found */
  }

  ciphertext = PG_GETARG_TEXT_PP(1);

  len = VARSIZE_ANY_EXHDR(ciphertext);

  /* check the text length */
  if (len < engine->mintxtlen ||
      len > engine->maxtxtlen) {
    ereport(ERROR, (errmsg("FF3 invalid text size %u", len),
		    errhint("FF3 min: %u | max: %u", engine->mintxtlen, engine->maxtxtlen)));
    PG_RETURN_NULL();
  }

  plaintext = (text *)palloc0(len + VARHDRSZ);
  /* cleaned with function context */

  if(!plaintext)
    E("Can't allocate memory for the plaintext");

  SET_VARSIZE(plaintext, len + VARHDRSZ);

  ptext = (unsigned int *)palloc0(len * sizeof(unsigned int));
  ctext = (unsigned int *)palloc0(len * sizeof(unsigned int));
  if(!ptext || !ctext)
    PG_RETURN_NULL(); /* clean up handled by function memory context */

  p = (unsigned char*)VARDATA_ANY(ciphertext);

  D2("Initial ciphertext: %.*s | len: %d", len, p, len);
  D2("Initial alphabet %s", engine->alphabet);

  /* map chars */
  for (i = 0; i < len; ++i){
    if(p[i] == '\0')
      ereport(ERROR, (errmsg("invalid NULL char in the text")));

    pos = (unsigned char*)strchr(engine->alphabet, p[i]);
    if(pos == NULL)
      ereport(ERROR, (errmsg("character %c not found in the alphabet %.*s", p[i], engine->radix, engine->alphabet)));

    ctext[i] = (unsigned int)(pos - (unsigned char*)engine->alphabet);
  }

  if(ff3_decrypt(engine, ctext, len, ptext))
    E("FF3 decrypt error");

  p = (unsigned char*)VARDATA_ANY(plaintext);
  /* reverse map chars */
  for (i = 0; i < len; ++i){
    assert( ptext[i] < engine->radix );
    p[i] = engine->alphabet[ptext[i]];
  }
  
  PG_RETURN_TEXT_P(plaintext);
}
