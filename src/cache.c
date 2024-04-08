#include "includes.h"

#include "funcapi.h"
#include "executor/spi.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "pgstat.h"
#include "tcop/tcopprot.h" /* for "debug_query_string" */

#ifndef PG_MODULE_MAGIC /* only one time */
PG_MODULE_MAGIC; 
#endif

static ff3_engine_t *engines = NULL;
static unsigned int nengines = 0;
static unsigned int invalid_cache = 1;

//static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static MemoryContext root_mctx = NULL;


#define FF3_CHECK_TYPE(p, t, n) \
  if(TupleDescAttr(SPI_tuptable->tupdesc, (p))->atttypid != (t)){ \
    F("SPI_execute: invalid type %d: %s", (p), (n)); }

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

ff3_engine_t *
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
