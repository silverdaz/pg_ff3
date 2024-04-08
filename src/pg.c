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

#include "miscadmin.h"
#include "utils/guc.h"

PG_MODULE_MAGIC; /* only one time */

/* global settings */
void _PG_init(void);
void _PG_fini(void);


static bool
ff3_non_empty_check_hook(char **newval, void **extra, GucSource source)
{

  if (source == PGC_S_DEFAULT){
    GUC_check_errmsg("%s.%% ignored when setting default value", FF3_PREFIX);
    GUC_check_errhint("%s.%% can only be set from postgres.conf.", FF3_PREFIX);
    return true;
  }

  if (source != PGC_S_FILE){
    GUC_check_errmsg("%s.%% ignored when source source is not %d", FF3_PREFIX, PGC_S_FILE);
    GUC_check_errhint("%s.%% can only be set from postgres.conf.", FF3_PREFIX);
    return false;
  }

  if (**newval == '\0'){
    GUC_check_errmsg("%s.%% can't be empty.", FF3_PREFIX);
    return false;
  }

  return true;
}

static const char*
ff3_no_show_hook(void)
{
  return "yeah... nice try!";
}


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

  /* Register the master key passphrase (for the pseudonymization) */
  DefineCustomStringVariable(FF3_PREFIX ".passphrase",
			     gettext_noop("The FF3 master passphrase for key derivation."),
			     NULL,
			     &pg_ff3_passphrase,
			     NULL, /* no default */
			     PGC_POSTMASTER,
 			     GUC_SUPERUSER_ONLY |
			     GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE |
			     GUC_DISALLOW_IN_AUTO_FILE |
			     GUC_NOT_WHILE_SEC_REST | GUC_NO_RESET_ALL,
			     ff3_non_empty_check_hook, NULL, ff3_no_show_hook);

  DefineCustomStringVariable(FF3_PREFIX ".tweak",
			     gettext_noop("The FF3 master tweak."),
			     NULL,
			     &pg_ff3_tweak,
			     NULL, /* no default */
			     PGC_POSTMASTER,
 			     GUC_SUPERUSER_ONLY |
			     GUC_NO_SHOW_ALL | GUC_NOT_IN_SAMPLE |
			     GUC_DISALLOW_IN_AUTO_FILE |
			     GUC_NOT_WHILE_SEC_REST | GUC_NO_RESET_ALL,
			     ff3_non_empty_check_hook, NULL, ff3_no_show_hook);

  DefineCustomStringVariable("ff3.group",
			     gettext_noop("Group for pseudonymization."),
			     NULL,
			     &pg_ff3_group,
			     "pseudonymized",
			     PGC_SUSET,
			     GUC_SUPERUSER_ONLY,
			     NULL, NULL, NULL);

  /* Init OPENSSL */
  EVP_add_cipher(EVP_aes_256_ecb());

  MarkGUCPrefixReserved(FF3_PREFIX);
}

/*
 * This gets called when the library file is unloaded.
 */
void
_PG_fini(void)
{
  D3("Postgres: cleaning");

  if(pg_ff3_master_engine.evp)
    EVP_CIPHER_CTX_free(pg_ff3_master_engine.evp);

  pg_ff3_master_engine_initialized = 0;
}




PG_FUNCTION_INFO_V1(pg_ff3_encrypt);
Datum
pg_ff3_encrypt(PG_FUNCTION_ARGS)
{
  text* plaintext = NULL;
  text* ciphertext = NULL;
  ff3_engine_t* engine = NULL;
  unsigned int key_id;
  uint8_t *ptext = NULL;
  uint8_t *ctext = NULL;
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

  ciphertext = (text *)palloc0(len + VARHDRSZ); /* cleaned with function context */
  if(!ciphertext){
    E("Can't allocate memory for the ciphertext");
    PG_RETURN_NULL();
  }
  SET_VARSIZE(ciphertext, len + VARHDRSZ);

  ptext = (uint8_t *)palloc0(len * sizeof(uint8_t));
  ctext = (uint8_t *)palloc0(len * sizeof(uint8_t));
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

    ptext[i] = (uint8_t)(pos - (unsigned char*)engine->alphabet);
  }

  if(ff3_encrypt(engine, ptext, len, ctext))
    E("FF3 encrypt error");

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
  uint8_t *ptext = NULL;
  uint8_t *ctext = NULL;
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

  plaintext = (text *)palloc0(len + VARHDRSZ); /* cleaned with function context */
  if(!plaintext)
    E("Can't allocate memory for the plaintext");

  SET_VARSIZE(plaintext, len + VARHDRSZ);

  ptext = (uint8_t *)palloc0(len * sizeof(unsigned int));
  ctext = (uint8_t *)palloc0(len * sizeof(unsigned int));
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

    ctext[i] = (uint8_t)(pos - (unsigned char*)engine->alphabet);
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
