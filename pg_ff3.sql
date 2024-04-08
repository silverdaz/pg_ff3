-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_ff3" to load this file. \quit

DO $$
BEGIN
   IF pg_catalog.current_setting('ff3.group') IS NULL OR
      pg_catalog.current_setting('ff3.group') = ''
   THEN
      RAISE EXCEPTION '% must be set', pg_catalog.current_setting('ff3.group')
      USING DETAIL = 'The group where members see pseudonymized IDs is not set.',
            HINT = 'Add ff3.group = ''...'' in postgresql.conf to chosen existing group.';
   END IF;
END;
$$;

CREATE SCHEMA ff3;

CREATE SEQUENCE ff3.keys_seq;

CREATE TABLE ff3.keys (
       id         integer PRIMARY KEY DEFAULT pg_catalog.nextval('ff3.keys_seq'),
       key        bytea NOT NULL CHECK(length(key) = 32), -- 256 bits
       tweak      bytea NOT NULL CHECK(length(tweak) = 7), -- 56 bits for FF3-1
       alphabet   varchar(255) NOT NULL DEFAULT '0123456789' CHECK(length(alphabet) >=2),
                                                             -- AND length(alphabet) <=255,
       is_enabled boolean NOT NULL DEFAULT TRUE,
       comment    text,

       UNIQUE(key,tweak,alphabet,is_enabled),

       -- auditing
       created_by  text NOT NULL DEFAULT CURRENT_USER,
       created_at  timestamp(6) with time zone NOT NULL DEFAULT now(),
       edited_by   text NOT NULL DEFAULT CURRENT_USER,
       edited_at   timestamp(6) with time zone NOT NULL DEFAULT now()
);

-- GRANT SELECT ON ff3.keys TO public;

ALTER TABLE ff3.keys ENABLE ROW LEVEL SECURITY;
CREATE POLICY ff3_keys_policy ON ff3.keys USING (created_by = current_user);


-- ########################
--     Pseudo Int8 Type
-- ########################

CREATE FUNCTION ff3.int8in(cstring)
RETURNS ff3.int8
AS 'MODULE_PATHNAME', 'pg_ff3_int8in'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.int8out(ff3.int8)
RETURNS cstring
AS 'MODULE_PATHNAME', 'pg_ff3_int8out'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.int8recv(internal)
RETURNS ff3.int8
AS 'MODULE_PATHNAME', 'pg_ff3_int8recv'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.int8send(ff3.int8)
RETURNS bytea
AS 'MODULE_PATHNAME', 'pg_ff3_int8send'
LANGUAGE C IMMUTABLE STRICT;


CREATE TYPE ff3.int8 (
   input = ff3.int8in,
   output = ff3.int8out,
   send = ff3.int8send,
   receive = ff3.int8recv,
   LIKE = int8,
   category = 'N',
   COLLATABLE = false
);


CREATE FUNCTION ff3.int48(v int4)
RETURNS ff3.int8
-- AS 'SELECT v::bigint::ff3.int8;'
-- LANGUAGE SQL IMMUTABLE STRICT;
AS 'MODULE_PATHNAME', 'pg_ff3_int48'
LANGUAGE C IMMUTABLE STRICT;

--CREATE CAST (int2 AS ff3.int8) WITHOUT FUNCTION AS IMPLICIT;
CREATE CAST (int4 AS ff3.int8) WITH FUNCTION ff3.int48 AS IMPLICIT;
CREATE CAST (int8 AS ff3.int8) WITHOUT FUNCTION AS IMPLICIT;
CREATE CAST (ff3.int8 AS int8) WITHOUT FUNCTION AS IMPLICIT;

-- We can't guarantee that the postgres non-negative int64 in base-10 won't be encrypted into another 
-- base-10 number that fits the range of int64. Moreover, we don't want to encrypt into negative numbers.
-- Postgres numeric values are signed.
--
-- max bigint is 9223372036854775807 = 2^63-1 = (~0) >> 1
-- In base 10, max bigint is 19 chars long = (MAXINT8LEN - 1) (ignoring negative numbers)
--
-- Therefore, we choose to limit the encryptable number to a digit less, ie MAXBIGINT / 10.
-- (that is, 18 nines)
--
CREATE DOMAIN ff3.int8domain AS ff3.int8 CHECK( VALUE::int8 >= 0 AND VALUE::int8 < 999999999999999999);


CREATE FUNCTION ff3.eq(ff3.int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_eq'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.lt(ff3.int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_lt'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.gt(ff3.int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_gt'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.le(ff3.int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_le'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.ge(ff3.int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_ge'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.cmp(ff3.int8, ff3.int8)
RETURNS int
AS 'MODULE_PATHNAME', 'pg_ff3_int8_cmp'
LANGUAGE C IMMUTABLE STRICT;

------------------------

CREATE FUNCTION ff3.eq(ff3.int8, int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_eq'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.lt(ff3.int8, int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_lt'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.gt(ff3.int8, int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_gt'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.le(ff3.int8, int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_le'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.ge(ff3.int8, int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_ge'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.cmp(ff3.int8, int8)
RETURNS int
AS 'MODULE_PATHNAME', 'pg_ff3_int8_cmp'
LANGUAGE C IMMUTABLE STRICT;

------------------------

CREATE FUNCTION ff3.eq(int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_eq'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.lt(int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_lt'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.gt(int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_gt'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.le(int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_le'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.ge(int8, ff3.int8)
RETURNS boolean
AS 'MODULE_PATHNAME', 'pg_ff3_int8_ge'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION ff3.cmp(int8, ff3.int8)
RETURNS int
AS 'MODULE_PATHNAME', 'pg_ff3_int8_cmp'
LANGUAGE C IMMUTABLE STRICT;

------------------------

CREATE FUNCTION ff3.sortsupport(internal)
RETURNS void
AS 'MODULE_PATHNAME', 'pg_ff3_int8_sortsupport'
LANGUAGE C IMMUTABLE STRICT;

------------------------

CREATE OPERATOR < (
    LEFTARG = ff3.int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.lt,
    COMMUTATOR = >, NEGATOR = >=,
    HASHES, MERGES
);

CREATE OPERATOR < (
    LEFTARG = int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.lt,
    COMMUTATOR = >, NEGATOR = >=,
    HASHES, MERGES
);

CREATE OPERATOR < (
    LEFTARG = ff3.int8, RIGHTARG = int8,
    FUNCTION = ff3.lt,
    COMMUTATOR = >, NEGATOR = >=,
    HASHES, MERGES
);

CREATE OPERATOR <= (
    LEFTARG = ff3.int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.le,
    COMMUTATOR = >=, NEGATOR = >,
    HASHES, MERGES
);

CREATE OPERATOR <= (
    LEFTARG = int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.le,
    COMMUTATOR = >=, NEGATOR = >,
    HASHES, MERGES
);

CREATE OPERATOR <= (
    LEFTARG = ff3.int8, RIGHTARG = int8,
    FUNCTION = ff3.le,
    COMMUTATOR = >=, NEGATOR = >,
    HASHES, MERGES
);

CREATE OPERATOR = (
    LEFTARG = ff3.int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.eq,
    COMMUTATOR = =, NEGATOR = !=,
    HASHES, MERGES
);

CREATE OPERATOR = (
    LEFTARG = int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.eq,
    COMMUTATOR = =, NEGATOR = !=,
    HASHES, MERGES
);

CREATE OPERATOR = (
    LEFTARG = ff3.int8, RIGHTARG = int8,
    FUNCTION = ff3.eq,
    COMMUTATOR = =, NEGATOR = !=,
    HASHES, MERGES
);

CREATE OPERATOR >= (
    LEFTARG = ff3.int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.ge,
    COMMUTATOR = <=, NEGATOR = <,
    HASHES, MERGES
);

CREATE OPERATOR >= (
    LEFTARG = int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.ge,
    COMMUTATOR = <=, NEGATOR = <,
    HASHES, MERGES
);

CREATE OPERATOR >= (
    LEFTARG = ff3.int8, RIGHTARG = int8,
    FUNCTION = ff3.ge,
    COMMUTATOR = <=, NEGATOR = <,
    HASHES, MERGES
);

CREATE OPERATOR > (
    LEFTARG = ff3.int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.gt,
    COMMUTATOR = <, NEGATOR = <=,
    HASHES, MERGES
);

CREATE OPERATOR > (
    LEFTARG = int8, RIGHTARG = ff3.int8,
    FUNCTION = ff3.gt,
    COMMUTATOR = >, NEGATOR = <=,
    HASHES, MERGES
);

CREATE OPERATOR > (
    LEFTARG = ff3.int8, RIGHTARG = int8,
    FUNCTION = ff3.gt,
    COMMUTATOR = >, NEGATOR = <=,
    HASHES, MERGES
);


CREATE OPERATOR CLASS ff3_int8_ops
    DEFAULT FOR TYPE ff3.int8 USING btree FAMILY integer_ops AS
        OPERATOR        1       <  (ff3.int8, ff3.int8) ,
        OPERATOR        2       <= (ff3.int8, ff3.int8) ,
        OPERATOR        3       =  (ff3.int8, ff3.int8) ,
        OPERATOR        4       >= (ff3.int8, ff3.int8) ,
        OPERATOR        5       >  (ff3.int8, ff3.int8) ,
	FUNCTION 	1 	ff3.cmp (ff3.int8, ff3.int8) ,
	FUNCTION 	2 	ff3.sortsupport(internal),

  	-- cross-type comparisons ff3.int8 vs int8
  	OPERATOR        1       <  (ff3.int8, int8) ,
  	OPERATOR 	2 	<= (ff3.int8, int8) ,
  	OPERATOR 	3 	=  (ff3.int8, int8) ,
  	OPERATOR 	4 	>= (ff3.int8, int8) ,
  	OPERATOR 	5 	>  (ff3.int8, int8) ,
  	FUNCTION 	1 	ff3.cmp (ff3.int8, int8) ,

  	-- cross-type comparisons int8 vs ff3.int8
  	OPERATOR        1       <  (int8, ff3.int8) ,
  	OPERATOR 	2 	<= (int8, ff3.int8) ,
  	OPERATOR 	3 	=  (int8, ff3.int8) ,
  	OPERATOR 	4 	>= (int8, ff3.int8) ,
  	OPERATOR 	5 	>  (int8, ff3.int8) ,
  	FUNCTION 	1 	ff3.cmp (int8, ff3.int8)
;

-- ########################
--     Main functions
-- ########################

CREATE FUNCTION ff3.encrypt(key_id integer, value text)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_ff3_encrypt'
LANGUAGE C IMMUTABLE; -- Don't make it STRICT
COMMENT ON FUNCTION ff3.encrypt(integer,text) IS 'pseudonymize the text using the given key criteria';


CREATE FUNCTION ff3.decrypt(key_id integer, value text)
RETURNS text
AS 'MODULE_PATHNAME', 'pg_ff3_decrypt'
LANGUAGE C IMMUTABLE; -- Don't make it STRICT
COMMENT ON FUNCTION ff3.decrypt(integer,text) IS 'reverse the pseudonymization of the text using the given key criteria';


CREATE FUNCTION ff3.reidentify(username text, value int8)
RETURNS int8
AS 'MODULE_PATHNAME', 'pg_ff3_reidentify'
LANGUAGE C IMMUTABLE; -- Don't make it STRICT
COMMENT ON FUNCTION ff3.reidentify(text,int8) IS 'reverse the pseudonymization of the text for the given user';

-- ########################
--       Utilities
-- ########################

CREATE FUNCTION ff3.rebuild_cache()
    RETURNS void
    LANGUAGE C
    AS 'MODULE_PATHNAME', 'pg_ff3_rebuild_cache';

CREATE FUNCTION ff3.invalidate_cache()
    RETURNS trigger
    LANGUAGE C
    AS 'MODULE_PATHNAME', 'pg_ff3_invalidate_cache_trigger';
COMMENT ON FUNCTION ff3.invalidate_cache() IS 'invalidate the engine list';

CREATE TRIGGER ff3_invalidate_cache
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE
ON ff3.keys
FOR STATEMENT EXECUTE PROCEDURE ff3.invalidate_cache();


CREATE FUNCTION ff3.update_edited_columns()
RETURNS trigger
LANGUAGE 'plpgsql'
AS $BODY$
BEGIN
    NEW.edited_at = now();
    NEW.edited_by_db_user = current_user;
    RETURN NEW;
END;
$BODY$;

CREATE TRIGGER ff3_keys_update_edited_columns 
BEFORE UPDATE ON ff3.keys
FOR EACH ROW EXECUTE PROCEDURE ff3.update_edited_columns();

SELECT pg_catalog.pg_extension_config_dump('ff3.keys', '');
SELECT pg_catalog.pg_extension_config_dump('ff3.keys_seq', '');
