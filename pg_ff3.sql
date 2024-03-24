-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_ff3" to load this file. \quit

DO $$
BEGIN
   IF pg_catalog.current_database() <> pg_catalog.current_setting('ff3.database') THEN
      RAISE EXCEPTION 'can only create extension in database %',
                      pg_catalog.current_setting('ff3.database')
      USING DETAIL = 'Keys must be declared from the database configured in ff3.database.',
            HINT = pg_catalog.format('Add ff3.database = ''%s'' in postgresql.conf to use the current database.',
	                              pg_catalog.current_database());
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


-- ########################
--        Utilities
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
