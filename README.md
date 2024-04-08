# FF3-1 in Postgres

We provide a C module, as a Postgres extension, to pseudonymize text data.

	make
	make install

And create the extension

	psql 'postgresql://superuser@localhost:5432/database' -c "CREATE EXTENSION pg_ff3;"

Update the postgresql.conf file with

	shared_preload_libraries = 'pg_ff3'
	ff3.passphrase = 'super-secret'
	ff3.tweak = 'some-random-text'
	ff3.group = 'some-group-name'

Insert information in the proper schema.table for the keys

	INSERT INTO ff3.keys(key,tweak,alphabet)
	VALUES ('\xEF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C'::bytea,
	        '\x61626364656667'::bytea,
			'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
	ON CONFLICT DO NOTHING;"

Moreover, for all database users belonging to the group `some-group-name`, the ff3.int8 output is pseudonymized with an HMAC-SHA256 of the connected username using the above parameters.  
The superuser bypasses the pseudonymization.

## Encrypting and decrypting some word

```sql
WITH encrypted AS (
	SELECT ff3.encrypt(<KEY-ID>, '<some-word>')
), decrypted AS (
	SELECT ff3.decrypt(<SAME-KEY-ID>, e.encrypt) FROM encrypted e
)
SELECT '<some-word>' AS original,
	   encrypted.encrypt AS enc,
	   decrypted.decrypt AS dec,
	   (decrypted.decrypt = '<some-word>') as match
FROM encrypted, decrypted;
```

## Pseudonymized output for bigint: ff3.int8

As the superuser:

```sql
database=# CREATE TABLE testing ( id ff3.int8 PRIMARY KEY, content text);
database=# GRANT SELECT ON testing TO pseudo; # user in the group to force pseudonymization
database=# GRANT SELECT ON testing TO regular; # user bypassing pseudonymization
database=# INSERT INTO testing VALUES (123, 'some text'), (456, 'some other text');
```


As the superuser (or a user _not_ in the group `some-group-name`, say `regular`):

```sql
database=# SELECT * FROM testing;
         id         |   description
--------------------+-----------------
 000000000000000123 | some text
 000000000000000456 | some other text
(2 rows)
```

As the user in the group `some-group-name` (say `pseudo`):

```sql
database=> SELECT * FROM testing;
         id         |   description
--------------------+-----------------
 555990810600631752 | some text
 706703104394323215 | some other text
 (2 rows)
```

Internally, the `ff3.int8` _is_ a bigint in the range `[0, 999999999999999999]` that gets displayed over 18 chars, padded with zeros.
