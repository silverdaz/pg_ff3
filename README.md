# FF3-1 in Postgres

We provide a C module, as a Postgres extension, to pseudonymize text data.

	make
	make install

And create the extension

	psql 'postgresql://superuser@localhost:5432/database' -c "CREATE EXTENSION pg_ff3;"

Update the postgresql.conf file with

	shared_preload_libraries = 'pg_ff3
	ff3.database = database_name  [default: 'postgres']

Insert information in the proper schema.table for the keys

	INSERT INTO ff3.keys(key,tweak,alphabet)
	VALUES ('\xEF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C'::bytea,
	        '\x61626364656667'::bytea,
			'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
	ON CONFLICT DO NOTHING;"


# Examples

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
