set -eu
state=$(mktemp -d /tmp/worker-pg.XXXXXX)
initdb -D "$state/data" --locale=C --auth-local=trust --auth-host=reject --no-instructions > "$state/init.log"
pg_ctl -D "$state/data" -l "$state/postgres.log" -o "-k $state -c listen_addresses=''" -w start > /dev/null
trap 'pg_ctl -D "$state/data" -m immediate -w stop >/dev/null' EXIT
psql -X -qAt -v ON_ERROR_STOP=1 -h "$state" -d postgres <<'SQL'
SHOW server_version;
CREATE ROLE fixture_reader;
CREATE TABLE demo_items (id integer PRIMARY KEY, label text NOT NULL);
INSERT INTO demo_items VALUES (7, 'book'), (9, 'pen');
GRANT SELECT ON TABLE demo_items TO fixture_reader;
SELECT 'before=' || encode(sha256(convert_to(jsonb_agg(to_jsonb(demo_items) ORDER BY id)::text, 'UTF8')), 'hex') FROM demo_items;
BEGIN READ ONLY;
SET LOCAL ROLE fixture_reader;
\echo constant_id_7
SELECT label FROM demo_items WHERE id = 7;
\echo normal_id_7
SELECT label FROM demo_items WHERE id = $1 \bind '7' \g
\echo other_id_9
SELECT label FROM demo_items WHERE id = $1 \bind '9' \g
\echo absent_id_13
SELECT label FROM demo_items WHERE id = $1 \bind '13' \g
COMMIT;
SELECT 'after=' || encode(sha256(convert_to(jsonb_agg(to_jsonb(demo_items) ORDER BY id)::text, 'UTF8')), 'hex') FROM demo_items;
SQL
