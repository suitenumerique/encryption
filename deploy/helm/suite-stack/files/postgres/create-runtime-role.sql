-- The role the server connects with (`DATABASE_URL`). Data only: it can read and write
-- rows but cannot create, alter or drop anything, so a compromised server cannot
-- rewrite the schema, and a migration cannot run by accident from a pod.
--
-- Run once, after create-migrator-role.sql, connected as the same administrator:
--   psql "$ADMIN_DATABASE_URL" -v password="'<strong password>'" -f deploy/postgres/create-runtime-role.sql
\set ON_ERROR_STOP on

CREATE ROLE encryption_runtime LOGIN PASSWORD :password;

GRANT USAGE ON SCHEMA encryption TO encryption_runtime;

-- Tables that already exist (none on a fresh database, all of them on an existing one).
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA encryption TO encryption_runtime;

-- Tables that future migrations create: without this line every release that adds a
-- table would need a manual GRANT before the server can use it. It applies to objects
-- created by the migrator role, so it must be run by a superuser or by a member of
-- that role (the administrator who created it, in PostgreSQL 16 and later).
ALTER DEFAULT PRIVILEGES FOR ROLE encryption_migrator IN SCHEMA encryption
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO encryption_runtime;
