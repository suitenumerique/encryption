-- The role that applies schema migrations (`prisma migrate deploy`). It owns the
-- `encryption` schema, so it is the only one allowed to create or alter tables, and it
-- is used once per release, never by the running server.
--
-- Everything lives in a dedicated schema rather than `public`: every role in a
-- database has USAGE on `public` (and CREATE, before PostgreSQL 15), so on a shared
-- server another application's role could list the tables. Nobody but the two roles
-- below gets as much as USAGE on `encryption`.
--
-- Run once, connected to the service's database as its administrator:
--   psql "$ADMIN_DATABASE_URL" -v password="'<strong password>'" -f deploy/postgres/create-migrator-role.sql
\set ON_ERROR_STOP on

CREATE ROLE encryption_migrator LOGIN PASSWORD :password;

CREATE SCHEMA encryption AUTHORIZATION encryption_migrator;

-- The first migration opens with `CREATE SCHEMA IF NOT EXISTS "encryption"`, and
-- PostgreSQL checks the CREATE privilege on the database BEFORE looking at whether the
-- schema already exists, so without this the migration fails with "permission denied
-- for database" even though the schema is there. `:DBNAME` is the database psql is
-- connected to.
GRANT CREATE ON DATABASE :"DBNAME" TO encryption_migrator;
