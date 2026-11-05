#!/bin/sh
# Runs once, on the first start of the Postgres container: Fortik's database,
# owned by fortik_owner (runs migrations), and fortik_app (what `fortik serve`
# connects as: least privileges, cannot touch the Diary's append-only triggers).
set -eu
psql -v ON_ERROR_STOP=1 --username postgres <<SQL
CREATE ROLE fortik_owner LOGIN PASSWORD '${FORTIK_OWNER_PASSWORD}';
CREATE ROLE fortik_app LOGIN PASSWORD '${FORTIK_APP_PASSWORD}';
CREATE DATABASE fortik OWNER fortik_owner;
SQL
psql -v ON_ERROR_STOP=1 --username postgres -d fortik <<SQL
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE fortik TO fortik_app;
SQL
