#!/usr/bin/env bash
# Runs the given command (default: cargo test --workspace) against a
# throwaway PostgreSQL cluster in a fresh temporary directory. Needs initdb and
# pg_ctl on PATH, unless OCB_TEST_DATABASE_URL is already set.
set -euo pipefail

if [[ -n "${OCB_TEST_DATABASE_URL:-}" ]]; then
  if [[ $# -eq 0 ]]; then exec cargo test --workspace; else exec "$@"; fi
fi

for bin in initdb pg_ctl; do
  command -v "$bin" >/dev/null || { echo "$bin not found: install PostgreSQL or set OCB_TEST_DATABASE_URL" >&2; exit 1; }
done

workdir="$(mktemp -d "${TMPDIR:-/tmp}/ocb-pg.XXXXXX")"
port="${OCB_TEST_PG_PORT:-55432}"

cleanup() {
  pg_ctl -D "$workdir/data" -m immediate stop >/dev/null 2>&1 || true
  # Only ever remove the directory mktemp created above.
  case "$workdir" in
    */ocb-pg.*) rm -r -f -- "$workdir" ;;
  esac
}
trap cleanup EXIT

export LC_ALL=C
initdb -D "$workdir/data" -U postgres --auth=trust -E UTF8 --no-locale >/dev/null
pg_ctl -D "$workdir/data" -l "$workdir/log" -w \
  -o "-p $port -k '' -c listen_addresses=127.0.0.1 -c fsync=off -c max_connections=300" start >/dev/null

export OCB_TEST_DATABASE_URL="postgres://postgres@127.0.0.1:$port/postgres"
if [[ $# -eq 0 ]]; then
  cargo test --workspace
else
  "$@"
fi
