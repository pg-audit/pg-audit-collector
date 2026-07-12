#!/usr/bin/env python3
"""
PostgreSQL Metadata Collector
==============================
Collects diagnostic data from PostgreSQL system catalogs and outputs JSON.

WHAT IT DOES:
  17 SELECT queries that read ONLY system catalogs
  (pg_catalog, pg_stat_*, information_schema).
  User data is NEVER read or modified. No network calls.

SECURITY:
  - Connects in READ-ONLY mode (readonly=True)
  - Uses statement_timeout to prevent long queries
  - Searches only pg_catalog and public schemas
  - Every query is visible in this file — review it yourself

OUTPUT:
  audit_data_YYYYMMDD_HHMMSS.json — compatible with PG Audit Analyzer

USAGE:
  python3 pg_collector.py --host 192.168.1.1 --dbname mydb --user postgres

  All parameters are optional — defaults to localhost:5432/postgres/postgres

License: MIT
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import psycopg2
from psycopg2.extras import RealDictCursor

VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Embedded SQL queries
# ---------------------------------------------------------------------------
_PROBE_SQL = r"""
SET search_path = pg_catalog, public;

-- For reference when running manually (the wrapper gets version separately)
SELECT version() AS full_version, current_setting('server_version_num') AS version_num;


-- ====================================================================
-- 01. Global context: uptime, last statistics reset
-- ====================================================================
-- @section: global_context
-- @single_row
SELECT
    stats_reset,
    EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time())) / 3600 AS uptime_hours,
    EXTRACT(EPOCH FROM (now() - COALESCE(stats_reset, now()))) / 3600 AS stats_reset_hours
FROM pg_stat_database
WHERE datname = current_database();


-- ====================================================================
-- 02. Database statistics
--     Cache Hit Ratio, deadlocks, checksums, temp_files
-- ====================================================================
-- @section: database_stats
-- @single_row
SELECT
    datname,
    blks_hit,
    blks_read,
    CASE
        WHEN (blks_hit + blks_read) > 0
        THEN ROUND((blks_hit::numeric / (blks_hit + blks_read)::numeric) * 100, 2)
        ELSE 0
    END AS cache_hit_ratio,
    tup_returned,
    tup_fetched,
    tup_inserted,
    tup_updated,
    tup_deleted,
    COALESCE(temp_files, 0) AS temp_files,
    COALESCE(temp_bytes, 0) AS temp_bytes,
    COALESCE(deadlocks, 0) AS deadlocks,
    COALESCE(checksum_failures, 0) AS checksum_failures
FROM pg_stat_database
WHERE datname = current_database();


-- ====================================================================
-- 03. Database size
-- ====================================================================
-- @section: database_size
-- @single_row
SELECT
    pg_database_size(current_database()) AS size_bytes,
    pg_size_pretty(pg_database_size(current_database())) AS size_pretty;


-- ====================================================================
-- 04. Table statistics
--     Scans, tuples, sizes, last maintenance
-- ====================================================================
-- @section: table_stats
SELECT
    schemaname,
    relname,
    seq_scan,
    seq_tup_read,
    idx_scan,
    idx_tup_fetch,
    n_live_tup,
    n_dead_tup,
    last_analyze,
    last_autoanalyze,
    last_autovacuum,
    COALESCE(pg_relation_size(quote_ident(schemaname) || '.' || quote_ident(relname)), 0) AS heap_size,
    COALESCE(pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(relname)), 0) AS total_relation_size
FROM pg_stat_user_tables;


-- ====================================================================
-- 05. Index statistics
--     Usage, size, definition
-- ====================================================================
-- @section: index_stats
SELECT
    schemaname,
    relname AS tablename,
    indexrelname,
    idx_scan,
    COALESCE(pg_relation_size(indexrelid), 0) AS index_size,
    pg_get_indexdef(indexrelid) AS index_definition
FROM pg_stat_user_indexes;


-- ====================================================================
-- 06. Constraints: PRIMARY KEY
-- ====================================================================
-- @section: constraints_pk
-- @merge_into: constraints
SELECT
    ns.nspname AS table_schema,
    cls.relname AS table_name,
    attr.attname AS column_name,
    con.conname AS constraint_name,
    'PRIMARY KEY' AS constraint_type
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class cls ON con.conrelid = cls.oid
JOIN pg_catalog.pg_namespace ns ON cls.relnamespace = ns.oid
JOIN pg_catalog.pg_attribute attr
    ON attr.attrelid = con.conrelid AND attr.attnum = ANY (con.conkey)
WHERE con.contype = 'p'
  AND ns.nspname NOT IN ('pg_catalog', 'information_schema');


-- ====================================================================
-- 07. Constraints: FOREIGN KEY
-- ====================================================================
-- @section: constraints_fk
-- @merge_into: constraints
SELECT
    ns.nspname AS table_schema,
    cls.relname AS table_name,
    attr.attname AS column_name,
    fns.nspname AS foreign_table_schema,
    fcls.relname AS foreign_table_name,
    fattr.attname AS foreign_column_name,
    con.conname AS constraint_name,
    'FOREIGN KEY' AS constraint_type
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class cls ON con.conrelid = cls.oid
JOIN pg_catalog.pg_namespace ns ON cls.relnamespace = ns.oid
JOIN pg_catalog.pg_class fcls ON con.confrelid = fcls.oid
JOIN pg_catalog.pg_namespace fns ON fcls.relnamespace = fns.oid
JOIN pg_catalog.pg_attribute attr
    ON attr.attrelid = con.conrelid AND attr.attnum = ANY (con.conkey)
JOIN pg_catalog.pg_attribute fattr
    ON fattr.attrelid = con.confrelid AND fattr.attnum = ANY (con.conkey)
WHERE con.contype = 'f'
  AND ns.nspname NOT IN ('pg_catalog', 'information_schema');


-- ====================================================================
-- 08. Constraints: UNIQUE
-- ====================================================================
-- @section: constraints_unique
-- @merge_into: constraints
SELECT
    ns.nspname AS table_schema,
    cls.relname AS table_name,
    attr.attname AS column_name,
    con.conname AS constraint_name,
    'UNIQUE' AS constraint_type
FROM pg_catalog.pg_constraint con
JOIN pg_catalog.pg_class cls ON con.conrelid = cls.oid
JOIN pg_catalog.pg_namespace ns ON cls.relnamespace = ns.oid
JOIN pg_catalog.pg_attribute attr
    ON attr.attrelid = con.conrelid AND attr.attnum = ANY (con.conkey)
WHERE con.contype = 'u'
  AND ns.nspname NOT IN ('pg_catalog', 'information_schema');


-- ====================================================================
-- 09. Long-running transactions and idle in transaction
--     Thresholds: >1 hour (active), >10 min (idle in transaction).
--     Adjustable via --long-tx-hours and --idle-tx-minutes.
-- ====================================================================
-- @section: activity
SELECT
    pid,
    application_name,
    state,
    query_start,
    state_change,
    wait_event_type,
    wait_event,
    EXTRACT(EPOCH FROM (now() - query_start)) / 3600 AS duration_hours,
    EXTRACT(EPOCH FROM (now() - state_change)) / 60 AS state_duration_minutes
FROM pg_stat_activity
WHERE ((state = 'active' AND query_start IS NOT NULL
        AND EXTRACT(EPOCH FROM (now() - query_start)) / 3600 > 1.0)
   OR (state = 'idle in transaction' AND state_change IS NOT NULL
        AND EXTRACT(EPOCH FROM (now() - state_change)) / 60 > 10.0))
  AND pid <> pg_backend_pid();


-- ====================================================================
-- 10. Dead tuple ratio per table (top 50)
-- ====================================================================
-- @section: dead_tuple_ratio
SELECT
    schemaname,
    relname AS tablename,
    n_live_tup,
    n_dead_tup,
    CASE WHEN n_live_tup + n_dead_tup > 0
         THEN (n_dead_tup::float / (n_live_tup + n_dead_tup)::float) * 100
         ELSE 0
    END AS dead_tuple_percent
FROM pg_stat_user_tables
WHERE n_live_tup > 0
  AND n_dead_tup > 0
ORDER BY dead_tuple_percent DESC
LIMIT 50;


-- ====================================================================
-- 11. Table bloat estimation (dead tuple ratio > 10%)
-- ====================================================================
-- @section: bloat_check
SELECT
    schemaname,
    relname AS tablename,
    ROUND(CAST(COALESCE(
        CASE WHEN n_live_tup + n_dead_tup > 0
             THEN (n_dead_tup::float / (n_live_tup + n_dead_tup)::float) * 100
             ELSE 0
        END, 0) AS numeric), 2) AS bloat_percent,
    ROUND(CAST(COALESCE(
        CASE WHEN n_live_tup + n_dead_tup > 0
             THEN (n_dead_tup::float / (n_live_tup + n_dead_tup)::float)
                  * pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(relname))
                  / 1024 / 1024
             ELSE 0
        END, 0) AS numeric), 2) AS bloat_mb
FROM pg_stat_user_tables
WHERE n_live_tup > 0
  AND n_dead_tup > 0
  AND (n_dead_tup::float / (n_live_tup + n_dead_tup)::float) > 0.10
ORDER BY bloat_mb DESC
LIMIT 20;


-- ====================================================================
-- 12. Table column structure
--     Used to detect boolean columns and low-cardinality columns
--     for partial index recommendations.
-- ====================================================================
-- @section: table_columns
SELECT
    n.nspname AS table_schema,
    c.relname AS table_name,
    a.attname AS column_name,
    pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type,
    a.attnotnull AS is_not_null,
    a.attnum AS ordinal_position
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON a.attrelid = c.oid
JOIN pg_catalog.pg_namespace n ON c.relnamespace = n.oid
WHERE a.attnum > 0
  AND NOT a.attisdropped
  AND c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
ORDER BY n.nspname, c.relname, a.attnum;


-- ====================================================================
-- 13. Per-table autovacuum settings
-- ====================================================================
-- @section: autovacuum_settings
SELECT
    n.nspname AS schemaname,
    c.relname,
    c.reloptions AS table_options,
    current_setting('autovacuum_vacuum_scale_factor') AS global_vacuum_scale_factor,
    current_setting('autovacuum_analyze_scale_factor') AS global_analyze_scale_factor,
    current_setting('autovacuum') AS autovacuum_enabled_global
FROM pg_class c
JOIN pg_namespace n ON c.relnamespace = n.oid
WHERE c.relkind = 'r'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast');


-- ====================================================================
-- 14. Key server settings
-- ====================================================================
-- @section: server_settings
SELECT
    name, setting, unit, short_desc
FROM pg_settings
WHERE name IN (
    'work_mem',
    'log_min_duration_statement',
    'idle_session_timeout',
    'idle_in_transaction_session_timeout',
    'shared_buffers',
    'effective_cache_size',
    'max_connections',
    'random_page_cost',
    'effective_io_concurrency',
    'autovacuum_max_workers',
    'autovacuum_naptime'
);


-- ====================================================================
-- 15. Idle connections summary
-- ====================================================================
-- @section: idle_connections
SELECT
    state,
    COUNT(*) AS count,
    MAX(EXTRACT(EPOCH FROM (now() - state_change)) / 60) AS max_idle_minutes
FROM pg_stat_activity
WHERE pid <> pg_backend_pid()
  AND state IN ('idle', 'idle in transaction')
GROUP BY state;


-- ====================================================================
-- 16. Sequence exhaustion risk
-- ====================================================================
-- @section: sequences
SELECT
    schemaname,
    sequencename,
    last_value,
    max_value,
    CASE WHEN max_value > 0
         THEN ROUND((last_value::numeric / max_value::numeric) * 100, 2)
         ELSE 0
    END AS usage_percent,
    data_type
FROM pg_sequences
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND last_value > 0;


-- ====================================================================
-- 17. Loaded shared libraries (pg_stat_statements check)
-- ====================================================================
-- @section: shared_preload_libraries
-- @single_row
SELECT current_setting('shared_preload_libraries') AS shared_preload_libraries;
"""


# ---------------------------------------------------------------------------
# Type normalization (psycopg2 returns Decimal for NUMERIC columns)
# ---------------------------------------------------------------------------
def _norm(obj):
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, dict):
        return {k: _norm(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_norm(i) for i in obj]
    if isinstance(obj, datetime):
        return obj.isoformat()
    return obj


# ---------------------------------------------------------------------------
# SQL parser — extracts sections by @section / @single_row / @merge_into
# ---------------------------------------------------------------------------
def parse_sql(sql: str) -> tuple[list[dict], str]:
    sha = hashlib.sha256(sql.encode("utf-8")).hexdigest()

    sections: list[dict] = []
    cur: dict | None = None

    for line in sql.split("\n"):
        m = re.match(r"^\s*--\s*@section:\s*(\w+)", line)
        if m:
            if cur:
                sections.append(cur)
            cur = {"key": m.group(1), "single_row": False, "merge_into": None, "sql": ""}
            continue

        if cur is None:
            continue

        if re.match(r"^\s*--\s*@single_row", line):
            cur["single_row"] = True
        elif (mm := re.match(r"^\s*--\s*@merge_into:\s*(\w+)", line)):
            cur["merge_into"] = mm.group(1)
        elif not line.strip().startswith("--"):
            cur["sql"] += line + "\n"

    if cur:
        sections.append(cur)

    return sections, sha


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=f"pg_collector v{VERSION} — PostgreSQL metadata collector for audit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "All queries are embedded in this file and read ONLY system catalogs.\n"
            "No user data is accessed or modified.\n\n"
            "Example:\n"
            "  python3 pg_collector.py --host 192.168.1.1 --dbname mydb\n"
            "  python3 pg_collector.py --host db.example.com --port 5432 --user admin --password-file /tmp/pw"
        ),
    )
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=5432)
    p.add_argument("--dbname", default="postgres")
    p.add_argument("--user", default="postgres")
    p.add_argument("--password-file", help="Read password from file (not from command line)")
    p.add_argument("--sslmode", default="prefer",
                    choices=["disable", "allow", "prefer", "require", "verify-ca", "verify-full"])
    p.add_argument("--output", default="audit_data.json")
    p.add_argument("--timeout", type=int, default=15000, help="Query timeout in ms (default: 15000)")
    p.add_argument("--long-tx-hours", type=float, default=1.0,
                    help="Threshold for long-running transactions in hours (default: 1.0)")
    p.add_argument("--idle-tx-minutes", type=float, default=10.0,
                    help="Threshold for idle-in-transaction in minutes (default: 10.0)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Generate timestamped filename
# ---------------------------------------------------------------------------
def get_timestamped_filename(base_output: str) -> str:
    """audit_data.json -> audit_data_20260710_145657.json"""
    dirname = os.path.dirname(base_output) or "."
    basename = os.path.basename(base_output)
    name, ext = os.path.splitext(basename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    new_name = f"{name}_{timestamp}{ext}"
    return os.path.join(dirname, new_name)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = parse_args()

    sections, sql_sha = parse_sql(_PROBE_SQL)

    # --- Read password ---
    password = None
    if args.password_file:
        with open(args.password_file) as f:
            password = f.read().strip()

    # --- Connect (read-only, no changes possible) ---
    try:
        conn = psycopg2.connect(
            host=args.host, port=args.port, dbname=args.dbname,
            user=args.user, password=password, sslmode=args.sslmode,
            connect_timeout=5,
        )
    except psycopg2.Error as e:
        print(f"Connection failed: {e}", file=sys.stderr)
        sys.exit(1)

    conn.set_session(readonly=True, autocommit=True)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    # Safety: restrict search path and set timeout
    cur.execute("SET search_path = pg_catalog, public;")
    cur.execute("SET statement_timeout = %s;", (args.timeout,))

    # --- PostgreSQL version ---
    cur.execute("SHOW server_version_num;")
    vnum = int(cur.fetchone()["server_version_num"])
    pg_version = f"{vnum // 10000}.{(vnum % 10000) // 100}"

    # --- Build JSON structure ---
    data: dict = {
        "session_id": str(uuid.uuid4()),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collector_version": f"pg_collector-{VERSION}",
        "database": args.dbname,
        "host": args.host,
        "pg_version": pg_version,
        "thresholds": {
            "long_running_tx_hours": args.long_tx_hours,
            "idle_in_transaction_minutes": args.idle_tx_minutes,
        },
        "collector_sha256": sql_sha,
    }

    # --- Execute each section ---
    for sec in sections:
        sql = sec["sql"].strip()
        if not sql:
            continue

        # Replace default thresholds in the activity query
        sql = sql.replace(
            "/ 3600 > 1.0",
            f"/ 3600 > {args.long_tx_hours}",
        ).replace(
            "/ 60 > 10.0",
            f"/ 60 > {args.idle_tx_minutes}",
        )

        try:
            cur.execute(sql)
            rows = [dict(r) for r in cur.fetchall()]
            rows = _norm(rows)

            if sec["merge_into"]:
                data.setdefault(sec["merge_into"], []).extend(rows)
            elif sec["single_row"]:
                data[sec["key"]] = rows[0] if rows else {}
            else:
                data[sec["key"]] = rows

        except Exception as e:
            print(f"Warning: {sec['key']}: {e}", file=sys.stderr)
            data.setdefault("errors", []).append(
                {"key": sec["key"], "error": str(e)}
            )

    # --- Write output with timestamp ---
    output_file = get_timestamped_filename(args.output)
    os.makedirs(os.path.dirname(os.path.abspath(output_file)) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

    print(f"Done: {output_file}  ({len(sections)} sections)")

    # --- Cleanup ---
    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
