#!/usr/bin/env python3
"""
PostgreSQL Audit Probe — Thin Wrapper
======================================
Reads pg_audit_probe.sql, executes queries against PostgreSQL,
outputs audit_data.json compatible with pg_audit_analyzer.py.

This wrapper contains NO SQL queries and NO business logic.
All queries live in pg_audit_probe.sql — open it and verify.

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
SQL_FILENAME = "pg_audit_probe.sql"


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
# SQL file parser — extracts sections by @section / @single_row / @merge_into
# ---------------------------------------------------------------------------
def parse_sql_file(path: str) -> tuple[list[dict], str]:
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()

    sha = hashlib.sha256(content.encode("utf-8")).hexdigest()

    sections: list[dict] = []
    cur: dict | None = None

    for line in content.split("\n"):
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
        description=f"pg_audit_probe v{VERSION} — thin wrapper for {SQL_FILENAME}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Queries are in {SQL_FILENAME} (same directory). Review it before running.",
    )
    p.add_argument("--host", default="localhost")
    p.add_argument("--port", type=int, default=5432)
    p.add_argument("--dbname", default="postgres")
    p.add_argument("--user", default="postgres")
    p.add_argument("--password-file", help="Read password from file")
    p.add_argument("--sslmode", default="prefer",
                    choices=["disable", "allow", "prefer", "require", "verify-ca", "verify-full"])
    p.add_argument("--output", default="audit_data.json")
    p.add_argument("--timeout", type=int, default=15000, help="Query timeout in ms")
    p.add_argument("--long-tx-hours", type=float, default=1.0,
                    help="Threshold for long-running transactions (hours)")
    p.add_argument("--idle-tx-minutes", type=float, default=10.0,
                    help="Threshold for idle-in-transaction (minutes)")
    return p.parse_args()


# ---------------------------------------------------------------------------
# Generate timestamped filename
# ---------------------------------------------------------------------------
def get_timestamped_filename(base_output: str) -> str:
    """Generate filename with timestamp: audit_data_20260710_145657.json"""
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

    # --- Locate SQL file (same directory as this script) ---
    sql_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), SQL_FILENAME)
    if not os.path.exists(sql_path):
        print(f"Error: {SQL_FILENAME} not found next to this script", file=sys.stderr)
        sys.exit(1)

    sections, sql_sha = parse_sql_file(sql_path)

    # --- Read password ---
    password = None
    if args.password_file:
        with open(args.password_file) as f:
            password = f.read().strip()

    # --- Connect ---
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

    # Session guardrails (same as pg_collector.py)
    cur.execute("SET search_path = pg_catalog, public;")
    cur.execute("SET statement_timeout = %s;", (args.timeout,))

    # --- PostgreSQL version ---
    cur.execute("SHOW server_version_num;")
    vnum = int(cur.fetchone()["server_version_num"])
    pg_version = f"{vnum // 10000}.{(vnum % 10000) // 100}"

    # --- Build JSON structure (same keys as pg_collector.py output) ---
    data: dict = {
        "session_id": str(uuid.uuid4()),
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "collector_version": f"probe-{VERSION}",
        "database": args.dbname,
        "host": args.host,
        "pg_version": pg_version,
        "thresholds": {
            "long_running_tx_hours": args.long_tx_hours,
            "idle_in_transaction_minutes": args.idle_tx_minutes,
        },
        "probe_sql_sha256": sql_sha,
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