# pg-audit-collector

**Single-file PostgreSQL metadata collector for security and performance audit.**

Reads system catalogs only. No user data. No modifications. Outputs a JSON file ready for analysis.

**Get a free assessment:** [pg-audit.github.io](https://pg-audit.github.io) — upload the JSON, receive the 3 most critical problems within 24 hours.

Full report with ready-to-execute SQL fixes and priority plan: **30,000 ₽**.

## Why?

Before tuning or auditing a PostgreSQL database, you need diagnostic data. This script collects it safely and quickly:

- **17 query groups** covering indexes, performance, bloat, transactions, configuration, and risks
- **Read-only connection** — `readonly=True` enforced at the driver level
- **Statement timeout** — no long-running queries
- **Single file** — no dependencies beyond `psycopg2`, no external SQL files

## Security

This is the first question any DBA or security team will ask. Here's the short answer:

| Concern | Answer |
|---------|--------|
| Does it read user data? | **No.** Only system catalogs (`pg_stat_*`, `pg_class`, `pg_index`, `pg_settings`, etc.) |
| Does it modify anything? | **No.** Connection is opened with `readonly=True, autocommit=True` |
| Does it send data anywhere? | **No.** No network calls. Output is a local JSON file |
| Can I verify? | **Yes.** Every SQL query is in this single file. Search path is locked to `pg_catalog, public` |

Run it, open the JSON, and see for yourself — there is zero user data in the output.

## Quick Start

**1. Install dependency:**

```bash
pip install psycopg2-binary
```

**2. Run:**

```bash
python3 pg_collector.py --host YOUR_DB_HOST --dbname YOUR_DB_NAME --user YOUR_DB_USER
```

If your database requires a password, use `--password-file` (avoids exposing the password in process listings):

```bash
echo "your_password" > /tmp/pgpw
python3 pg_collector.py --host your-db-host --dbname production --user dba --password-file /tmp/pgpw
rm /tmp/pgpw
```

**3. Get the result:**

A file like `audit_data_20260712_153000.json` appears in the current directory. 

**4. Get your report:**

Upload the JSON file at [pg-audit.github.io](https://pg-audit.github.io) — you'll receive the 3 most critical problems for free.

## All Options

```
--host              Database host          (default: localhost)
--port              Database port          (default: 5432)
--dbname            Database name          (default: postgres)
--user              Database user          (default: postgres)
--password-file     Read password from file
--sslmode           SSL mode               (default: prefer)
--output            Output filename base   (default: audit_data.json)
--timeout           Query timeout in ms    (default: 15000)
--long-tx-hours     Long transaction threshold in hours   (default: 1.0)
--idle-tx-minutes   Idle-in-transaction threshold in minutes (default: 10.0)
```

## What Gets Collected

| # | Section | What it measures |
|---|---------|-----------------|
| 01 | Global context | Uptime, statistics reset time |
| 02 | Database stats | Cache hit ratio, deadlocks, temp files |
| 03 | Database size | Total database size in bytes |
| 04 | Table stats | Scans, tuples, sizes, last vacuum/analyze |
| 05 | Index stats | Usage count, size, index definition |
| 06–08 | Constraints | Primary keys, foreign keys, unique constraints |
| 09 | Activity | Long-running and idle-in-transaction queries |
| 10 | Dead tuple ratio | Tables with highest dead tuple percentage |
| 11 | Bloat check | Tables with >10% bloat and estimated wasted MB |
| 12 | Table columns | Column types and structure (for index analysis) |
| 13 | Autovacuum | Per-table autovacuum configuration |
| 14 | Server settings | Key configuration parameters |
| 15 | Idle connections | Count and max idle time of idle connections |
| 16 | Sequences | Sequence exhaustion risk |
| 17 | Shared libraries | Loaded shared_preload_libraries |

## Output Format

The script produces a timestamped JSON file:

```json
{
  "session_id": "a1b2c3d4-...",
  "collected_at": "2026-07-12T15:30:00+00:00",
  "collector_version": "pg_collector-1.0.0",
  "database": "production",
  "host": "192.168.1.1",
  "pg_version": "16",
  "collector_sha256": "abc123...",
  "database_stats": { ... },
  "table_stats": [ ... ],
  "index_stats": [ ... ],
  ...
}
```

> Example output with synthetic values. The collector captures database metadata only — no user data, no query contents, no table rows.

## Requirements

- Python 3.10+
- `psycopg2-binary` (or `psycopg2`)
- Network access to a PostgreSQL server (version 10+)
- A database user with permission to read `pg_stat_*` views (any non-superuser can usually do this; `pg_read_all_stats` role grants it explicitly)

## License

MIT

---

**PG Audit Service** — [pg-audit.github.io](https://pg-audit.github.io) · [pg.audit.service@proton.me](mailto:pg.audit.service@proton.me)
