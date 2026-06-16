# RLScout

A **read-only, in-scope detector** for missing or broken Row Level Security (RLS)
on Supabase / PostgREST backends.

```sh
uv run rlscout app.example.com
```

Type the website name (bare host or full URL). The host you type is the
allowlist; if recon finds a different Supabase API host, the tool asks once
(`Also scan xyz.supabase.co? [y/N]`, `--yes` auto-accepts), then enumerates
tables and runs one read-only `GET` per table.

> **A detector, not an exploiter.** It determines *whether* an RLS hole exists
> and points a human at it — it never exploits, writes, or stores row data. Full
> spec: [AGENTS.md](AGENTS.md).

## Guarantees

- **In scope only** — every request's host is checked in code before it's sent;
  off-scope (including redirects) is a hard abort.
- **Read-only** — `GET` is the only method; no `POST`/`PATCH`/`PUT`/`DELETE`.
- **No data hoarding** — reports record counts and metadata only, never rows.

## What it catches

| Result | Meaning |
|---|---|
| 🚩 vulnerable | anon `SELECT` returns rows (RLS off or over-permissive) |
| 🔴 critical | `service_role` key exposed client-side — halts without using it |
| ✅ protected | anon read blocked or empty (default-deny) |

Cross-user/IDOR and write-side gaps are out of scope by design (the report
points; a human confirms).

## Install

```sh
uv sync                 # runtime
uv sync --extra dev     # + pytest
# or: pip install -e .
```

## Usage

```sh
uv run rlscout app.example.com              # scan, print Markdown report
uv run rlscout app.example.com -o report    # also write report.md / report.json
uv run rlscout app.example.com --yes        # non-interactive (CI/piped)
```

Common flags: `--rate` (req/s, default 3), `--max-requests` (cap, default 500),
`--api-base` (override PostgREST base), `--wordlist`, `-v`. `--ai` enables an
optional, advisory LLM triage layer (needs the `ai` extra + `ANTHROPIC_API_KEY`);
run `rlscout -h` for the full list.

Exit codes: `0` clean · `1` findings · `2` scope/usage error · `10` critical.

## Tests

```sh
uv run pytest                                        # unit suite
uv run python tests/integration/run_integration.py   # Docker: real PostgREST
uv run python scripts/check_local_supabase.py        # Supabase CLI local stack
```

## Authorization

Only run RLScout against systems you are **explicitly authorized** to test (your
own, a CTF, or a confirmed bug-bounty scope). The scope gate raises the bar for
misuse — it is not a substitute for permission.
