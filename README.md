# RLScout

A **read-only, in-scope detector** for missing or broken Row Level Security (RLS)
on Supabase / PostgREST backends.

```sh
uv run rlscout app.example.com
```

That's it. Just type the name of the website — a bare host or a full
`https://...` URL both work. No `scope.yaml`, no config file, no "type I AM
AUTHORIZED" wall. The host you typed is the implicit allowlist; if recon
discovers a different Supabase API host in the bundle (it usually does), the
tool pauses once with `Also scan api-xyz.supabase.co? [y/N]` — `--yes`
auto-accepts.

> **This is a detector, not an exploiter.** Its job is to determine *whether* an
> RLS vulnerability exists and point a human at it — never to exploit it, never to
> change state, never to hoard data. See [AGENTS.md](AGENTS.md) for the full spec
> and working agreement.

## Two hard invariants

1. **In scope only.** Every outbound request's host is matched against the
   active scope *in code, before the request is built*. A non-match is a hard
   abort — fail closed, loudly. Redirects are re-checked per hop. The scope is
   built from the website name you typed; nothing else is contacted until you
   approve it at the inline prompt.
2. **Non-destructive only.** The tool issues only read-only `GET`
   (`ALLOWED_METHODS = {"GET"}`). There is no code path that sends `HEAD` /
   `POST` / `PATCH` / `PUT` / `DELETE` against a target.

## What it catches (v1)

- **RLS disabled / over-permissive** → anon `SELECT` returns rows it shouldn't → flagged.
- **`service_role` key exposed client-side** → **critical**; the tool stops and
  reports the leak *without using the key*.
- **RLS enabled, default-deny** → anon read returns nothing → reported as protected.

Out of scope **by design** (the report points, a human confirms): cross-user/IDOR
RLS gaps and write-side policy gaps. v1 is a high-confidence detector for the most
common, most automatable failure — unauthenticated read exposure.

## Data handling

The tool records **counts and metadata only** — table name, the access that
succeeded, HTTP status, row count. It **never stores sample rows**. Nothing
sensitive is captured, so there is nothing to redact.

## Install

With [uv](https://docs.astral.sh/uv/) (recommended — creates a `.venv` and pins a
lockfile):

```sh
uv sync                 # runtime deps only
uv sync --extra dev     # + pytest, for running the test suite
```

Or with pip:

```sh
pip install -e .
```

## Usage

### Point and shoot

```sh
uv run rlscout app.example-ctf.com
# (or just `rlscout ...` if installed with pip / inside an activated venv)
```

That's the whole flow. The scope is built from the name you typed: only
`app.example-ctf.com` is authorized. The tool then:

1. Fetches the page + same-origin JS, extracts the Supabase anon JWT.
2. If it finds a different Supabase API host (e.g. `xyz.supabase.co`), prompts
   `Also scan xyz.supabase.co? [y/N]`. `--yes` (or `-y`) auto-accepts.
3. Enumerates tables, runs one read-only `GET /rest/v1/<table>` per table.
4. Prints a Markdown report. Pass `-o report` to also write `report.md` and
   `report.json`.

```sh
# a full URL works too:
uv run rlscout https://app.example-ctf.com

# write reports to disk:
uv run rlscout app.example-ctf.com -o report

# fully non-interactive (CI, piped, demos):
uv run rlscout app.example-ctf.com --yes -o report
```

### Flags

| Flag | Default | Meaning |
|---|---|---|
| `--wordlist FILE` | — | extra table names (extends the built-in default) |
| `--crawl-depth N` | `1` | recon depth (target page + same-origin assets) |
| `--rate N` | `3` | max requests/second (`<=0` disables throttle) |
| `--max-requests N` | `500` | global per-run request cap (`<=0` disables) |
| `--api-base URL` | auto | override the PostgREST base (still scope-checked) |
| `--user-agent UA` | browser-like | override the HTTP User-Agent |
| `--ai` | off | enable the bounded LLM layer (needs the `ai` extra + `ANTHROPIC_API_KEY`) |
| `--ai-model ID` | `claude-opus-4-8` | model for `--ai` |
| `-y`, `--yes` | off | auto-accept any inline "also scan host X?" prompt (required for piped/CI use) |
| `-v` | off | verbose progress |
| `-o, --out PFX` | — | write `<PFX>.md` and `<PFX>.json` (otherwise the Markdown report prints to stdout) |

### Real-world recon

Recon extracts the anon key (a JWT) and the API base from the target page and
its same-origin JS. It handles `createClient(url, key)`, `*_SUPABASE_URL`
env-var assignments, and `*.supabase.*` URLs — including **custom API
domains**. The app and the API are usually different hosts: an app at
`app.example.com` talks to `https://<ref>.supabase.co/rest/v1/`.

When the API host is a different host than the app, it pops up as
`Also scan xyz.supabase.co? [y/N]` — one keystroke and the scope extends to
cover it (`--yes` auto-accepts for non-interactive runs).

Requests use a browser-like User-Agent (overridable with `--user-agent`) and
back off on `429`.

### Bounded LLM layer (`--ai`, optional)

Opt-in, advisory, and strictly constrained — the model never gets a network
primitive, so it cannot leave scope (enforcement stays at the request chokepoint):

- **Triage** — classifies each anon-readable table as likely-sensitive vs.
  likely-public and drafts a writeup, working only on captured *metadata* (table
  names + counts). No network calls, no record contents.
- **Recon fallback** — when deterministic extraction finds no key, the model reads
  the *already-fetched, in-scope* bundle and *proposes* an anon key + API base.
  RLScout re-validates the proposal (the key must decode to an anon JWT — a
  `service_role` key is refused; the URL must pass the scope gate) before any use.

```sh
uv sync --extra ai
# put your key in .env (gitignored):  ANTHROPIC_API_KEY=sk-ant-...
uv run rlscout https://app.example-ctf.com --ai --out report
```

The key is read from a `.env` file in the project root (see `.env.example`), or
from the `ANTHROPIC_API_KEY` environment variable if already set (the shell wins
over `.env`). Without the extra or the key, `--ai` is a no-op that records a note
and the deterministic scan proceeds normally.

On startup the tool prints the active scope and starts scanning immediately —
typing the website name is itself the affirmation. The only inline prompt is
the `[y/N]` for a newly-discovered Supabase API host; `--yes` skips it.

Exit codes: `0` clean, `1` findings present, `2` scope error / usage error,
`10` critical (service_role key exposed client-side).

## Tests

```sh
uv run pytest               # with uv
# or, with pip:  pip install -e ".[dev]" && pytest
```

**Integration tests** run RLScout against *real* PostgREST / Supabase on
localhost, asserting verdicts on tables with known RLS states — see
[tests/integration/README.md](tests/integration/README.md):

```sh
uv run python tests/integration/run_integration.py   # Docker: real PostgREST
uv run python scripts/check_local_supabase.py        # Supabase CLI local stack
```

The scope matcher is unit-tested against tricky near-matches (`evil-example.com`,
`example.com.evil`, wildcard apex, sibling-suffix) to guarantee it fails closed.

## Layout

```
rlscout/
  scope.py       # build + enforce scope from the typed name (fail-closed matching)
  http.py        # ScopedClient: the read-only, scope-gated network chokepoint
  recon.py       # fetch page/JS, extract & decode JWTs, role-branch
  enumerate.py   # OpenAPI spec + wordlist table discovery
  rls.py         # read-only anon SELECT checks (counts only)
  agent.py       # optional bounded-LLM layer (--ai): triage + recon fallback
  report.py      # markdown + json output, no sample capture
  ratelimit.py   # throttle + global cap
  envfile.py     # minimal .env loader (ANTHROPIC_API_KEY)
  cli.py         # wiring, flags, authorization gate
  wordlists/default.txt
.env / .env.example   # API keys for --ai (real .env is gitignored)
tests/                # unit tests
tests/integration/    # Docker: real Postgres + PostgREST + nginx gateway
scripts/              # check_local_supabase.py (Supabase CLI local stack)
supabase/migrations/  # ground-truth RLS states for the Supabase test
```

## Authorization

Only run RLScout against systems you are **explicitly authorized** to test (your
own, a CTF, or a bug-bounty target whose scope you have confirmed). The scope gate
and authorization prompt exist to make unauthorized use take deliberate effort —
they are not a substitute for having permission.
