# AGENTS.md — RLScout

> Spec and working agreement for an authorized-testing tool that detects missing
> or broken Row Level Security (RLS) on Supabase / PostgREST backends.

**Status: v1.1, implemented and tested.** Python CLI managed with `uv`: the
read-only scanner, Quick Mode (point-and-shoot from a website name), and an
optional bounded-LLM layer are all built; unit tests pass and a Docker
integration test verifies behaviour against real PostgREST. Sections are marked
**[implemented]** / **[deferred]**.

---

## 0. Prime directive

**A detector, not an exploiter.** Determine *whether* an RLS hole exists and
point a human at it — never exploit, change state, or hoard data. If a feature
requires writing to, damaging, or extracting real data from a target, it does not
belong here.

Two invariants that must never break:

1. **In scope only.** Every request goes through one chokepoint
   (`http.ScopedClient` → `scope.enforce()`) that checks the host *before the
   request is built*; a non-match is a hard abort. The allowlist is built one way
   — Quick Mode (`Scope.from_target(name)`), extended at runtime only via
   `scope.allow(host)` after an explicit `[y/N]`. **[implemented]**
2. **Non-destructive only.** `ScopedClient` exposes only `GET`
   (`ALLOWED_METHODS = {"GET"}`); any other method is refused in code. Write-side
   *detection* (Phase 2) infers from metadata/errors, never by writing.
   **[implemented]**

---

## 1. What it does (and deliberately doesn't)

**Catches — [implemented]**
- RLS disabled → anon `SELECT` returns rows → flagged.
- RLS on but over-permissive policy → anon `SELECT` returns rows → flagged.
- `service_role` key exposed client-side → critical; stop and report.

**Reports as safe — [implemented]**
- RLS on, default-deny (no policy) → anon `SELECT` returns nothing → protected.
  (This default-deny-vs-leak distinction is what the integration test pins down.)

**Out of scope by design (point, don't confirm)**
- Cross-user / IDOR gaps (needs authenticated multi-user state). Not in v1.
- Write-side policy gaps. Phase 2 *detects* them non-destructively (§7b); never
  writes. **[deferred]**

A clean result means "no unauthenticated-read exposure found by an automated
pass," not a security guarantee.

---

## 2. Scope enforcement — [implemented]

```sh
rlscout app.example-ctf.com            # a bare name, or a full https:// URL
```

The website typed *is* the allowlist (`Scope.from_target(name)` →
`authorized_hosts = [host]`). `normalize_target()` prepends `https://` to a bare
host and rejects anything that isn't a real http(s) host, so a nonsense target is
never silently authorized. The scope extends at runtime via `scope.allow()`
**only after an explicit `[y/N]`** (or `--yes`):

```
[scope] (Quick Mode): app.example-ctf.com
  Also scan discovered Supabase host xyz.supabase.co? [y/N] y
[scope] (Quick Mode): app.example-ctf.com, xyz.supabase.co
```

Non-interactive runs (`stdin` not a TTY) must pass `--yes`, or an off-scope
discovered host fails closed.

**Matching rules:**
- Host matched against `authorized_hosts` before the request is built; a
  non-match is a hard abort.
- Wildcards (`*.domain.com`) match strict subdomains only, via explicit pattern
  matching — `evil-example.com` must not match `example.com`, and `*.domain.com`
  does not match the bare apex. Unit-tested against these near-misses.
- Redirects are re-checked per hop; an off-scope 30x is not followed.

---

## 3. Recon & key extraction — [implemented]

- **Where:** target page + same-origin `.js` bundles and inline config blobs.
  Every fetch is scope-gated. Crawl depth defaults to 1 (page + same-origin
  assets) — intentionally shallow.
- **Keys:** find JWTs by their `eyJ` prefix, decode the payload to read the role.
- **API base (custom domains):** resolved in confidence order — (1)
  `createClient("<url>","<key>")` pairs, (2) `*_SUPABASE_URL` assignments,
  (3) `*.supabase.*` URLs. A discovered-but-off-scope API host is named for
  approval, not silently dropped.
- **Role branch:** `anon` → test read-only; `service_role` → **STOP**, emit a
  critical finding and do not use the key (the leak is itself the vulnerability).

---

## 4. Table enumeration — [implemented]

PostgREST OpenAPI spec at `/rest/v1/` (authoritative when exposed), always merged
with a small built-in wordlist of common table names. `--wordlist <file>` extends
(never replaces) the default.

---

## 5. RLS testing (the core, read-only) — [implemented]

For each table, against the **anon** key only: one `GET /rest/v1/<table>?select=*`
with a tight row limit (§6).
- rows returned → **finding** (readable by an unauthenticated client).
- empty / default-deny / `401` / `403` → protected.

A successful read *is* the proof; nothing further is done. No write or cross-user
testing in v1.

---

## 6. Data handling — capture nothing — [implemented]

To prove "readable by anon," the tool records only: table name, the access that
succeeded, HTTP status, and a **row count** (via `Prefer: count=exact` +
`Range: 0-0`, learning "there are rows" without pulling them). **No sample rows
are ever stored** — nothing sensitive is captured, so there is nothing to redact.

---

## 7. Phase 2 — still non-destructive

### 7a. Bounded LLM layer — [implemented, opt-in `--ai`]

Two single-call, advisory capabilities in `agent.py`. The model **never gets a
network primitive**, so it can't leave scope; the deterministic core and scope
gate dispose of whatever it proposes.

- **Triage** — classifies anon-readable tables (sensitive vs. public) and drafts a
  writeup from captured *metadata* only.
- **Recon fallback** — when no key is found deterministically, the model reads the
  already-fetched in-scope bundle and *proposes* a key + API base; RLScout
  re-validates (key must decode to `anon`; URL must pass the scope gate) before use.

Recon content is untrusted (a prompt-injection surface); because the output is a
fixed schema the core validates, a hostile page can at worst propose a candidate
that fails validation. Uses the Anthropic SDK (default model `claude-opus-4-8`);
optional extra (`uv sync --extra ai`) needing `ANTHROPIC_API_KEY`. Without the
package or key, `--ai` is a no-op.

### 7b. Write-side gap detection — without writing — [deferred]

Prove anon writes *would* be allowed without sending a real row: `OPTIONS`
preflight (PostgREST advertises allowed methods), OpenAPI spec inspection, and
malformed-insert error discrimination (a `400` validation error means RLS would
have allowed the write and only the schema rejected it — nothing was written).

> Rejected, recorded so it isn't reintroduced: an **insert-then-delete loop** is a
> real write — cleanup can fail, inserts can fire triggers/webhooks/billing, and
> it's out of scope for most programs. The approaches above give the same signal
> with no state change.

### 7c. Cross-user read testing — [deferred]

If added, stays non-destructive: compares two *authorized* sessions to detect
A-reads-B leakage. Excluded from v1 by choice.

---

## 8. Operational rails — [implemented]

- **Rate limiting:** `--rate 3` req/s + `--max-requests 500` global cap, both on
  by default.
- **HTTP hygiene:** a browser-like `User-Agent` (so WAFs/CDNs don't cause false
  "protected" readings); `429` backed off (honoring `Retry-After`) and retried.
- **Logging:** request/response pairs as metadata only (method, URL, status).
- **Reports:** Markdown (submission-ready) + JSON. Each finding: table, access
  proven, the request that proved it, HTTP status, row count, severity. No
  samples; `--ai` notes appear in an advisory section.
- **Secrets:** `--ai` keys load from a gitignored `.env` (`.env.example` is the
  template); a real env var wins over `.env`.

---

## 9. Layout & flow — [implemented]

Python CLI (`httpx` + `argparse`), managed with `uv`. Console entry point: `rlscout`.

```
rlscout/
  scope.py          # build + enforce scope from the typed name (fail-closed matching)
  http.py           # ScopedClient — read-only, scope-gated, rate-limited chokepoint
  recon.py          # fetch page/JS, extract & decode JWTs, resolve API base, role-branch
  enumerate.py      # OpenAPI spec + wordlist table discovery
  rls.py            # read-only anon SELECT checks (counts only)
  agent.py          # optional bounded-LLM layer (--ai): triage + recon fallback
  report.py         # markdown + json output, no sample capture
  ratelimit.py      # throttle + global cap
  envfile.py        # minimal .env loader (ANTHROPIC_API_KEY)
  cli.py            # wiring, flags, Quick Mode bootstrap, inline scope.allow() confirm
  wordlists/default.txt
tests/              # unit tests (scope, http/redirects, rls, recon, cli, agent)
tests/integration/  # Docker: real Postgres + PostgREST + gateway, known-RLS assertions
scripts/            # check_local_supabase.py (Supabase CLI local-stack test)
supabase/           # migrations/ for the Supabase local-stack test
```

```
build scope:  Quick Mode (name → Scope.from_target)
  └▶ print active scope
       └▶ recon: fetch page + same-origin JS, extract JWT + resolve API base, decode role
            ├─ service_role found ──▶ CRITICAL finding, STOP
            ├─ Supabase API host off-scope ──▶ inline [y/N] →
            │                                    scope.allow(host) → re-resolve
            ├─ no anon key & --ai           ──▶ bounded LLM recon fallback (re-validated)
            └─ anon ──▶ enumerate tables (OpenAPI ∪ wordlist)
                         └▶ read-only anon SELECT per table  (rate-limited throughout)
                              └▶ [--ai] advisory triage of findings (metadata only)
                                   └▶ report (md + json), counts only, no samples
```

Exit codes: `0` clean · `1` findings · `2` scope/usage error · `10` critical.

---

## 10. Testing

- **Unit** (`uv run pytest`): scope near-misses, redirect re-checking, GET-only
  enforcement, rate cap, JWT/role decode, count parsing, RLS classification, recon
  extraction/API-base decision, LLM-proposal re-validation (service_role and
  off-scope refused), Quick Mode (`normalize_target`/`from_target`/`allow`), and
  the `[y/N]` prompt (`--yes` auto-accepts; non-TTY without it refuses).
- **Integration — Docker** (`tests/integration/run_integration.py`): real Postgres
  + PostgREST behind a Supabase-style gateway, asserting verdicts on known-RLS
  tables. Needs Docker.
- **Integration — Supabase CLI** (`scripts/check_local_supabase.py` +
  `supabase/migrations/`): same ground truth against the real Supabase local stack.
