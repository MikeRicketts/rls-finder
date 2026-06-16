# CLAUDE.md — RLScout

> Project spec and working agreement for an authorized-testing tool that detects
> missing or broken Row Level Security (RLS) on Supabase / PostgREST backends.

*("RLScout" is a working title — rename freely.)*

**Status: v1.1 is implemented and tested.** Python CLI, managed with `uv`. The
core read-only scanner, Quick Mode (point-and-shoot from a website name), and an
optional bounded-LLM layer are all built. Unit tests pass and a Docker-based
integration test verifies behaviour against real PostgREST. Section markers
below note what is **[implemented]** vs **[deferred]**.

---

## 0. Prime directive

**This is a detector, not an exploiter.** Its job is to determine *whether* an RLS
vulnerability exists and point a human at it — never to exploit it, never to change
state, never to hoard data. Every design decision below flows from that. If a feature
would require writing to, damaging, or extracting real data from a target, it does not
belong in this tool.

Two hard invariants that must never be violated:

1. **In scope only.** The tool refuses to send a single request to any host not
 in its in-memory allowlist. Scope is enforced in code, before any network call,
 not left to the operator's memory. **[implemented]** — every request goes
 through one chokepoint (`http.ScopedClient`) that calls `scope.enforce()`
 before the request is built. The allowlist is built one way: **Quick Mode**
 (`Scope.from_target(name)` — the website name the operator typed is the only
 authorized host; the CLI may extend it at runtime via `scope.allow(host)`
 after an explicit inline `[y/N]`).
2. **Non-destructive only.** The tool performs read-only checks. It never issues a
 state-changing request (`POST`/`PATCH`/`PUT`/`DELETE`) against a target. Write-side
 *detection* is done through metadata and error-signal inference (see Phase 2), never
 by actually writing. **[implemented]** — `ScopedClient` exposes only `GET`
 (`ALLOWED_METHODS = {"GET"}`), and any other method is refused in code. Phase 2's
 `OPTIONS`-style detection will widen this set deliberately when it lands.

---

## 1. What it does (and what it deliberately doesn't)

### Catches (high confidence, fully automatable) — [implemented]
- **RLS disabled** on a table → anon `SELECT` returns rows → flagged.
- **RLS enabled but a policy is too permissive** → anon `SELECT` returns rows it
  shouldn't → flagged.
- **Exposed `service_role` key** client-side → critical finding; tool stops and reports.

### Correctly reports as safe — [implemented]
- **RLS enabled, default-deny (no policy)** → anon `SELECT` returns nothing → reported
  as protected. (This default-deny-vs-leak distinction is the subtle case the
  integration test specifically verifies.)

### Out of scope by design (flag/point, don't confirm)
- **Cross-user / IDOR-style broken RLS** (user A reads user B's rows). Requires
  authenticated multi-user state; deliberately excluded from v1. Not implemented.
- **Write-side policy gaps** (`INSERT`/`UPDATE`/`DELETE` allowed where they shouldn't
  be). v1 does not test these. Phase 2 *detects* them non-destructively (see §7); it
  never performs the write. **[deferred]**

The honest framing baked into the reports: **v1 is a high-confidence detector for the
most common, most automatable RLS failure (unauthenticated read exposure), and a
pointer for the deeper classes that need a human.** It narrows the surface; it is not
the whole assessment. A clean result means "no unauthenticated-read exposure found by
an automated pass," not a security guarantee.

---

## 2. Scope enforcement — [implemented]

Scope is built before any network call and enforced at the request chokepoint
(`http.ScopedClient` → `scope.enforce()`). Two construction paths, one
enforcement object.

### 2a. Quick Mode (the only mode)

```sh
rlscout app.example-ctf.com            # a bare name, or a full https:// URL
```

The website the operator typed *is* the implicit allowlist
(`Scope.from_target(name)` → `authorized_hosts = [host]`). A bare host is
normalized to `https://` by `normalize_target()`; anything that doesn't parse
to a real host (or carries a non-web scheme) is rejected, so we never silently
authorize a nonsense host. The CLI may extend the scope at runtime via
`scope.allow(host)` **only after an explicit operator `[y/N]` confirmation**
(or `--yes` to auto-accept):

```
[scope] (Quick Mode): app.example-ctf.com
  Also scan discovered Supabase host xyz.supabase.co? [y/N] y
[scope] (Quick Mode): app.example-ctf.com, xyz.supabase.co
```

Non-interactive sessions (`stdin` is not a TTY) **must** pass `--yes` to
extend scope at runtime; without it, an off-scope discovered API host fails
closed and the run is halted. `ScopedClient` always calls `scope.enforce()`
before every request — Quick Mode just *builds* the allowlist from
operator-affirmed inputs (the name on the command line, plus zero-or-more
inline `[y/N]`s).

### Rules

- Every outbound request's target host is matched against `authorized_hosts` **before
  the request is built**. A non-match is a **hard abort** (not
  logged-and-skipped) — fail closed, loudly.
- Wildcards (`*.domain`) are supported via explicit pattern matching, not loose
  substring checks (`evil-example.com` must not match `example.com`; `*.domain.com`
  matches strict subdomains, not the bare apex). Unit-tested against these near-misses.
- Redirects are re-checked against scope per hop. A 30x that points off-scope is not
  followed.

---

## 3. Recon & key extraction — [implemented]

- **Where to look:** the target page plus its same-origin linked `.js` bundles and
  inline config blobs (`window.__ENV`, `import.meta.env`, JSON in `<script>`). Look
  wherever a client-shipped key would plausibly live — every fetch is still scope-gated.
- **Crawl depth:** default `crawl_depth: 1` (target page + its same-origin assets).
  Configurable, but the default is intentionally shallow — a deep crawler is harder to
  keep inside scope, and depth 1 already catches essentially all client-shipped keys.
- **Key extraction:** find JWTs by their `eyJ` prefix across fetched HTML/JS; decode the
  payload to read the role.
- **API-base extraction (handles custom domains):** the API host is usually a
  *different* host from the app. RLScout resolves it from, in order of confidence:
  (1) `createClient("<url>", "<key>")` pairs (works for custom domains, not just
  `*.supabase.co`), (2) `*_SUPABASE_URL` env-var assignments, (3) `*.supabase.*` URLs.
  If a Supabase API host is discovered but **not** in `authorized_hosts`, the tool says
  exactly which host to add rather than silently falling back and 404ing.
- **Role branching:**
  - `role: anon` → proceed with read-only testing.
  - `role: service_role` → **STOP.** Do not use the key. Emit a **critical** finding
    ("service_role key exposed client-side — full RLS bypass") and halt that target.
    A leaked service_role key is itself the headline vulnerability; using it would be
    exploitation, which this tool does not do.

---

## 4. Table enumeration — [implemented]

- **Primary source:** the PostgREST OpenAPI spec at `/rest/v1/` when exposed — it's the
  authoritative list of tables and the operations each exposes.
- **Fallback / supplement:** a small built-in wordlist of common Supabase table names
  (`users`, `profiles`, `accounts`, `orders`, `messages`, etc.), always merged with the
  spec results.
- **Extendable:** `--wordlist <file>` adds user-supplied names (extends, does not
  replace the default) so the operator can tailor it to the target.

---

## 5. RLS testing (the core, read-only) — [implemented]

For each discovered table, against the **anon** key only:

- Issue a read-only `GET /rest/v1/<table>?select=*` (with a tight row limit — see §6).
- Interpret:
  - rows returned → **finding**: table readable by an unauthenticated client.
  - empty / default-deny → reported as protected.
  - `401`/`403` → protected (RLS blocked the read).
- A successful read **is** the proof. No further action is taken on a vulnerable table.

No write testing in v1. No cross-user testing in v1.

---

## 6. Data handling — capture nothing — [implemented]

This is a determination tool, not an extraction tool. To prove "this table is readable
by an unauthenticated client," the tool records only:

- table name
- the access that succeeded (e.g. `anon SELECT returned rows`)
- HTTP status
- a **row count** (via PostgREST's `Prefer: count=exact` + `Range: 0-0` headers, to
  learn "there are rows" without pulling them)

**The tool does not store sample rows.** No record contents are written to disk or to
the report. Because nothing sensitive is captured, there's nothing to redact — which is
the cleanest possible answer for bounty hygiene and avoids holding data you have no
business holding. (PII-redaction logic is therefore unnecessary; it's listed here only
to record *why* it's absent.)

---

## 7. Phase 2 — partly implemented, still non-destructive

Everything here preserves the two invariants (in-scope, non-destructive). None of it
performs a write.

### 7a. Agentic / LLM layer — **bounded autonomy** — [implemented, opt-in `--ai`]
Implemented as two strictly-constrained, single-call capabilities in `agent.py`. The
model **never gets a network primitive**, so it cannot leave scope regardless of what
page content says — enforcement stays structural at `ScopedClient`. Both are advisory:
the deterministic core and the scope gate dispose of whatever the model proposes.

- **Triage** — classifies each anon-readable table as likely-sensitive vs.
  likely-public and drafts a submission-ready writeup, working only on already-captured
  *metadata* (table names + counts). No network, no record contents.
- **Recon fallback** — when deterministic extraction finds no key, the model reads the
  *already-fetched, in-scope* bundle text and *proposes* an anon key + API base.
  RLScout **re-validates** the proposal before any use: the key must decode to an
  `anon` JWT (a `service_role` proposal is refused), and the URL must pass the scope
  gate. The fetch stays deterministic and scope-gated.

Recon content is untrusted (a prompt-injection surface); because the model's output is
a fixed schema the core validates, the worst a hostile page can do is propose a
candidate that then fails validation. Uses the Anthropic SDK (`messages.parse`,
structured outputs, default model `claude-opus-4-8`). It is an **optional extra**
(`uv sync --extra ai`) needing `ANTHROPIC_API_KEY`; without the package or key, `--ai`
is a no-op that records a note and the deterministic scan proceeds normally.

### 7b. Write-side RLS gap detection — **without writing** — [deferred]
Prove that anon writes *would* be permitted, without ever sending a real row:

- **`OPTIONS` pre-flight** on a table endpoint: PostgREST advertises allowed methods in
  the response. `POST`/`PATCH`/`DELETE` offered to the anon role is a strong signal of
  permissive policy. Pure metadata, no state change.
- **OpenAPI spec inspection:** the `/rest/v1/` spec describes which operations each
  table exposes per role.
- **Malformed-insert error discrimination:** send a deliberately *invalid* insert
  (missing required fields / wrong types) and read the **error code**, not the result.
  A `401`/`403` means RLS blocked the write before validation (protected). A `400`
  validation error means RLS *would have let the write through* and only the schema
  rejected it (policy gap) — and **nothing was written, because the row never
  validated.** Same diagnostic signal as an insert/delete loop, zero state change.

Output for these: `"table X appears to permit anon writes — manually verify within
scope"`, with the supporting evidence (the `OPTIONS`/error signal). The tool detects and
points; a human confirms.

> Rejected approach, recorded so it doesn't get reintroduced: an **insert-then-delete
> loop**. Even with immediate cleanup it is a real write — cleanup can fail (leaving
> data behind), inserts can fire triggers/webhooks/emails/billing that a later delete
> can't undo, and it's out of scope for nearly every bounty program. The `OPTIONS` +
> malformed-insert approach above gives the same signal with none of the risk.

### 7c. Cross-user read testing (optional, later) — [deferred]
If ever added, stays non-destructive — compares two *authorized* read sessions to detect
A-reads-B leakage. Adds token lifecycle complexity; only worth it if the need is real.
Excluded from v1 by deliberate choice.

---

## 8. Operational rails — [implemented]

- **Rate limiting:** a sensible default (`--rate 3` req/s) with a global per-run request
  cap (`--max-requests 500`), both on by default and adjustable via flags. Don't hammer
  a live database.
- **HTTP hygiene:** a browser-like `User-Agent` by default (overridable with
  `--user-agent`) so WAFs/CDNs don't produce false "protected" readings; `429` responses
  are backed off (honoring `Retry-After`) and retried rather than misread.
- **Logging:** every request/response pair is recorded as metadata only (method, URL,
  status) for clean evidence — never captured record contents (§6).
- **Reports:** emit both **Markdown** (human/submission-ready) and **JSON**
  (machine-readable). Each finding: table, access proven, request that proved it, HTTP
  status, row count, severity. No record samples. Optional AI triage/notes appear in an
  advisory section.
- **Secrets:** API keys (for `--ai`) load from a gitignored `.env` in the project root
  (`.env.example` is the tracked template); a real environment variable wins over `.env`.

---

## 9. Layout & stack — [implemented]

- **Language:** Python CLI (`httpx` + `argparse`), managed with **`uv`**
  (`uv sync`, `uv run rlscout ...`, `uv run pytest`). Console entry point: `rlscout`.

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
  wordlists/
    default.txt
.env / .env.example # API keys for --ai (real .env is gitignored)
tests/              # unit tests (scope, http/redirects, rls, recon, cli, agent)
tests/integration/  # Docker: real Postgres + PostgREST + gateway, known-RLS assertions
scripts/            # check_local_supabase.py (Supabase CLI local-stack test)
supabase/           # migrations/ for the Supabase local-stack test
```

High-level flow:

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

Exit codes: `0` clean · `1` findings present · `2` scope error / usage error ·
`10` critical (service_role exposed).

---

## 10. Testing

- **Unit tests** (`uv run pytest`) — scope matcher near-misses, redirect re-checking,
  read-only-method enforcement, rate cap, JWT/role decode, count parsing, RLS
  classification, recon extraction/API-base decision, the bounded-LLM proposal
  re-validation (service_role refused, off-scope base refused), Quick Mode
  (`normalize_target`, `Scope.from_target`, `scope.allow`), and the inline
  `[y/N]` scope-extension prompt (`--yes` auto-accepts; non-TTY without `--yes`
  refuses).
- **Integration — Dockerized PostgREST** (`tests/integration/run_integration.py`):
  real Postgres + PostgREST behind a Supabase-style gateway, seeded with tables in
  known RLS states; asserts the verdict for each matches ground truth. Needs Docker.
- **Integration — Supabase CLI local stack** (`scripts/check_local_supabase.py` +
  `supabase/migrations/`): same ground truth against the real Supabase local stack.
  Needs the Supabase CLI. (Built; run when the CLI is available.)

---

## 11. Checklist before publish

- [x] Scope matcher fails closed and is unit-tested against tricky near-matches.
- [x] Redirects re-checked against scope.
- [x] service_role branch halts and does not use the key.
- [x] No code path issues a write request anywhere in v1 (`ALLOWED_METHODS` = GET).
- [x] Reports contain counts/metadata only — no record contents.
- [x] Rate limit + global cap on by default.
- [x] Quick Mode: `normalize_target` accepts a bare name or http(s):// URL and
      rejects nonsense/non-web schemes; `scope.allow(host)` only fires after an
      explicit operator `[y/N]` or `--yes`; non-TTY without `--yes` refuses to
      extend scope silently.
- [x] `--ai` is opt-in, advisory, and re-validates every LLM proposal; refuses
      service_role and off-scope proposals; degrades gracefully without the key/package.
- [x] Verified end-to-end against real PostgREST (Docker integration test passes).
- [ ] (Optional, later) Phase 2 write-side detection (§7b).
