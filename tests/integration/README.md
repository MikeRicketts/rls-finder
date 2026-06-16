# RLScout integration tests (real backends)

The unit suite (`uv run pytest`) proves the decision logic against a mock. These
integration tests prove RLScout works against the **real** software it targets,
on tables whose RLS state is known in advance, so a pass is genuine confidence and
a mismatch is a real bug. Everything runs on `localhost` — fully in scope.

Both tests assert the same ground truth:

| Table | RLS state | Expected verdict |
|---|---|---|
| `public_notes` | RLS **disabled** | 🚩 vulnerable |
| `leaky_profiles` | RLS on, `USING (true)` | 🚩 vulnerable |
| `private_secrets` | RLS on, **no policy** (default-deny) | ✅ protected |
| `owner_only` | RLS on, owner-only policy | ✅ protected (anon) |

These are **not** run by `pytest` (they need Docker and are slow); run them by hand.

---

## 1. Dockerized PostgREST  (`run_integration.py`)

Real Postgres + PostgREST behind an nginx gateway that mirrors Supabase's
`/rest/v1/` layout, so the full `rlscout` CLI runs unmodified (recon finds the
key on the served page, then enumerates + checks against real PostgREST).

**Prereq:** Docker Desktop running.

```sh
uv run python tests/integration/run_integration.py
```

It brings the stack up, mints an anon JWT signed with the compose file's
`PGRST_JWT_SECRET`, runs the scan, prints a PASS/FAIL table per target table, then
tears the stack down. Exit `0` = all verdicts matched.

Files: `docker-compose.yml`, `seed.sql` (ground truth), `nginx.conf`, `www/`
(generated landing page), `run_integration.py` (runner + assertions).

**Image pins are intentional.** The compose file pins `postgrest/postgrest:v12.2.3`
and `postgres:15-alpine`. Both are "known good" for `seed.sql` — newer versions
may tighten PostgREST's `OPTIONS` advertising or change how `Content-Range`
behaves with `count=exact`, either of which silently invalidates the
ground-truth contract. Bump them deliberately, and only after re-running this
test on the same `seed.sql` to confirm the same four verdicts.

---

## 2. Supabase CLI local stack  (`../../scripts/check_local_supabase.py`)

Closest to real Supabase — the actual Supabase local stack (GoTrue, Kong, the
real anon key).

**Prereq:** Docker + the [Supabase CLI](https://supabase.com/docs/guides/cli).

```sh
supabase init      # from repo root; keeps the existing migration
supabase start     # boots the stack, applies supabase/migrations/0001_rls_states.sql

uv run python scripts/check_local_supabase.py
supabase stop      # when done
```

The script auto-discovers the local API URL + anon key via `supabase status`
(or `RLSCOUT_TEST_URL` / `RLSCOUT_TEST_ANON_KEY`), drives RLScout's real
enumeration + read-only checks, and asserts the verdicts. Exit `0` = all matched.

Ground truth: `supabase/migrations/0001_rls_states.sql`.
