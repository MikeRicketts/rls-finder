-- RLScout ground truth for a local Supabase stack (`supabase start`).
-- Same four known RLS states as tests/integration/seed.sql, expressed against
-- Supabase's pre-existing `anon` role and `auth.uid()` helper.
--
-- Apply with:  supabase db reset   (or it runs automatically on `supabase start`)

-- === 1. RLS DISABLED -> anon reads everything -> EXPECTED: vulnerable ========
create table public.public_notes (id serial primary key, body text);
insert into public.public_notes (body) values ('note-1'), ('note-2'), ('note-3');
grant select on public.public_notes to anon;
-- (row level security intentionally NOT enabled — Supabase will warn; that's the point)

-- === 2. RLS ON, permissive USING(true) -> anon reads -> EXPECTED: vulnerable =
create table public.leaky_profiles (id serial primary key, email text);
insert into public.leaky_profiles (email) values ('a@example.com'), ('b@example.com');
alter table public.leaky_profiles enable row level security;
create policy leaky_select_all on public.leaky_profiles for select to anon using (true);
grant select on public.leaky_profiles to anon;

-- === 3. RLS ON, NO policy (default-deny) -> 0 rows -> EXPECTED: protected =====
create table public.private_secrets (id serial primary key, secret text);
insert into public.private_secrets (secret) values ('s-1'), ('s-2');
alter table public.private_secrets enable row level security;
grant select on public.private_secrets to anon;  -- granted, but RLS denies rows

-- === 4. RLS ON, owner-only policy -> anon sees 0 rows -> EXPECTED: protected ==
create table public.owner_only (id serial primary key, owner uuid, data text);
insert into public.owner_only (owner, data)
  values (gen_random_uuid(), 'd-1'), (gen_random_uuid(), 'd-2');
alter table public.owner_only enable row level security;
create policy owner_select on public.owner_only for select to anon
  using (owner = auth.uid());
grant select on public.owner_only to anon;
