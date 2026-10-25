-- Gift-address authorization rate limiting.
-- Run this once in Supabase SQL Editor. It stores only a one-way hash of a visitor IP.
create table if not exists public.gift_access_attempts (
  ip_hash text primary key,
  attempts integer not null default 0,
  window_started timestamptz not null default now(),
  blocked_until timestamptz
);
alter table public.gift_access_attempts enable row level security;
-- No public policies: only the server-side Edge Function service key can access this table.
