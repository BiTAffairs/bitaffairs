-- BiT Affairs — rate-limit access code redemption
--
-- redeem_client_code() (0008_client_code_login.sql) had no attempt
-- tracking or lockout at all. The 8-character code itself is a large
-- keyspace (~1.1 trillion combinations), so guessing one specific code
-- is impractical — but nothing stopped unlimited-speed guessing via
-- direct RPC calls, and every attempt (right or wrong) first created a
-- permanent anonymous auth.users row via signInAnonymously(), since that
-- happens client-side before the code is ever checked.
--
-- Fix has two parts:
-- 1. This table tracks failed attempts per IP so the new redeem-code
--    Edge Function (which can see the caller's IP — a plain SQL RPC
--    never can) can lock out after repeated failures.
-- 2. Revoking execute on the old RPC from anon/authenticated closes the
--    door on calling it directly and bypassing the rate limit entirely —
--    from here on, the Edge Function (using the service-role key) is the
--    only path to redemption. The function itself is left in the schema
--    rather than dropped, in case anything still references it, but it's
--    now inert for ordinary callers.
--
-- This doesn't eliminate the "one junk anonymous user per failed attempt"
-- issue (that would mean restructuring when the anonymous session gets
-- created, a bigger change) but it does cap it hard: at most a handful of
-- junk accounts per IP per lockout window, not unlimited.

create table code_redeem_attempts (
  id uuid primary key default gen_random_uuid(),
  ip_address text not null,
  attempted_at timestamptz not null default now()
);

create index idx_code_redeem_attempts_ip_time on code_redeem_attempts(ip_address, attempted_at);

-- No policies granted to anyone — this table is only ever touched by the
-- redeem-code Edge Function via the service-role key, which bypasses RLS
-- entirely. Enabling RLS with zero policies means even a stray anon/
-- authenticated request can't read or write it at all.
alter table code_redeem_attempts enable row level security;

revoke execute on function redeem_client_code(text) from anon, authenticated;
