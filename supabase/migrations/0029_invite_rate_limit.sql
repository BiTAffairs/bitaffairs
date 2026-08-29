-- BiT Affairs — rate-limit invite emails (invite-planner, invite-client)
--
-- invite-planner is admin-only; invite-client allows any planner in the
-- event's org. Either way this isn't defending against an outside
-- attacker the way 0028's code-redemption fix is — it's defending
-- against a compromised or malicious planner/admin account being used to
-- mass-spam invite emails through your Supabase project, which risks
-- your project's sending reputation, not just being annoying. Supabase's
-- own email sending has its own platform-level quota too, but hitting
-- that produces a confusing failure rather than a clear one, and doesn't
-- stop the attempt from being made in the first place.
--
-- One shared table for both functions — an admin's total invite rate is
-- what matters, not which specific invite endpoint they called.

create table invite_attempts (
  id uuid primary key default gen_random_uuid(),
  caller_id uuid not null,
  attempted_at timestamptz not null default now()
);

create index idx_invite_attempts_caller_time on invite_attempts(caller_id, attempted_at);

-- Same reasoning as code_redeem_attempts (0028) — service-role only,
-- zero policies granted to anyone else.
alter table invite_attempts enable row level security;
