-- BiT Affairs — team member changes require admin approval
--
-- Covers everything a team member could edit as of this migration, other
-- than messaging (explicitly excluded) and finance (already fully
-- locked to admins as of 0031, so there's nothing left for a team member
-- to request there): run sheet items, tasks, proposal items, and
-- approvals.
--
-- One generic table rather than a shadow table per action — the
-- alternative (a separate pending-version table for run sheet items,
-- another for tasks, another for proposal items...) would mean
-- duplicating each table's shape. Storing the action name + a JSON
-- payload is less rigid at the database level, but the actual apply
-- logic lives in the frontend (reusing the exact same mutation functions
-- admins already call directly), which keeps the business logic in one
-- place rather than half in SQL and half in JS.
--
-- summary is a plain-English description generated at submission time
-- ("Add run sheet item: Florist arrives at 9:00 AM") so an admin
-- reviewing the queue doesn't have to read raw JSON to know what they're
-- approving.

create table pending_changes (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references events(id) on delete cascade,
  requested_by uuid not null references auth.users(id),
  action text not null,
  payload jsonb not null default '{}',
  summary text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected')),
  created_at timestamptz not null default now(),
  reviewed_at timestamptz,
  reviewed_by uuid references auth.users(id)
);

create index idx_pending_changes_event on pending_changes(event_id);
create index idx_pending_changes_status on pending_changes(status);

alter table pending_changes enable row level security;

-- Any org planner (team member or admin) can submit a request for an
-- event in their own org, and it's recorded under their own id — not
-- someone else's.
create policy "planners submit change requests"
  on pending_changes for insert
  with check (is_org_planner(event_id) and requested_by = auth.uid());

-- A planner can see their own submitted requests (so they can tell what's
-- still pending vs already decided), and can withdraw one of their own
-- while it's still pending — not after an admin has already acted on it.
create policy "planners read their own change requests"
  on pending_changes for select
  using (requested_by = auth.uid());

create policy "planners withdraw their own pending requests"
  on pending_changes for delete
  using (requested_by = auth.uid() and status = 'pending');

-- Admins see and decide on every request for events in their org,
-- regardless of who submitted it.
create policy "admins manage all change requests"
  on pending_changes for all
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());
