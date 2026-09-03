-- BiT Affairs — reminders
--
-- A separate concept from tasks (planning-stage checklist, no specific
-- date) and the run sheet (day-of timeline, no specific date either —
-- implicitly "on the event day"). A reminder has a real date (and
-- optionally a time window), because it might be set days or weeks
-- ahead — "confirm final headcount with caterer on Nov 3rd, 2-3pm" —
-- rather than being tied to the event day itself.
--
-- involved_text is free text ("florist, caterer") alongside
-- reminder_assignees, which tags actual team members — the two aren't
-- mutually exclusive, a reminder can have both.
--
-- Team members can view; only admins create, edit, or delete — same
-- shape as run_sheet_items' "planner-only" pattern, one step further
-- (view open to all org planners, write admin-only) rather than fully
-- closed to non-admins.

create table reminders (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references events(id) on delete cascade,
  title text not null,
  reminder_date date not null,
  start_time time,
  end_time time,
  involved_text text,
  created_at timestamptz not null default now()
);

create index idx_reminders_event on reminders(event_id);

create table reminder_assignees (
  reminder_id uuid not null references reminders(id) on delete cascade,
  planner_id uuid not null references planners(id) on delete cascade,
  primary key (reminder_id, planner_id)
);

alter table reminders enable row level security;
alter table reminder_assignees enable row level security;

create policy "planners read reminders" on reminders for select
  using (is_org_planner(event_id));
create policy "admins insert reminders" on reminders for insert
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins update reminders" on reminders for update
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins delete reminders" on reminders for delete
  using (is_org_planner(event_id) and is_admin_planner());

-- reminder_assignees has no event_id of its own, so its policies check
-- through the parent reminder — same reasoning as vendors_for_planner
-- needing the base table's own RLS: there's no way around checking
-- org/admin membership via a join back to something that actually has
-- an event_id.
create policy "planners read reminder assignees" on reminder_assignees for select
  using (exists (select 1 from reminders r where r.id = reminder_assignees.reminder_id and is_org_planner(r.event_id)));
create policy "admins manage reminder assignees" on reminder_assignees for all
  using (exists (select 1 from reminders r where r.id = reminder_assignees.reminder_id and is_org_planner(r.event_id) and is_admin_planner()))
  with check (exists (select 1 from reminders r where r.id = reminder_assignees.reminder_id and is_org_planner(r.event_id) and is_admin_planner()));
