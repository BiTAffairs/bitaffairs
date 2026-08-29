-- BiT Affairs — day-of run sheet
--
-- Separate concept from phases/tasks: those track planning-stage to-dos
-- ("book caterer") that get checked off over weeks or months. A run sheet
-- is the minute-by-minute timeline for the event day itself ("9:00 AM —
-- florist arrives", "6:00 PM — vendor breakdown") — different shape,
-- different audience, different lifecycle, so it gets its own table
-- rather than being bolted onto phases.
--
-- Planner-only by design (no client read policy at all, unlike vendors/
-- budget_items/client_payments) — this is internal day-of logistics, not
-- something meant for the client to see.

create table run_sheet_items (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references events(id) on delete cascade,
  time_label text,
  title text not null,
  notes text,
  position int not null default 0
);

create index idx_run_sheet_items_event on run_sheet_items(event_id);

alter table run_sheet_items enable row level security;

create policy "planners manage run sheet" on run_sheet_items for all
  using (is_org_planner(event_id)) with check (is_org_planner(event_id));
