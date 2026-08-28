-- BiT Affairs — track money sent by the client
--
-- Separate from vendors.deposit (0024_vendor_deposit.sql), which tracks
-- money the AGENCY has paid OUT to vendors. This tracks money the CLIENT
-- has paid IN to the agency — the other half of the cash picture. Kept as
-- its own table rather than folded into budget_items, since budget_items
-- is planned-vs-actual spend tracking, not a payment log with dates.

create table client_payments (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references events(id) on delete cascade,
  amount numeric not null check (amount >= 0),
  date_sent date not null default current_date,
  created_at timestamptz not null default now()
);

create index idx_client_payments_event on client_payments(event_id);

alter table client_payments enable row level security;

-- Same shape as "planners manage vendors" / "planners manage budget"
-- (0002_rls.sql) — full read/write for planners scoped to their org.
create policy "planners manage client payments" on client_payments for all
  using (is_org_planner(event_id)) with check (is_org_planner(event_id));

-- Read-only for the client this payment log belongs to — same pattern as
-- 0009_client_vendors_budget.sql. A client can see what's been logged
-- against their event, but never add, edit, or delete entries themselves;
-- this is the agency's record of what it received, not a self-report.
create policy "clients read client payments for their event"
  on client_payments for select
  using (is_event_client(event_id));
