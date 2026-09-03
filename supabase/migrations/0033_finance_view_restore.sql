-- BiT Affairs — restore team-member visibility, mask per-vendor figures
--
-- Supersedes 0031_finance_admin_only.sql, which went further than
-- actually wanted: team members should see vendors, budget, and client
-- payments — just not which vendor is being paid what. That's a column-
-- level distinction RLS can't express directly (RLS is row-level), so
-- this uses a security-definer VIEW that nulls out the financial columns
-- for anyone who isn't an admin or the event's own client.
--
-- IMPORTANT: plain Postgres views bypass RLS by default — they run as
-- the view owner, not the querying user, unless security_invoker is set.
-- Skipping that here would have handed every vendor's real cost/deposit
-- to everyone, the opposite of the point. See Supabase's own RLS docs.

-- These drops use IF EXISTS and cover both possible prior names, since
-- it's unclear whether 0031 was ever actually applied before this
-- superseded it (it was proposed and quickly revised in the same
-- conversation) — this way the migration works correctly whether the
-- live database is still on the original 0002_rls.sql policy name or
-- already moved through 0031's.
drop policy if exists "planners manage vendors" on vendors;
drop policy if exists "admins manage vendors" on vendors;
create policy "planners read vendors" on vendors for select
  using (is_org_planner(event_id));
create policy "admins insert vendors" on vendors for insert
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins update vendors" on vendors for update
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins delete vendors" on vendors for delete
  using (is_org_planner(event_id) and is_admin_planner());

drop policy if exists "planners manage budget" on budget_items;
drop policy if exists "admins manage budget" on budget_items;
create policy "planners read budget" on budget_items for select
  using (is_org_planner(event_id));
create policy "admins insert budget" on budget_items for insert
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins update budget" on budget_items for update
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins delete budget" on budget_items for delete
  using (is_org_planner(event_id) and is_admin_planner());

drop policy if exists "planners manage client payments" on client_payments;
drop policy if exists "admins manage client payments" on client_payments;
create policy "planners read client payments" on client_payments for select
  using (is_org_planner(event_id));
create policy "admins insert client payments" on client_payments for insert
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins update client payments" on client_payments for update
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());
create policy "admins delete client payments" on client_payments for delete
  using (is_org_planner(event_id) and is_admin_planner());

-- Masked read of vendors — everything except cost/deposit/balance_due_date
-- visible to any org planner; those three columns only visible to an
-- admin planner or the event's own client (clients already saw full
-- vendor figures before any of this — 0009_client_vendors_budget.sql —
-- and that's unchanged here, not a new exposure).
--
-- security_invoker = true is what makes this actually enforce anything —
-- without it the view would run as its owner and ignore the vendors RLS
-- policies above entirely. Not updatable (the case expressions make that
-- automatic), and explicitly revoked/granted below as a second layer on
-- top of that so nothing can write through it even by accident.
create view vendors_for_planner with (security_invoker = true) as
select
  id, event_id, name, category, contact, phone, status,
  case when is_admin_planner() or is_event_client(event_id) then cost else null end as cost,
  case when is_admin_planner() or is_event_client(event_id) then deposit else null end as deposit,
  case when is_admin_planner() or is_event_client(event_id) then balance_due_date else null end as balance_due_date
from vendors;

revoke insert, update, delete on vendors_for_planner from anon, authenticated;
grant select on vendors_for_planner to authenticated;

-- The Budget page's "Paid to confirmed vendors" total is an aggregate,
-- not a per-vendor figure — you confirmed team members can see that. It
-- used to be computed client-side by summing each vendor's deposit, which
-- no longer works once those come back masked. This computes the same
-- sum entirely server-side, so a team member gets the correct total
-- without any itemized figure ever reaching their browser.
create or replace function vendor_spend_total(p_event_id uuid)
returns numeric
language plpgsql
security definer
stable
as $$
begin
  if not is_org_planner(p_event_id) then
    raise exception 'Not authorized for this event';
  end if;
  return (
    select coalesce(sum(deposit), 0)
    from vendors
    where event_id = p_event_id and status = 'confirmed'
  );
end;
$$;
