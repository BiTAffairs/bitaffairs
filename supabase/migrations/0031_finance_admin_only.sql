-- BiT Affairs — finance is admin-only, not just edit-restricted
--
-- Previously any org planner (team member or admin) could read and write
-- vendors, budget_items, and client_payments — is_org_planner() with no
-- role check. Per the decision this migration implements: team members
-- shouldn't see this data at all, not just be blocked from editing it.
-- Hiding the tabs in the UI alone wouldn't actually enforce that — a team
-- member could still read this data directly via the API — so the real
-- fix is here, at the RLS level.
--
-- Client-facing read policies (0009_client_vendors_budget.sql,
-- 0025_client_payments.sql) are untouched — clients still see their own
-- event's vendors/budget/payments read-only, same as before. This only
-- changes which *planners* can reach these tables.

drop policy "planners manage vendors" on vendors;
create policy "admins manage vendors" on vendors for all
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());

drop policy "planners manage budget" on budget_items;
create policy "admins manage budget" on budget_items for all
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());

drop policy "planners manage client payments" on client_payments;
create policy "admins manage client payments" on client_payments for all
  using (is_org_planner(event_id) and is_admin_planner())
  with check (is_org_planner(event_id) and is_admin_planner());

-- events.client_balance_due_date is a single column on an otherwise
-- general-purpose table — the broad "planners update their org's events"
-- policy (0002_rls.sql) is correct to stay open to any org planner for
-- the table as a whole (there's no reason to lock team members out of
-- event fields generally). RLS can't restrict one column while leaving
-- others open, so this is a trigger instead, same pattern already used
-- for planner-deletion guards (0010, 0023): block the update only when
-- this specific field is the one changing and the caller isn't an admin.
create or replace function enforce_finance_field_admin_only()
returns trigger
language plpgsql
security definer
as $$
begin
  if new.client_balance_due_date is distinct from old.client_balance_due_date
     and not is_admin_planner() then
    raise exception 'Only an admin can change the client balance due date';
  end if;
  return new;
end;
$$;

create trigger trg_enforce_finance_field_admin_only
  before update on events
  for each row
  execute function enforce_finance_field_admin_only();
