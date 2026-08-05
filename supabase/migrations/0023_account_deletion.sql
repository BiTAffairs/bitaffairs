-- BiT Affairs — real account deletion (planners + clients)
--
-- 0010_remove_planner.sql's enforce_planner_deletion() blocks a planner
-- from deleting their own `planners` row — correct for "remove teammate"
-- (an admin removing someone else), where self-removal would just be a
-- confusing way to lock yourself out by mistake. But real self-service
-- account deletion (new: delete-account Edge Function) needs the opposite:
-- deleting your own Auth user MUST be allowed to cascade into deleting
-- your own `planners` row (planners.id references auth.users(id) on
-- delete cascade).
--
-- Distinguish the two the same way 0020_fix_project_delete_cascade.sql
-- distinguished "direct delete" from "cascade already authorized upstream":
-- if the auth.users row for this id is already gone, this delete is firing
-- as part of that cascade, whose authorization was already checked in the
-- Edge Function (self, or an admin acting on someone in their org) — so
-- skip the self-delete check. The last-admin check still applies either
-- way: an org can never be left with zero admins, whether someone tries
-- to remove another admin or delete their own account.

create or replace function enforce_planner_deletion()
returns trigger
language plpgsql
security definer
as $$
declare
  remaining_admins int;
  auth_user_still_exists boolean;
begin
  select exists(select 1 from auth.users where id = old.id) into auth_user_still_exists;

  if old.id = auth.uid() and auth_user_still_exists then
    raise exception 'You cannot remove your own account — have another admin do it.';
  end if;

  if old.role = 'admin' then
    select count(*) into remaining_admins
    from planners
    where organization_id = old.organization_id
      and role = 'admin'
      and id <> old.id;
    if remaining_admins = 0 then
      raise exception 'Cannot remove the last admin in an organization. Promote another teammate to admin first.';
    end if;
  end if;

  return old;
end;
$$;

-- client_access already cascades cleanly on client_user_id -> auth.users
-- delete (0001_init.sql) with no blocking trigger, so a client's account
-- deletion needs no schema change here.
