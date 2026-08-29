-- BiT Affairs — shorten access code validity to 10 minutes
--
-- generate_client_code() (0008_client_code_login.sql) defaulted to a
-- 30-day validity window — reasonable when the code was thought of as a
-- standing "no email needed" invite, but a much bigger target than it
-- needs to be now that 0028_code_rate_limit.sql exists specifically to
-- slow down guessing: a code only needs to survive long enough for the
-- planner to read it out or text it to the client in the moment, not
-- stay valid for a month. Shortening the window shrinks the guessing
-- opportunity directly, on top of (not instead of) the rate limit.
--
-- Same function, same signature shape (create or replace keeps the
-- existing revoke from 0028 intact) — just the unit and default change
-- from days to minutes.

create or replace function generate_client_code(p_event_id uuid, p_minutes_valid int default 10)
returns text
language plpgsql
security definer
as $$
declare
  new_code text;
  chars text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; -- no 0/O/1/I — easy to read aloud
  i int;
  existing_id uuid;
begin
  if not (is_org_planner(p_event_id) and is_admin_planner()) then
    raise exception 'Only an admin can generate an access code';
  end if;

  new_code := '';
  for i in 1..8 loop
    new_code := new_code || substr(chars, floor(random() * length(chars) + 1)::int, 1);
  end loop;

  -- Postgres unique constraints don't treat two NULLs as equal, so a plain
  -- "on conflict" upsert can't be used here — look up any existing
  -- code-only row (invited_email is null) for this event explicitly instead.
  select id into existing_id from client_access
  where event_id = p_event_id and invited_email is null
  limit 1;

  if existing_id is not null then
    update client_access
    set invite_code = new_code, code_expires_at = now() + (p_minutes_valid || ' minutes')::interval
    where id = existing_id;
  else
    insert into client_access (event_id, invite_code, code_expires_at, invited_email)
    values (p_event_id, new_code, now() + (p_minutes_valid || ' minutes')::interval, null);
  end if;

  return new_code;
end;
$$;
