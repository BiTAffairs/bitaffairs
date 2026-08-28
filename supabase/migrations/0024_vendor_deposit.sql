-- BiT Affairs — vendor deposits and balance
--
-- Vendors already track a full price (`cost`). This adds `deposit` — the
-- amount actually paid so far — so the app can show a real "balance
-- remaining" per vendor (cost - deposit) instead of only the full price.
--
-- The check constraint keeps a deposit from ever exceeding the vendor's
-- price at the database level, not just in the UI — this also means an
-- attempt to lower `cost` below an already-recorded deposit will be
-- rejected by Postgres rather than silently producing a negative balance.

alter table vendors
  add column deposit numeric not null default 0
    check (deposit >= 0 and deposit <= cost);
