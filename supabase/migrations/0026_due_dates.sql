-- BiT Affairs — payment due dates
--
-- Both vendors.deposit (0024) and client_payments (0025) track amounts
-- but not deadlines — nothing warns anyone before a payment is overdue,
-- only shows the state after the fact. This adds one due date per side:
--
-- vendors.balance_due_date — when the agency owes the vendor the rest of
-- their price. Per-vendor, since each vendor negotiates their own terms.
--
-- events.client_balance_due_date — when the client owes the rest of the
-- event's budget. One date per event (not a full payment schedule — a
-- deliberate scope decision, not a placeholder for one), since most
-- events have a single final-balance deadline rather than a multi-
-- installment plan.

alter table vendors add column balance_due_date date;
alter table events add column client_balance_due_date date;
