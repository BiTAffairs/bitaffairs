// Supabase client wrapper for BiT Affairs.
//
// IMPORTANT: this file only ever uses the public "anon" key, which is safe
// to ship to the browser — every query it makes is still filtered by the
// RLS policies in supabase/migrations/0002_rls.sql. It never uses the
// service-role key, which must never appear in frontend code (see the
// invite-client Edge Function for the one operation that needs it).
//
// App.jsx calls every function in this file directly — there is no local
// fallback mode. If VITE_SUPABASE_URL / VITE_SUPABASE_ANON_KEY aren't set,
// App.jsx shows a "Backend not configured" screen instead of using this
// file at all (see supabaseConfigured below).

import { createClient } from "@supabase/supabase-js";

const supabaseUrl = import.meta.env?.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env?.VITE_SUPABASE_ANON_KEY;

// Whether a real backend is actually configured. App.jsx checks this before
// rendering anything else — createClient() throws immediately if given an
// empty URL/key, so we must not call it at all until we know both are present.
export const supabaseConfigured = Boolean(supabaseUrl && supabaseAnonKey);

export const supabase = supabaseConfigured ? createClient(supabaseUrl, supabaseAnonKey) : null;

if (!supabaseConfigured && typeof window !== "undefined") {
  console.warn(
    "Supabase env vars are not set — BiT Affairs cannot run without a " +
    "connected backend. Copy .env.example to .env and fill in your " +
    "project's URL and anon key. See README.md for full setup steps."
  );
}

function requireSupabase() {
  if (!supabase) {
    throw new Error("Supabase is not configured — see .env.example.");
  }
  return supabase;
}

/* ---------------- Planner auth ---------------- */

export async function signInPlanner(email, password, captchaToken) {
  const { data, error } = await requireSupabase().auth.signInWithPassword({ email, password, options: { captchaToken } });
  if (error) throw error;
  return data.session;
}

// Sends a real email via Supabase Auth with a recovery link. Clicking it
// redirects back here with a temporary recovery session — the
// PASSWORD_RECOVERY event on onAuthStateChange (see App.jsx) is what
// detects that and shows the "set a new password" screen instead of just
// signing the person into the app as-is.
export async function requestPlannerPasswordReset(email, captchaToken) {
  const { error } = await requireSupabase().auth.resetPasswordForEmail(email, {
    redirectTo: window.location.origin,
    captchaToken,
  });
  if (error) throw error;
}

// Only valid while a recovery session from the link above is active —
// Supabase Auth itself enforces that, not app code. Also marks this
// planner's password_set flag true — see 0022_password_set_flag.sql —
// which is the persistent, non-URL-dependent signal restoreSessionFromAuth
// actually relies on to decide whether this screen is needed at all.
export async function updatePlannerPassword(newPassword) {
  const { data: { user }, error: getUserError } = await requireSupabase().auth.getUser();
  if (getUserError) throw getUserError;

  const { error } = await requireSupabase().auth.updateUser({ password: newPassword });
  if (error) throw error;

  if (user) {
    // Best-effort — if this planner doesn't have a row yet for some
    // reason, or the flag update fails, the password itself is already
    // set and they can still sign in; not worth failing the whole flow
    // over a flag that only affects a future convenience check.
    await requireSupabase().from("planners").update({ password_set: true }).eq("id", user.id).then(
      () => {},
      (err) => console.error("Failed to mark password_set", err)
    );
  }
}

export async function signOut() {
  const { error } = await requireSupabase().auth.signOut();
  if (error) throw error;
}

export async function getCurrentPlanner() {
  const { data: { user } } = await requireSupabase().auth.getUser();
  if (!user) return null;
  // maybeSingle, not single — a planner removed by an admin (see removePlanner
  // below) has no row here anymore, and that must come back as null, not a
  // thrown "no rows" Postgres error, so the caller's own "no planner profile"
  // message is what the person actually sees.
  const { data, error } = await requireSupabase().from("planners").select("*").eq("id", user.id).maybeSingle();
  if (error) throw error;
  return data; // includes .role ('admin' | 'team') and .organization_id
}

/* ---------------- Client auth (magic link, no password) ---------------- */

export async function requestClientMagicLink(email, captchaToken) {
  // Sends a real email via Supabase Auth. redirectTo should be the deployed
  // app URL — Supabase Auth settings must have this URL allow-listed.
  const { error } = await requireSupabase().auth.signInWithOtp({
    email,
    options: { emailRedirectTo: window.location.origin, captchaToken },
  });
  if (error) throw error;
}

// The missing link that made magic-link login actually work at all — see
// 0019_client_invite_claim.sql. Call this once right after a magic-link
// redirect completes, before looking up which event(s) the client has
// access to. Safe to call every time a session restores (a client with no
// pending unclaimed invite just gets 0 rows affected, not an error) —
// and safe to call for a planner or an access-code client too, since
// neither of those has any unclaimed invited_email row to match.
export async function claimClientInvites() {
  const { data: { user } } = await requireSupabase().auth.getUser();
  if (!user?.email) return;
  const { error } = await requireSupabase()
    .from("client_access")
    .update({ client_user_id: user.id, accepted_at: new Date().toISOString() })
    .is("client_user_id", null)
    .eq("invited_email", user.email.toLowerCase().trim());
  if (error) throw error;
}

// Plural — a returning client can now be invited to more than one event
// under the same email (see 0019). Combines magic-link invites
// (client_access) and access-code redemptions (client_code_sessions),
// since either can be how a given event was reached, and returns every
// distinct event_id this authenticated person has access to.
export async function getCurrentClientEvents() {
  const { data: { user } } = await requireSupabase().auth.getUser();
  if (!user) return [];

  const [accessRows, codeRows] = await Promise.all([
    requireSupabase().from("client_access").select("event_id").eq("client_user_id", user.id),
    requireSupabase().from("client_code_sessions").select("event_id").eq("user_id", user.id).order("redeemed_at", { ascending: false }),
  ]);
  if (accessRows.error) throw accessRows.error;
  if (codeRows.error) throw codeRows.error;

  const ids = [...(accessRows.data || []), ...(codeRows.data || [])].map((r) => r.event_id);
  return [...new Set(ids)]; // de-dupe — the same event could in principle show up via both paths
}

/* ---------------- Events ---------------- */

// RLS does the real filtering here — a planner only ever gets their org's
// events back, a client only ever gets their own single event.
export async function fetchEvents() {
  const { data, error } = await requireSupabase().from("events").select("*").order("created_at", { ascending: false });
  if (error) throw error;
  return data;
}

export async function fetchEventDetail(eventId) {
  const [phases, tasks, proposal, proposalItems, approvals, vendors, budgetItems, clientPayments, runSheetItems, messages, members, taskRequests] = await Promise.all([
    requireSupabase().from("phases").select("*").eq("event_id", eventId).order("position"),
    requireSupabase().from("tasks").select("*").in(
      "phase_id",
      (await requireSupabase().from("phases").select("id").eq("event_id", eventId)).data?.map((p) => p.id) ?? []
    ),
    requireSupabase().from("proposals").select("*").eq("event_id", eventId).maybeSingle(),
    requireSupabase().from("proposal_items").select("*").eq("event_id", eventId),
    requireSupabase().from("approvals").select("*").eq("event_id", eventId).order("requested_at"),
    requireSupabase().from("vendors").select("*").eq("event_id", eventId), // clients can read these too — see 0009_client_vendors_budget.sql
    requireSupabase().from("budget_items").select("*").eq("event_id", eventId), // clients can read these too — see 0009_client_vendors_budget.sql
    requireSupabase().from("client_payments").select("*").eq("event_id", eventId).order("date_sent", { ascending: false }), // clients can read these too — see 0025_client_payments.sql
    requireSupabase().from("run_sheet_items").select("*").eq("event_id", eventId).order("position"), // planner-only, no client read policy — see 0027_run_sheet.sql
    requireSupabase().from("messages").select("*").eq("event_id", eventId).order("created_at"),
    // planner_id is required here (not just email/display_name) so the UI
    // can appoint specific people to a restricted task — see task_assignees.
    requireSupabase().from("event_members").select("planner_id, member_role, planners(email, display_name)").eq("event_id", eventId),
    // Empty for team members, planner-and-up + client-owned rows only —
    // see 0011_client_task_requests.sql.
    requireSupabase().from("task_requests").select("*").eq("event_id", eventId).order("requested_at", { ascending: false }),
  ]);

  // task_assignees isn't scoped by event_id directly (it hangs off tasks),
  // so fetch it keyed to the task ids we actually got back — RLS still
  // filters this to rows the caller is allowed to see either way.
  const taskIds = (tasks.data ?? []).map((t) => t.id);
  const taskAssignees = taskIds.length
    ? await requireSupabase().from("task_assignees").select("task_id, planner_id").in("task_id", taskIds)
    : { data: [] };

  return {
    phases: phases.data ?? [],
    tasks: tasks.data ?? [],
    proposal: proposal.data ?? null,
    proposalItems: proposalItems.data ?? [],
    approvals: approvals.data ?? [],
    vendors: vendors.data ?? [],
    budgetItems: budgetItems.data ?? [],
    clientPayments: clientPayments.data ?? [],
    runSheetItems: runSheetItems.data ?? [],
    messages: messages.data ?? [],
    members: members.data ?? [],
    taskRequests: taskRequests.data ?? [],
    taskAssignees: taskAssignees.data ?? [],
  };
}

/* ---------------- Mutations (RLS + triggers enforce who can do what) ---------------- */

export async function toggleTask(taskId, done) {
  const { error } = await requireSupabase().from("tasks").update({ done }).eq("id", taskId);
  if (error) throw error;
}

export async function submitProposalForReview(eventId) {
  const { error } = await requireSupabase().from("proposals").update({ status: "pending_review" }).eq("event_id", eventId);
  if (error) throw error; // trigger rejects this unless caller is a team member on a draft
}

export async function approveAndSendProposal(eventId) {
  const { error } = await requireSupabase().from("proposals").update({ status: "sent" }).eq("event_id", eventId);
  if (error) throw error; // trigger rejects this unless caller is an admin
}

export async function rejectProposalToDraft(eventId) {
  const { error } = await requireSupabase().from("proposals").update({ status: "draft" }).eq("event_id", eventId);
  if (error) throw error; // trigger rejects this unless caller is an admin
}

export async function clientApproveProposal(eventId) {
  const { error } = await requireSupabase().from("proposals").update({ status: "approved" }).eq("event_id", eventId);
  if (error) throw error; // trigger rejects this unless caller is the invited client and status is 'sent'
}

export async function clientDisapproveProposal(eventId) {
  const { error } = await requireSupabase().from("proposals").update({ status: "disapproved" }).eq("event_id", eventId);
  if (error) throw error; // trigger rejects this unless caller is the invited client and status is 'sent'
}

export async function requestApproval(eventId, label, description) {
  // Trigger forces status to 'pending_review' unless the caller is an admin.
  const { error } = await requireSupabase().from("approvals").insert({ event_id: eventId, label, description });
  if (error) throw error;
}

// Admin-only — see 0018_approval_edit_delete.sql. Editing never touches
// status; the same row's status field is simply omitted from this update.
export async function updateApproval(approvalId, label, description) {
  const { error } = await requireSupabase().from("approvals").update({ label, description }).eq("id", approvalId);
  if (error) throw error; // trigger rejects this unless caller is an admin
}

export async function deleteApproval(approvalId) {
  const { error } = await requireSupabase().from("approvals").delete().eq("id", approvalId);
  if (error) throw error; // trigger rejects this unless caller is an admin
}

export async function releaseApprovalToClient(approvalId) {
  const { error } = await requireSupabase().from("approvals").update({ status: "pending" }).eq("id", approvalId);
  if (error) throw error; // trigger rejects this unless caller is an admin
}

export async function clientApproveMilestone(approvalId) {
  const { error } = await requireSupabase().from("approvals").update({ status: "approved" }).eq("id", approvalId);
  if (error) throw error; // trigger rejects this unless caller is the invited client and status is 'pending'
}

export async function clientDisapproveMilestone(approvalId) {
  const { error } = await requireSupabase().from("approvals").update({ status: "disapproved" }).eq("id", approvalId);
  if (error) throw error; // trigger rejects this unless caller is the invited client and status is 'pending'
}

/* ---------------- Push notifications ---------------- */
// See 0016_push_notifications.sql and supabase/functions/send-push. These
// two just persist/remove a browser's push subscription — the actual
// permission prompt and browser-side subscribe() call live in App.jsx,
// since that's UI-triggered, not a pure data op.
//
// Each explicitly nulls the *other* owner column on conflict, not just
// sets its own — a bare upsert only touches the columns it lists, so
// without this, the same physical browser being used for both a planner
// login and (separately) a client login would leave stale data in
// whichever column it didn't just write, silently violating the
// "exactly one owner" intent even where RLS happens to allow the write.
// (In practice RLS usually blocks a same-endpoint cross-owner switch
// outright — see the retry-with-a-fresh-subscription handling in
// App.jsx's enableNotifications for how that's actually recovered from.)

export async function savePlannerPushSubscription(plannerId, subscription) {
  const json = subscription.toJSON();
  const { error } = await requireSupabase().from("push_subscriptions").upsert(
    { planner_id: plannerId, event_id: null, endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth },
    { onConflict: "endpoint" }
  );
  if (error) throw error;
  await pruneOldSubscriptions("planner_id", plannerId);
}

export async function saveClientPushSubscription(eventId, subscription) {
  const json = subscription.toJSON();
  const { error } = await requireSupabase().from("push_subscriptions").upsert(
    { event_id: eventId, planner_id: null, endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth },
    { onConflict: "endpoint" }
  );
  if (error) throw error;
  await pruneOldSubscriptions("event_id", eventId);
}

// A reinstall (or re-enabling notifications after uninstalling) gets a
// brand new, entirely unrelated push endpoint every time — there's no way
// to detect "this is the same physical device as before" from the
// subscription alone, by design (that's a deliberate Web Push privacy
// property, not a gap). send-push's own 404/410 cleanup only catches a
// dead endpoint once a send is actually attempted against it, and in
// practice a push service can keep accepting sends to a since-abandoned
// endpoint for a while — so during active testing (reinstalling
// repeatedly on the same phone), dead rows can pile up faster than that
// natural cleanup catches them, and every send goes to all of them. This
// bounds the pile-up directly instead: keep only the N most recent
// subscriptions per owner, without assuming which ones are "real" vs
// stale. Legitimate multi-device use (phone + laptop) still works fine as
// long as someone has this many-or-fewer active devices.
const MAX_SUBSCRIPTIONS_PER_OWNER = 3;

async function pruneOldSubscriptions(ownerColumn, ownerId) {
  const { data, error } = await requireSupabase()
    .from("push_subscriptions")
    .select("id")
    .eq(ownerColumn, ownerId)
    .order("created_at", { ascending: false });
  if (error || !data) return; // best-effort — never let cleanup failure break the actual subscribe flow
  const staleIds = data.slice(MAX_SUBSCRIPTIONS_PER_OWNER).map((r) => r.id);
  if (staleIds.length > 0) {
    await requireSupabase().from("push_subscriptions").delete().in("id", staleIds);
  }
}

export async function removePushSubscription(endpoint) {
  const { error } = await requireSupabase().from("push_subscriptions").delete().eq("endpoint", endpoint);
  if (error) throw error;
}
// See 0015_realtime.sql for enabling this on the Postgres side.

// One always-on subscription covering messages, proposals, approvals, and
// task_requests. No event_id filter is needed: Realtime evaluates each
// table's existing RLS SELECT policy per connected user on every change,
// so a planner only ever receives rows for their org's events and a
// client only ever receives rows for their one event — same scoping as a
// normal query, just pushed immediately instead of waiting for the next
// fetch. Returns an unsubscribe function.
export function subscribeToActivity(onChange) {
  const tables = ["messages", "proposals", "approvals", "task_requests"];
  let channel = requireSupabase().channel("bitaffairs-activity");
  for (const table of tables) {
    channel = channel.on("postgres_changes", { event: "*", schema: "public", table }, (payload) => onChange(table, payload));
  }
  channel.subscribe();
  return () => requireSupabase().removeChannel(channel);
}

export async function sendMessage(eventId, authorType, authorName, body, imageUrl) {
  const { error } = await requireSupabase().from("messages").insert({
    event_id: eventId, author_type: authorType, author_name: authorName, body, image_url: imageUrl,
  });
  if (error) throw error;
}

// Any Studio user can delete any message (existing "planners manage
// messages" policy); a client can delete their own — see
// 0018_approval_edit_delete.sql for the client-side grant.
export async function deleteMessage(messageId) {
  const { error } = await requireSupabase().from("messages").delete().eq("id", messageId);
  if (error) throw error;
}

/* ---------------- Tasks, vendors, and project creation ---------------- */

/* ---------------- Proposal line items ---------------- */
// Editable while the proposal is in "draft" — once submitted for review or
// sent, changes should go through "send back to draft" first, keeping the
// admin-approval workflow meaningful rather than editable out from under it.

export async function addProposalItem(eventId, item) {
  const { error } = await requireSupabase().from("proposal_items").insert({
    event_id: eventId, label: item.label, qty: item.qty, unit_cost: item.unitCost,
  });
  if (error) throw error;
}

export async function updateProposalItem(itemId, item) {
  const { error } = await requireSupabase().from("proposal_items")
    .update({ label: item.label, qty: item.qty, unit_cost: item.unitCost })
    .eq("id", itemId);
  if (error) throw error;
}

export async function deleteProposalItem(itemId) {
  const { error } = await requireSupabase().from("proposal_items").delete().eq("id", itemId);
  if (error) throw error;
}

// supabase-js's functions.invoke() only ever gives a generic "Edge
// Function returned a non-2xx status code" message on failure — the
// actual reason (which invite-client/invite-planner both carefully return
// as JSON, e.g. "Only an admin can add team members" or a real Supabase
// Auth error like "User already registered") sits unread in
// error.context, the raw Response object. This reads it so the real
// cause reaches the UI instead of a message that hides it.
async function functionErrorMessage(error) {
  try {
    if (error?.context?.json) {
      const body = await error.context.json();
      if (body?.error) return String(body.error);
    }
  } catch {
    // context wasn't valid JSON, or already consumed — fall through
  }
  return error?.message || "Something went wrong calling the server.";
}

export async function inviteClient(eventId, clientEmail) {
  const { data, error } = await requireSupabase().functions.invoke("invite-client", {
    body: { eventId, clientEmail },
  });
  if (error) throw new Error(await functionErrorMessage(error));
  return data;
}

export async function generateClientCode(eventId) {
  const { data, error } = await requireSupabase().rpc("generate_client_code", { p_event_id: eventId });
  if (error) throw error;
  return data; // the code itself, as a string
}

// Anonymous sign-in must be enabled in the Supabase dashboard (Authentication
// → Providers → Anonymous Sign-ins) or this will fail with a clear error.
// The actual code check happens in the redeem-code Edge Function, not a
// direct RPC call — see 0028_code_rate_limit.sql for why: a plain SQL
// function has no way to see the caller's IP, so it couldn't rate-limit
// repeated guesses. This can, and locks out an IP after too many failures.
export async function redeemClientCode(code, captchaToken) {
  const client = requireSupabase();
  const { error: authError } = await client.auth.signInAnonymously({ options: { captchaToken } });
  if (authError) throw authError;
  const { data, error } = await client.functions.invoke("redeem-code", { body: { code } });
  if (error) throw new Error(await functionErrorMessage(error));
  return data.eventId;
}

export async function invitePlanner(email, role) {
  const { data, error } = await requireSupabase().functions.invoke("invite-planner", {
    body: { email, role },
  });
  if (error) throw new Error(await functionErrorMessage(error));
  return data;
}

export async function fetchTeamMembers() {
  const { data, error } = await requireSupabase().from("planners").select("id, email, role").order("email");
  if (error) throw error;
  return data;
}

export async function updatePlannerRole(plannerId, role) {
  const { error } = await requireSupabase().from("planners").update({ role }).eq("id", plannerId);
  if (error) throw error;
}

// Removes a teammate's Studio access. Does not touch their underlying auth
// account — see 0010_remove_planner.sql for why that's enough, and for the
// server-side guards (can't remove yourself, can't remove the last admin)
// that make this safe to call directly from the client.
export async function removePlanner(plannerId) {
  const { error } = await requireSupabase().from("planners").delete().eq("id", plannerId);
  if (error) throw error;
}

// Real account deletion — planner or client, self or admin-triggered.
// Unlike removePlanner above, this deletes the underlying Supabase Auth
// user entirely (needs the service-role key, hence the Edge Function —
// see delete-account/index.ts). Omit targetUserId to delete your own
// account; pass another user's id as an admin to delete theirs. The
// server enforces who's allowed to do which — see the function for the
// exact rules (last-admin protection still applies either way).
export async function deleteAccount(targetUserId) {
  const { data, error } = await requireSupabase().functions.invoke("delete-account", {
    body: targetUserId ? { targetUserId } : {},
  });
  if (error) throw new Error(await functionErrorMessage(error));
  return data;
}

export async function assignTask(taskId, assignee) {
  const { error } = await requireSupabase().from("tasks").update({ assignee }).eq("id", taskId);
  if (error) throw error;
}

export async function addVendor(eventId, vendor) {
  const { error } = await requireSupabase().from("vendors").insert({
    event_id: eventId,
    name: vendor.name,
    category: vendor.category,
    contact: vendor.contact,
    phone: vendor.phone || null,
    cost: vendor.cost,
    status: "inquiry",
  });
  if (error) throw error;
}

export async function updateVendorPhone(vendorId, phone) {
  const { error } = await requireSupabase().from("vendors").update({ phone }).eq("id", vendorId);
  if (error) throw error;
}

// Full edit — name, category, contact — for correcting a vendor's details
// after creation, same as phone/cost/deposit above.
export async function updateVendorDetails(vendorId, { name, category, contact }) {
  const { error } = await requireSupabase().from("vendors").update({ name, category, contact }).eq("id", vendorId);
  if (error) throw error;
}

// No other table references vendors by foreign key, so this is a plain
// delete — nothing else to cascade or clean up.
export async function deleteVendor(vendorId) {
  const { error } = await requireSupabase().from("vendors").delete().eq("id", vendorId);
  if (error) throw error;
}

// Due dates (0026_due_dates.sql) — one per vendor (when the agency owes
// them the rest of their price) and one per event (when the client owes
// the rest of the budget). Null clears the date.
export async function updateVendorBalanceDueDate(vendorId, dueDate) {
  const { error } = await requireSupabase().from("vendors").update({ balance_due_date: dueDate }).eq("id", vendorId);
  if (error) throw error;
}

export async function updateEventBalanceDueDate(eventId, dueDate) {
  const { error } = await requireSupabase().from("events").update({ client_balance_due_date: dueDate }).eq("id", eventId);
  if (error) throw error;
}

// Day-of run sheet (0027_run_sheet.sql) — planner-only, never exposed to
// clients. position controls display order; new items append to the end
// (caller passes items.length as position), and moveRunSheetItem swaps
// two neighboring positions to reorder.
export async function addRunSheetItem(eventId, { timeLabel, title, notes, position }) {
  const { error } = await requireSupabase()
    .from("run_sheet_items")
    .insert({ event_id: eventId, time_label: timeLabel || null, title, notes: notes || null, position });
  if (error) throw error;
}

export async function updateRunSheetItem(itemId, { timeLabel, title, notes }) {
  const { error } = await requireSupabase()
    .from("run_sheet_items")
    .update({ time_label: timeLabel || null, title, notes: notes || null })
    .eq("id", itemId);
  if (error) throw error;
}

export async function deleteRunSheetItem(itemId) {
  const { error } = await requireSupabase().from("run_sheet_items").delete().eq("id", itemId);
  if (error) throw error;
}

export async function setRunSheetItemPosition(itemId, position) {
  const { error } = await requireSupabase().from("run_sheet_items").update({ position }).eq("id", itemId);
  if (error) throw error;
}

// Cost is editable after creation — vendor prices routinely change as
// quotes firm up. The deposit check constraint (0024_vendor_deposit.sql)
// means Postgres itself will reject dropping cost below an already-
// recorded deposit, so the error from that needs to reach the caller
// intact rather than being swallowed.
export async function updateVendorCost(vendorId, cost) {
  const { error } = await requireSupabase().from("vendors").update({ cost }).eq("id", vendorId);
  if (error) throw error;
}

// Deposit is entered after the vendor already exists, not at creation —
// same DB-level guard applies here (deposit can't exceed cost).
export async function updateVendorDeposit(vendorId, deposit) {
  const { error } = await requireSupabase().from("vendors").update({ deposit }).eq("id", vendorId);
  if (error) throw error;
}

export async function cycleVendorStatus(vendorId, nextStatus) {
  const { error } = await requireSupabase().from("vendors").update({ status: nextStatus }).eq("id", vendorId);
  if (error) throw error;
}

// Client payments — money the client has sent the agency (0025_client_payments.sql).
// Planner-only writes; clients can read their own event's log but not add
// to it themselves, since this is the agency's record of what it actually
// received, not a self-report.
export async function addClientPayment(eventId, amount, dateSent) {
  const { error } = await requireSupabase()
    .from("client_payments")
    .insert({ event_id: eventId, amount, date_sent: dateSent });
  if (error) throw error;
}

export async function deleteClientPayment(paymentId) {
  const { error } = await requireSupabase().from("client_payments").delete().eq("id", paymentId);
  if (error) throw error;
}

// Creates the event row plus its starter proposal row and default phases/tasks
// in one pass. Not wrapped in a single DB transaction (supabase-js doesn't
// expose multi-statement transactions directly) — for production use, this
// is a good candidate to move into a Postgres function (see approve_proposal
// in 0003_triggers.sql for the pattern) so it's atomic.
export async function createEvent({ organizationId, plannerId, name, type, date, venue, clientName, clientEmail, budgetTotal, phaseTemplate }) {
  const client = requireSupabase();

  const { data: event, error: eventError } = await client
    .from("events")
    .insert({
      organization_id: organizationId,
      name,
      type,
      event_date: date,
      venue,
      status: "Early planning",
      budget_total: budgetTotal,
    })
    .select()
    .single();
  if (eventError) throw eventError;

  const { error: memberError } = await client
    .from("event_members")
    .insert({ event_id: event.id, planner_id: plannerId, member_role: "lead" });
  if (memberError) throw memberError;

  const { error: proposalError } = await client.from("proposals").insert({ event_id: event.id, status: "draft" });
  if (proposalError) throw proposalError;

  if (clientEmail) {
    const { error: clientError } = await client
      .from("client_access")
      .insert({ event_id: event.id, invited_email: clientEmail.toLowerCase().trim() });
    if (clientError) throw clientError;
  }

  for (let i = 0; i < (phaseTemplate || []).length; i++) {
    const phase = phaseTemplate[i];
    const { data: phaseRow, error: phaseError } = await client
      .from("phases")
      .insert({ event_id: event.id, title: phase.title, position: i })
      .select()
      .single();
    if (phaseError) throw phaseError;

    const taskRows = phase.tasks.map((label, ti) => ({
      phase_id: phaseRow.id, label, done: false, assignee: null, position: ti,
    }));
    if (taskRows.length > 0) {
      const { error: taskError } = await client.from("tasks").insert(taskRows);
      if (taskError) throw taskError;
    }
  }

  return event.id;
}

/* ---------------- Admin: delete projects, manage tasks directly ---------------- */

// Deleting the event cascades to every child row (phases, tasks, proposals,
// approvals, vendors, budget items, messages, client access) via the
// "on delete cascade" foreign keys in 0001_init.sql — one call is enough.
// The RLS delete policy (0005_admin_controls.sql) additionally requires the
// caller to be an admin in that event's organization, not just any planner.
export async function deleteEvent(eventId) {
  const { error } = await requireSupabase().from("events").delete().eq("id", eventId);
  if (error) throw error;
}

// Admin-only at the database level too — see the split insert/delete
// policies on "tasks" in 0005_admin_controls.sql. Team members can still
// toggle done/assignee on existing tasks (that policy is unchanged).
// Pass { visibility: "restricted", assigneePlannerIds: [...] } to create a
// task only admins and those specific planners can see or manage — see
// 0012_restricted_tasks.sql. Two calls, not one transaction (same
// trade-off noted on createEvent above) — if the second call fails the
// task exists but with no appointees, which for a restricted task simply
// means only admins can see it until someone is added.
export async function addTask(phaseId, label, { visibility = "team", assigneePlannerIds = [] } = {}) {
  const { data, error } = await requireSupabase()
    .from("tasks")
    .insert({ phase_id: phaseId, label, done: false, visibility })
    .select()
    .single();
  if (error) throw error;

  if (visibility === "restricted" && assigneePlannerIds.length > 0) {
    const { error: assigneeError } = await requireSupabase()
      .from("task_assignees")
      .insert(assigneePlannerIds.map((plannerId) => ({ task_id: data.id, planner_id: plannerId })));
    if (assigneeError) throw assigneeError;
  }
  return data;
}

export async function deleteTask(taskId) {
  const { error } = await requireSupabase().from("tasks").delete().eq("id", taskId);
  if (error) throw error;
}

/* ---------------- Client task requests ---------------- */
// Clients propose, admins dispose — see 0011_client_task_requests.sql.

export async function requestTask(eventId, label, description) {
  const { error } = await requireSupabase().from("task_requests").insert({ event_id: eventId, label, description });
  if (error) throw error;
}

export async function dismissTaskRequest(requestId) {
  const { error } = await requireSupabase().from("task_requests").update({ status: "dismissed" }).eq("id", requestId);
  if (error) throw error; // trigger rejects this unless caller is an admin and the request is still pending
}

// Turns a request into a real task on the chosen phase, then marks the
// request approved and links it to the task it became. Admin-only, same
// as addTask itself — the request-approval policy just gates the status
// update; the tasks insert policy independently gates the task creation.
export async function approveTaskRequest(requestId, phaseId, label) {
  const task = await addTask(phaseId, label);
  const { error } = await requireSupabase()
    .from("task_requests")
    .update({ status: "approved", resolved_task_id: task.id })
    .eq("id", requestId);
  if (error) throw error;
  return task;
}
