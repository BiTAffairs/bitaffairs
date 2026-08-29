// Supabase Edge Function: delete-account
//
// Deletes a real Supabase Auth account — planner or client. Needs the
// service-role key (same reason invite-planner/invite-client do): deleting
// an auth.users row is an admin-API operation the browser can never do
// directly.
//
// Two call shapes:
//   { }                      -> self-service: caller deletes their own account
//   { targetUserId: "..." }  -> admin-triggered: caller must be an admin
//                               planner, and the target must belong to
//                               their organization (as a planner, or as a
//                               client with access to one of their events)
//
// Deleting the auth user cascades automatically:
//   - planners.id references auth.users(id) on delete cascade
//     (see 0023_account_deletion.sql for the trigger fix that lets a
//     planner's own account deletion through, while still blocking
//     direct self-removal via "remove teammate" and still blocking
//     removal of an org's last admin)
//   - client_access.client_user_id references auth.users(id) on delete
//     cascade (0001_init.sql) — no trigger guards this, nothing further
//     needed for clients.
// Events, tasks, vendors, budget items are NOT touched either way — they
// belong to the organization, not to an individual planner or client.
//
// Deploy with: supabase functions deploy delete-account

import { serve } from "https://deno.land/std@0.203.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Locked to the app's own origin rather than "*" — this function is only
// ever meant to be called from the deployed app itself, not from any
// arbitrary webpage that happens to have gotten hold of someone's token.
// Reuses the same APP_URL secret already set for invite-email redirects
// (see invite-planner/invite-client) rather than introducing a new one.
// Falls back to "*" only if APP_URL somehow isn't set, so a missing
// secret degrades to the old (less safe) behavior instead of breaking
// the function outright.
const allowedOrigin = Deno.env.get("APP_URL") || "*";
const corsHeaders = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Vary": "Origin",
};

function jsonResponse(body: unknown, status: number) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) return jsonResponse({ error: "Missing Authorization header" }, 401);

    const callerClient = createClient(supabaseUrl, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: userError } = await callerClient.auth.getUser();
    if (userError || !user) return jsonResponse({ error: "Not authenticated" }, 401);

    const body = await req.json().catch(() => ({}));
    const targetUserId: string = body?.targetUserId || user.id;
    const isSelf = targetUserId === user.id;

    const adminClient = createClient(supabaseUrl, serviceRoleKey);

    // Last-admin protection, checked explicitly here rather than relying
    // solely on the DB trigger (0023_account_deletion.sql). The trigger
    // still fires either way as a real safety net, but a Postgres
    // exception raised mid-cascade from the Admin API's deleteUser() call
    // isn't a path this app has ever exercised before — better to give a
    // clean, predictable error here than hope GoTrue's wrapping preserves
    // the trigger's message intact.
    const { data: targetAsPlanner } = await adminClient
      .from("planners")
      .select("organization_id, role")
      .eq("id", targetUserId)
      .maybeSingle();

    if (targetAsPlanner?.role === "admin") {
      const { count } = await adminClient
        .from("planners")
        .select("id", { count: "exact", head: true })
        .eq("organization_id", targetAsPlanner.organization_id)
        .eq("role", "admin")
        .neq("id", targetUserId);
      if (!count) {
        return jsonResponse(
          { error: "Cannot delete the last admin in an organization. Promote another teammate to admin first." },
          400
        );
      }
    }

    if (!isSelf) {
      // Admin-triggered: caller must be an admin planner.
      const { data: callerPlanner } = await adminClient
        .from("planners")
        .select("organization_id, role")
        .eq("id", user.id)
        .single();
      if (!callerPlanner || callerPlanner.role !== "admin") {
        return jsonResponse({ error: "Only an admin can delete another account" }, 403);
      }

      // Is the target a planner in the caller's org? (already fetched
      // above as targetAsPlanner, for the last-admin check.)
      if (targetAsPlanner) {
        if (targetAsPlanner.organization_id !== callerPlanner.organization_id) {
          return jsonResponse({ error: "That account isn't in your organization" }, 403);
        }
      } else {
        // Not a planner — is the target a client with access to one of
        // the caller's org's events?
        const { data: clientAccess } = await adminClient
          .from("client_access")
          .select("event_id, events!inner(organization_id)")
          .eq("client_user_id", targetUserId);

        const belongsToOrg = (clientAccess || []).some(
          (row: any) => row.events?.organization_id === callerPlanner.organization_id
        );
        if (!belongsToOrg) {
          return jsonResponse({ error: "That account isn't in your organization" }, 403);
        }
      }
    }

    const { error: deleteError } = await adminClient.auth.admin.deleteUser(targetUserId);
    if (deleteError) throw deleteError;

    return jsonResponse({ ok: true }, 200);
  } catch (err) {
    // Surfaces Postgres trigger messages too (e.g. "Cannot remove the
    // last admin in an organization") so the caller gets a real reason,
    // not a generic failure.
    return jsonResponse({ error: String(err?.message || err) }, 500);
  }
});
