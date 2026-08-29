// Supabase Edge Function: invite-client
//
// Why this can't live in supabaseClient.js: creating a client_access row and
// sending an invite requires the service-role key (to look up/create the
// client's auth user and to insert on their behalf, bypassing their own
// RLS). The service-role key must NEVER be shipped to the browser — it
// bypasses every RLS policy in the database. This function is the one
// place that key is allowed to exist, running server-side on Supabase's
// infrastructure, never in the client bundle.
//
// Deploy with: supabase functions deploy invite-client
// Call with the caller's planner session (their JWT), NOT the service key —
// this function itself uses the service key internally, once, safely.

import { serve } from "https://deno.land/std@0.203.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// SUPABASE_URL, SUPABASE_ANON_KEY, and SUPABASE_SERVICE_ROLE_KEY are reserved
// names Supabase injects into every Edge Function automatically — do not
// `supabase secrets set` these yourself (it will fail/be ignored). The only
// secret this function needs set by hand is APP_URL.
const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;

// Required for browser calls: the frontend runs on a different origin
// (your Vercel/Netlify domain) than this function (*.supabase.co), so the
// browser sends a CORS preflight OPTIONS request before the real one, and
// expects these headers on every response — including error responses.
// Without this, supabase-js's functions.invoke() fails with a generic
// "Failed to send a request to the Edge Function" and never even reaches
// the actual error handling below.
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

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader) {
      return new Response(JSON.stringify({ error: "Missing Authorization header" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Verify the caller is a real, currently-authenticated planner — using
    // their own JWT against the anon-scoped client, not the service key.
    const callerClient = createClient(supabaseUrl, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: userError } = await callerClient.auth.getUser();
    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Not authenticated" }), {
        status: 401,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const { eventId, clientEmail } = await req.json();
    if (!eventId || !clientEmail) {
      return new Response(JSON.stringify({ error: "eventId and clientEmail are required" }), {
        status: 400,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Service-role client — only ever used inside this server-side function.
    const adminClient = createClient(supabaseUrl, serviceRoleKey);

    // Confirm the caller is actually a planner in this event's organization
    // before doing anything privileged — don't trust the request body alone.
    const { data: planner } = await adminClient.from("planners").select("organization_id").eq("id", user.id).single();
    const { data: event } = await adminClient.from("events").select("organization_id").eq("id", eventId).single();
    if (!planner || !event || planner.organization_id !== event.organization_id) {
      return new Response(JSON.stringify({ error: "Not authorized for this event" }), {
        status: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    // Rate limit — see 0029_invite_rate_limit.sql. Shared across
    // invite-planner and invite-client: what matters is this caller's
    // total invite volume, not which endpoint they used.
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const { count: recentInvites } = await adminClient
      .from("invite_attempts")
      .select("id", { count: "exact", head: true })
      .eq("caller_id", user.id)
      .gte("attempted_at", oneHourAgo);
    if ((recentInvites || 0) >= 20) {
      return new Response(JSON.stringify({ error: "Too many invites sent recently — try again in a bit." }), {
        status: 429,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
    await adminClient.from("invite_attempts").insert({ caller_id: user.id });

    // Record the invite. The client's actual auth.users row gets created the
    // moment they click the magic link Supabase Auth emails them — we don't
    // need to (and shouldn't) pre-create it here.
    const { error: insertError } = await adminClient
      .from("client_access")
      .upsert(
        { event_id: eventId, invited_email: clientEmail.toLowerCase().trim() },
        { onConflict: "event_id,invited_email" }
      );
    if (insertError) throw insertError;

    // Trigger the actual invite email via Supabase Auth's admin API.
    const { error: inviteError } = await adminClient.auth.admin.inviteUserByEmail(clientEmail, {
      redirectTo: Deno.env.get("APP_URL") ?? undefined,
    });
    if (inviteError) throw inviteError;

    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: String(err) }), {
      status: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  }
});
