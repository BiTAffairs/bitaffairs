// Supabase Edge Function: redeem-code
//
// Replaces the direct RPC call to redeem_client_code() (0008) as the only
// way to redeem a client access code — see 0028_code_rate_limit.sql for
// why: a plain SQL RPC has no visibility into the caller's IP, so it had
// no way to rate-limit repeated guesses. This function does, and locks
// out an IP after too many failed attempts in a short window.
//
// The browser is still expected to call supabase.auth.signInAnonymously()
// itself before calling this (unchanged from before) — this function
// needs the caller to already be authenticated so it knows which user_id
// to attach the redeemed event to.
//
// Deploy with: supabase functions deploy redeem-code

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

const MAX_ATTEMPTS = 5;
const WINDOW_MINUTES = 10;

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
    const code: string = (body?.code || "").trim().toUpperCase();
    if (!code) return jsonResponse({ error: "Invalid or expired code" }, 400);

    // Best-effort IP extraction — x-forwarded-for can carry a comma-
    // separated chain (client, proxy, proxy...); the first entry is the
    // original caller. Falls back to a shared "unknown" bucket if
    // somehow absent, which just means those callers share one rate
    // limit rather than each getting their own — still better than none.
    const forwardedFor = req.headers.get("x-forwarded-for") || "";
    const ip = forwardedFor.split(",")[0].trim() || "unknown";

    const adminClient = createClient(supabaseUrl, serviceRoleKey);

    const windowStart = new Date(Date.now() - WINDOW_MINUTES * 60 * 1000).toISOString();
    const { count: recentFailures } = await adminClient
      .from("code_redeem_attempts")
      .select("id", { count: "exact", head: true })
      .eq("ip_address", ip)
      .gte("attempted_at", windowStart);

    if ((recentFailures || 0) >= MAX_ATTEMPTS) {
      return jsonResponse({ error: "Too many attempts — try again in a few minutes." }, 429);
    }

    const { data: match } = await adminClient
      .from("client_access")
      .select("event_id, code_expires_at")
      .eq("invite_code", code)
      .maybeSingle();

    const valid = match && (!match.code_expires_at || new Date(match.code_expires_at) > new Date());

    if (!valid) {
      // Record the failure before responding — this is what makes the
      // lockout above actually accumulate.
      await adminClient.from("code_redeem_attempts").insert({ ip_address: ip });
      return jsonResponse({ error: "Invalid or expired code" }, 400);
    }

    const { error: insertError } = await adminClient
      .from("client_code_sessions")
      .insert({ event_id: match.event_id, user_id: user.id });
    if (insertError) throw insertError;

    return jsonResponse({ eventId: match.event_id }, 200);
  } catch (err) {
    return jsonResponse({ error: String(err?.message || err) }, 500);
  }
});
