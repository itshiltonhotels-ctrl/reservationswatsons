// Supabase Edge Function: admin-users
// Lets a signed-in HEAD OFFICE user create and manage outlet logins.
// Deploy with "Verify JWT" turned OFF (this function checks the caller itself).
import { createClient } from "npm:@supabase/supabase-js@2";

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, s = 200) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
    const token = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    const { data: who, error: ue } = await admin.auth.getUser(token);
    if (ue || !who?.user) return json({ error: "Please sign in again." }, 401);
    const { data: me } = await admin.from("staff").select("role").eq("user_id", who.user.id).maybeSingle();
    if (!me || me.role !== "head_office") return json({ error: "Head office access only." }, 403);

    const b = await req.json();
    const log = (action: string, detail: string, outlet: string | null) =>
      admin.from("activity_log").insert({
        user_id: who.user.id, user_email: who.user.email, outlet_id: outlet, action, detail,
      });

    if (b.action === "list") {
      const { data: all } = await admin.auth.admin.listUsers({ perPage: 1000 });
      const { data: st } = await admin.from("staff").select("user_id,outlet_id,role");
      const m = new Map((st || []).map((s: any) => [s.user_id, s]));
      const users = (all?.users || []).filter((x: any) => m.has(x.id)).map((x: any) => ({
        id: x.id, email: x.email, outlet_id: m.get(x.id).outlet_id, role: m.get(x.id).role,
        last_sign_in: x.last_sign_in_at,
        disabled: !!x.banned_until && new Date(x.banned_until) > new Date(),
      }));
      return json({ users });
    }

    if (b.action === "create") {
      const role = b.role === "head_office" ? "head_office" : "outlet_admin";
      if (!b.email || !b.password || String(b.password).length < 8) return json({ error: "Email and a password of at least 8 characters are required." }, 400);
      if (role === "outlet_admin" && !b.outlet_id) return json({ error: "Choose an outlet." }, 400);
      const { data, error } = await admin.auth.admin.createUser({ email: b.email, password: b.password, email_confirm: true });
      if (error) return json({ error: error.message }, 400);
      const outlet = role === "head_office" ? null : b.outlet_id;
      const { error: se } = await admin.from("staff").insert({ user_id: data.user.id, outlet_id: outlet, role });
      if (se) return json({ error: se.message }, 400);
      await log("User created", `${b.email} (${role}${outlet ? ", " + outlet : ""})`, outlet);
      return json({ ok: true });
    }

    if (b.action === "setpw") {
      if (!b.user_id || String(b.password || "").length < 8) return json({ error: "Password must be at least 8 characters." }, 400);
      const { error } = await admin.auth.admin.updateUserById(b.user_id, { password: b.password });
      if (error) return json({ error: error.message }, 400);
      await log("Password reset", `User ${b.user_id}`, null);
      return json({ ok: true });
    }

    if (b.action === "disable") {
      if (b.user_id === who.user.id) return json({ error: "You cannot disable your own account." }, 400);
      const { error } = await admin.auth.admin.updateUserById(b.user_id, { ban_duration: b.disabled ? "876000h" : "none" });
      if (error) return json({ error: error.message }, 400);
      await log(b.disabled ? "User disabled" : "User enabled", `User ${b.user_id}`, null);
      return json({ ok: true });
    }

    return json({ error: "Unknown action." }, 400);
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
