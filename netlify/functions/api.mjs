import { getStore } from "@netlify/blobs";
import { scryptSync, randomBytes, timingSafeEqual } from "node:crypto";

const J = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { "Content-Type": "application/json" } });
const DAY = 864e5;

const clean = (r) => {
  if (!r || !/^\d{4}-\d{2}-\d{2}$/.test(r.date)) return null;
  const n = x => (Number.isFinite(+x) ? Math.round(+x) : 0);
  return {
    id: String(r.id || "").slice(0, 40) || randomBytes(6).toString("hex"),
    date: r.date, rest: String(r.rest || "").slice(0, 80), person: String(r.person || "").slice(0, 30),
    food: n(r.food), disc: Math.min(100, Math.max(0, +r.disc || 0)),
    ch: ["both", "sst", "sc", "none"].includes(r.ch) ? r.ch : "both",
    after: n(r.after), sc: n(r.sc), sst: n(r.sst), rnd: n(r.rnd), pay: n(r.pay),
  };
};

export default async (req) => {
  if (req.method !== "POST") return J({ error: "POST only" }, 405);
  let b; try { b = await req.json(); } catch { return J({ error: "Bad request" }, 400); }
  const users = getStore({ name: "users", consistency: "strong" });
  const sessions = getStore({ name: "sessions", consistency: "strong" });
  const data = getStore({ name: "data", consistency: "strong" });
  const a = b.action;
  const u = await users.get("owner", { type: "json" });

  if (a === "status") return J({ exists: !!u });

  if (a === "register" || a === "login") {
    const pw = String(b.password || "");
    if (pw.length < 6 || pw.length > 100) return J({ error: "Password must be 6–100 characters" }, 400);
    if (a === "register") {
      if (u) return J({ error: "A password has already been set" }, 409);
      const salt = randomBytes(16);
      await users.setJSON("owner", { salt: salt.toString("hex"), hash: scryptSync(pw, salt, 32).toString("hex"), fails: 0, lock: 0 });
    } else {
      if (!u) return J({ error: "No password set yet" }, 400);
      if (u.lock > Date.now()) return J({ error: "Too many wrong attempts – try again in a few minutes" }, 429);
      const ok = timingSafeEqual(scryptSync(pw, Buffer.from(u.salt, "hex"), 32), Buffer.from(u.hash, "hex"));
      if (!ok) {
        u.fails = (u.fails || 0) + 1;
        if (u.fails >= 5) { u.lock = Date.now() + 5 * 60e3; u.fails = 0; }
        await users.setJSON("owner", u);
        return J({ error: "Wrong password" }, 401);
      }
      if (u.fails) { u.fails = 0; await users.setJSON("owner", u); }
    }
    const token = randomBytes(24).toString("hex");
    await sessions.setJSON(token, { exp: Date.now() + 30 * DAY });
    return J({ token });
  }

  const s = b.token ? await sessions.get(String(b.token), { type: "json" }) : null;
  if (!s || s.exp < Date.now()) return J({ error: "Please log in again" }, 401);
  const d = (await data.get("data", { type: "json" })) || { settings: null, rows: [] };

  if (a === "load") return J({ settings: d.settings, rows: d.rows });
  if (a === "add") {
    const add = (Array.isArray(b.rows) ? b.rows.slice(0, 500) : []).map(clean).filter(Boolean);
    d.rows = d.rows.concat(add).slice(-10000);
  } else if (a === "del") {
    d.rows = d.rows.filter(r => r.id !== String(b.id));
  } else if (a === "clear") {
    d.rows = [];
  } else if (a === "settings") {
    const p = x => Math.min(100, Math.max(0, +x || 0));
    const t = b.settings || {};
    const people = [...new Set((Array.isArray(t.people) ? t.people : []).map(x => String(x).trim().slice(0, 30)).filter(Boolean))].slice(0, 40);
    d.settings = { sc: p(t.sc), sst: p(t.sst), onsc: !!t.onsc, rnd: !!t.rnd, people };
  } else return J({ error: "Unknown action" }, 400);
  await data.setJSON("data", d);
  return J({ ok: true });
};
