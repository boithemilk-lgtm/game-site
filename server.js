import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import crypto from "node:crypto";
import dns from "node:dns/promises";
import net from "node:net";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { WebSocketServer } from "ws";
import * as cheerio from "cheerio";
import { checkUrl, checkChat, safeSearch } from "./filter.js";

/* ================= CONFIG ================= */
// This text MUST be identical to APP_SECRET in server.py. Change it to anything you like (in both files).
const SECRET = process.env.APP_SECRET || "novaarcade-k29xqpz7-change-me";
const ADMIN_NAME = "jackwobbe";
const RESERVED = ["admin", "administrator", "moderator", "mod", "system", "owner", "staff"];
/* ========================================== */

const publicPath = fileURLToPath(new URL("./public/", import.meta.url));

/* ================= STORAGE ================= */
const DATA_DIR = process.env.DATA_DIR || fileURLToPath(new URL("./data/", import.meta.url));
try { mkdirSync(DATA_DIR, { recursive: true }); } catch {}
const DB_FILE = DATA_DIR + "/db.json";
let db = { users: {}, blockedDomains: [], blockedWords: [], suggestions: [] };
try { db = { ...db, ...JSON.parse(readFileSync(DB_FILE, "utf8")) }; } catch {}
const save = () => { try { writeFileSync(DB_FILE, JSON.stringify(db)); } catch (e) { console.error("Could not save data:", e.message); } };

const events = [];
const addLog = (kind, who, detail) => {
  events.unshift({ ts: Date.now(), kind, who, detail: String(detail).slice(0, 200) });
  if (events.length > 200) events.length = 200;
};

/* ================= AUTH ================= */
const ADMIN_CODE = process.env.ADMIN_CODE || crypto.randomBytes(4).toString("hex");
const getUser = (n) => db.users[String(n).toLowerCase()];
if (!getUser(ADMIN_NAME)) console.log(`Admin setup code for "${ADMIN_NAME}": ${ADMIN_CODE}  (only needed once, when you create that account)`);

const sign = (p) => crypto.createHmac("sha256", SECRET).update(p).digest("hex");
const makeToken = (name) => {
  const p = Buffer.from(JSON.stringify({ u: name, exp: Date.now() + 7 * 864e5 })).toString("base64url");
  return p + "." + sign(p);
};
function readToken(t) {
  if (!t || !t.includes(".")) return null;
  const [p, s] = t.split(".");
  const good = sign(p);
  if (!s || s.length !== good.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(good))) return null;
  try { const o = JSON.parse(Buffer.from(p, "base64url").toString()); return o.exp > Date.now() ? o.u : null; } catch { return null; }
}
const parseCookies = (h) =>
  Object.fromEntries((h || "").split(";").map((s) => s.trim().split(/=(.*)/s).slice(0, 2)).filter((x) => x[0]));
const authReq = (req) => {
  const name = readToken(parseCookies(req.headers.cookie).sid);
  const u = name && getUser(name);
  return u && !u.banned ? u : null;
};
const isAdmin = (u) => !!u && u.name.toLowerCase() === ADMIN_NAME;
const setSession = (reply, req, token) =>
  reply.header("set-cookie", `sid=${token}; HttpOnly; Path=/; SameSite=Lax; Max-Age=604800${req.protocol === "https" ? "; Secure" : ""}`);
const keyOk = (req) => {
  const k = String(req.headers["x-key"] || "");
  return k.length === SECRET.length && crypto.timingSafeEqual(Buffer.from(k), Buffer.from(SECRET));
};

const hashPw = (pw, salt = crypto.randomBytes(16).toString("hex")) =>
  salt + ":" + crypto.scryptSync(pw, salt, 64).toString("hex");
const checkPw = (pw, stored) => {
  const [salt, h] = stored.split(":");
  const t = hashPw(pw, salt).split(":")[1];
  return h.length === t.length && crypto.timingSafeEqual(Buffer.from(h), Buffer.from(t));
};

/* ================= RATE LIMITS ================= */
const mkLimiter = (max) => {
  const hits = new Map();
  setInterval(() => hits.clear(), 60_000);
  return (ip) => { const n = (hits.get(ip) || 0) + 1; hits.set(ip, n); return n > max; };
};
const proxyLimited = mkLimiter(1500);
const authLimited = mkLimiter(15);

/* ================= CHAT ================= */
const chat = new WebSocketServer({ noServer: true });
let history = [], nextId = 1;
const sys = (t) => JSON.stringify({ type: "sys", t });
const broadcast = (o) => { const s = JSON.stringify(o); for (const c of chat.clients) if (c.readyState === 1) c.send(s); };
const kick = (name) => { for (const c of chat.clients) if (c.uname.toLowerCase() === name.toLowerCase()) c.close(4000); };

chat.on("connection", (ws) => {
  ws.send(JSON.stringify({ type: "hist", msgs: history }));
  let last = 0;
  ws.on("message", (raw) => {
    const u = getUser(ws.uname);
    if (!u || u.banned) return ws.close();
    if (u.muted) return ws.send(sys("You are muted by an admin."));
    if (Date.now() - last < 800) return;
    last = Date.now();
    let t;
    try { t = String(JSON.parse(raw.toString()).t).trim().slice(0, 300); } catch { return; }
    if (!t) return;
    if (checkChat(t, db.blockedWords, db.blockedDomains)) {
      addLog("chat-block", u.name, t);
      return ws.send(sys("Message blocked by the chat filter."));
    }
    const m = { id: nextId++, u: u.name, t, ts: Date.now(), admin: isAdmin(u) };
    history.push(m);
    if (history.length > 60) history.shift();
    broadcast({ type: "msg", ...m });
  });
});

/* ================= PROXY HELPERS ================= */
const isPrivate = (ip) =>
  /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|::ffff:|fc|fd|fe80)/i.test(ip);
async function isSafeHost(host) {
  try {
    const ips = net.isIP(host) ? [host] : (await dns.lookup(host, { all: true })).map((a) => a.address);
    return ips.length > 0 && ips.every((ip) => !isPrivate(ip));
  } catch { return false; }
}
const proxify = (u, base) => { try { return "/p?url=" + encodeURIComponent(new URL(u, base).href); } catch { return u; } };
const skip = /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i;
const shim = (base) => `<script>(()=>{const B=${JSON.stringify(base)};
const P=u=>{try{u=String(u);if(u.startsWith("/p?url=")||/^(data:|blob:)/.test(u))return u;
return "/p?url="+encodeURIComponent(new URL(u,B).href)}catch{return u}};
const f=window.fetch;window.fetch=(i,o)=>f(typeof i==="string"?P(i):(i instanceof URL?P(i.href):i),o);
const x=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(m,u,...a){return x.call(this,m,P(u),...a)};
const wo=window.open;window.open=(u,...a)=>wo.call(window,u?P(u):u,...a);
})()</script>`;
function rewriteCss(css, base) {
  return css
    .replace(/url\(\s*(['"]?)(?!data:)([^)'"]+)\1\s*\)/g, (_, q, u) => `url(${q}${proxify(u.trim(), base)}${q})`)
    .replace(/@import\s+(['"])([^'"]+)\1/g, (_, q, u) => `@import ${q}${proxify(u, base)}${q}`);
}
const blockedPage = (r) => `<!doctype html><meta charset=utf-8><title>Blocked</title><body style="font-family:system-ui;background:#0a0b14;color:#e8ebf7;display:grid;place-items:center;height:100vh;margin:0"><div style="text-align:center"><div style="font-size:56px">🚫</div><h2>This page is blocked</h2><p style="color:#9aa2c8">${r}</p></div>`;

/* ================= SERVER ================= */
const fastify = Fastify({
  trustProxy: true,
  serverFactory: (handler) => {
    const s = createServer((req, res) => handler(req, res));
    s.on("upgrade", (req, socket, head) => {
      if (!req.url.startsWith("/chat")) return socket.destroy();
      const name = readToken(parseCookies(req.headers.cookie).sid);
      const u = name && getUser(name);
      if (!u || u.banned) { socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n"); return socket.destroy(); }
      chat.handleUpgrade(req, socket, head, (ws) => { ws.uname = u.name; chat.emit("connection", ws); });
    });
    return s;
  },
});
fastify.register(fastifyStatic, { root: publicPath });

/* ---------- accounts ---------- */
fastify.post("/api/signup", async (req, reply) => {
  if (authLimited(req.ip)) return reply.code(429).send({ error: "Too many attempts. Wait a minute." });
  const { username, password, code } = req.body || {};
  const name = String(username || "").trim(), pw = String(password || "");
  if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) return reply.code(400).send({ error: "Username: 3-16 letters, numbers or _" });
  if (pw.length < 6 || pw.length > 100) return reply.code(400).send({ error: "Password must be at least 6 characters" });
  const lower = name.toLowerCase();
  if (getUser(lower)) return reply.code(400).send({ error: "That username is taken" });
  if (lower === ADMIN_NAME) {
    if (String(code || "") !== ADMIN_CODE) return reply.code(403).send({ error: "Invalid admin setup code" });
  } else if (RESERVED.includes(lower) || checkChat(name, db.blockedWords, [])) {
    return reply.code(400).send({ error: "That username isn't allowed" });
  }
  db.users[lower] = { name, hash: hashPw(pw), created: Date.now(), muted: false, banned: false };
  save();
  const token = makeToken(name);
  setSession(reply, req, token);
  return { name, admin: lower === ADMIN_NAME, token };
});

fastify.post("/api/login", async (req, reply) => {
  if (authLimited(req.ip)) return reply.code(429).send({ error: "Too many attempts. Wait a minute." });
  const { username, password } = req.body || {};
  const u = getUser(String(username || "").trim());
  if (!u || !checkPw(String(password || ""), u.hash)) return reply.code(401).send({ error: "Wrong username or password" });
  if (u.banned) return reply.code(403).send({ error: "This account is banned" });
  const token = makeToken(u.name);
  setSession(reply, req, token);
  return { name: u.name, admin: isAdmin(u), token };
});

fastify.post("/api/logout", async (req, reply) => {
  reply.header("set-cookie", "sid=; HttpOnly; Path=/; Max-Age=0");
  return { ok: true };
});

fastify.get("/api/me", async (req, reply) => {
  const u = authReq(req);
  if (!u) return reply.code(401).send({ error: "Not signed in" });
  return { name: u.name, admin: isAdmin(u), token: makeToken(u.name) };
});

/* ---------- suggestions ---------- */
const lastSuggest = new Map();

fastify.post("/api/suggest", async (req, reply) => {
  const u = authReq(req);
  if (!u) return reply.code(401).send({ error: "Please sign in" });
  const title = String((req.body || {}).title || "").trim().slice(0, 80);
  const text = String((req.body || {}).text || "").trim().slice(0, 500);
  if (title.length < 3) return reply.code(400).send({ error: "Give your suggestion a title (at least 3 characters)" });
  if (checkChat(title + " " + text, db.blockedWords, db.blockedDomains)) {
    addLog("suggest-block", u.name, title);
    return reply.code(400).send({ error: "Your suggestion was blocked by the filter" });
  }
  const key = u.name.toLowerCase();
  if (Date.now() - (lastSuggest.get(key) || 0) < 30_000) return reply.code(429).send({ error: "Please wait 30 seconds between suggestions" });
  if (db.suggestions.filter((s) => s.by.toLowerCase() === key && s.status === "pending").length >= 5)
    return reply.code(400).send({ error: "You already have 5 suggestions waiting for review" });
  const id = db.suggestions.reduce((m, s) => Math.max(m, s.id), 0) + 1;
  db.suggestions.push({ id, by: u.name, title, text, ts: Date.now(), status: "pending", note: "" });
  lastSuggest.set(key, Date.now());
  save();
  return { ok: true };
});

fastify.get("/api/suggestions", async (req, reply) => {
  const u = authReq(req);
  if (!u) return reply.code(401).send({ error: "Please sign in" });
  const adminView = isAdmin(u);
  const items = (adminView ? db.suggestions : db.suggestions.filter((s) => s.by.toLowerCase() === u.name.toLowerCase()))
    .slice().reverse();
  return { items, admin: adminView, pending: adminView ? db.suggestions.filter((s) => s.status === "pending").length : 0 };
});

/* ---------- admin ---------- */
const admin = (req, reply) => {
  const u = authReq(req);
  if (!u || !isAdmin(u)) { reply.code(403).send({ error: "Admins only" }); return null; }
  return u;
};

fastify.post("/api/admin/suggestion", async (req, reply) => {
  if (!admin(req, reply)) return;
  const { id, action, note } = req.body || {};
  const i = db.suggestions.findIndex((s) => s.id === Number(id));
  if (i < 0) return reply.code(404).send({ error: "No such suggestion" });
  const s = db.suggestions[i];
  if (action === "approve") { s.status = "approved"; s.note = String(note || "").slice(0, 200); }
  else if (action === "reject") { s.status = "rejected"; s.note = String(note || "").slice(0, 200); }
  else if (action === "reopen") { s.status = "pending"; s.note = ""; }
  else if (action === "delete") db.suggestions.splice(i, 1);
  else return reply.code(400).send({ error: "Unknown action" });
  save();
  return { ok: true };
});

fastify.get("/api/admin/overview", async (req, reply) => {
  if (!admin(req, reply)) return;
  const online = new Set([...chat.clients].map((c) => c.uname.toLowerCase()));
  return {
    users: Object.values(db.users).map((u) => ({
      name: u.name, created: u.created, muted: !!u.muted, banned: !!u.banned,
      online: online.has(u.name.toLowerCase()), admin: isAdmin(u),
    })),
    blockedDomains: db.blockedDomains, blockedWords: db.blockedWords, events,
  };
});

fastify.post("/api/admin/user", async (req, reply) => {
  if (!admin(req, reply)) return;
  const { name, action } = req.body || {};
  const u = getUser(name);
  if (!u) return reply.code(404).send({ error: "No such user" });
  if (isAdmin(u)) return reply.code(400).send({ error: "You can't do that to the admin account" });
  if (action === "mute") u.muted = true;
  else if (action === "unmute") u.muted = false;
  else if (action === "ban") { u.banned = true; kick(u.name); }
  else if (action === "unban") u.banned = false;
  else if (action === "delete") { delete db.users[u.name.toLowerCase()]; kick(u.name); }
  else return reply.code(400).send({ error: "Unknown action" });
  save();
  return { ok: true };
});

fastify.post("/api/admin/list", async (req, reply) => {
  if (!admin(req, reply)) return;
  const { type, action, value } = req.body || {};
  let v = String(value || "").trim().toLowerCase();
  const key = type === "domain" ? "blockedDomains" : type === "word" ? "blockedWords" : null;
  if (!key || !v) return reply.code(400).send({ error: "Bad request" });
  if (type === "domain") v = v.replace(/^https?:\/\//, "").replace(/^www\./, "").split("/")[0];
  if (action === "add") { if (!db[key].includes(v)) db[key].push(v); }
  else if (action === "remove") db[key] = db[key].filter((x) => x !== v);
  else return reply.code(400).send({ error: "Bad request" });
  save();
  return { ok: true };
});

fastify.post("/api/admin/chat", async (req, reply) => {
  if (!admin(req, reply)) return;
  const { action, id } = req.body || {};
  if (action === "clear") { history = []; broadcast({ type: "clear" }); }
  else if (action === "delete") { history = history.filter((m) => m.id !== Number(id)); broadcast({ type: "del", id: Number(id) }); }
  else return reply.code(400).send({ error: "Bad request" });
  return { ok: true };
});

/* ---------- used by server.py (Chrome game) ---------- */
fastify.get("/api/sync", async (req, reply) => {
  if (!keyOk(req)) return reply.code(403).send({ error: "no" });
  return {
    domains: db.blockedDomains, words: db.blockedWords,
    banned: Object.values(db.users).filter((u) => u.banned).map((u) => u.name.toLowerCase()),
  };
});
fastify.post("/api/log", async (req, reply) => {
  if (!keyOk(req)) return reply.code(403).send({ error: "no" });
  const { user, url, reason } = req.body || {};
  addLog("chrome-block", user || "?", `${url} (${reason})`);
  return { ok: true };
});

/* ---------- proxy ---------- */
fastify.get("/p", async (req, reply) => {
  const me = authReq(req);
  if (!me) return reply.code(401).type("text/html").send(blockedPage("Please sign in first."));
  if (proxyLimited(req.ip)) return reply.code(429).send("Too many requests. Wait a minute and try again.");

  let target;
  try {
    if (req.query.__u) {
      target = new URL(req.query.__u);
      for (const [k, v] of Object.entries(req.query)) if (k !== "__u") target.searchParams.set(k, v);
    } else target = new URL(req.query.url);
  } catch { return reply.code(400).send("Bad URL"); }
  if (!/^https?:$/.test(target.protocol)) return reply.code(400).send("Bad protocol");

  const bad = checkUrl(target.href, db.blockedDomains, db.blockedWords);
  if (bad) {
    if (["document", "iframe", "frame"].includes(req.headers["sec-fetch-dest"])) addLog("proxy-block", me.name, target.href);
    return reply.code(403).type("text/html").send(blockedPage(bad));
  }
  if (!(await isSafeHost(target.hostname))) return reply.code(403).send("Blocked host");
  safeSearch(target);

  let r;
  try {
    r = await fetch(target, {
      redirect: "manual",
      signal: AbortSignal.timeout(15000),
      headers: {
        "user-agent": req.headers["user-agent"] || "Mozilla/5.0",
        accept: req.headers.accept || "*/*",
        "accept-language": req.headers["accept-language"] || "en-US,en;q=0.9",
      },
    });
  } catch { return reply.code(502).send("Could not reach that site."); }

  const loc = r.headers.get("location");
  if (r.status >= 300 && r.status < 400 && loc) return reply.redirect(proxify(loc, target.href));

  const type = r.headers.get("content-type") || "application/octet-stream";
  reply.code(r.status).header("content-type", type);

  if (type.includes("text/html")) {
    const $ = cheerio.load(await r.text());
    const base = target.href;
    const rewriteAttr = (sel, attr) => $(sel).each((_, el) => {
      const v = $(el).attr(attr);
      if (v && !skip.test(v)) $(el).attr(attr, proxify(v, base));
    });
    [["a","href"],["area","href"],["link","href"],["script","src"],["img","src"],["iframe","src"],
     ["source","src"],["video","src"],["video","poster"],["audio","src"],["embed","src"]].forEach(([s, a]) => rewriteAttr(s, a));
    $("[srcset]").each((_, el) => {
      const out = $(el).attr("srcset").split(",").map((part) => {
        const [u, ...rest] = part.trim().split(/\s+/);
        return [skip.test(u) ? u : proxify(u, base), ...rest].join(" ");
      });
      $(el).attr("srcset", out.join(", "));
    });
    $("style").each((_, el) => $(el).text(rewriteCss($(el).text(), base)));
    $("[style]").each((_, el) => $(el).attr("style", rewriteCss($(el).attr("style"), base)));
    $("form").each((_, el) => {
      const form = $(el);
      const action = new URL(form.attr("action") || "", base).href;
      form.attr("action", "/p").attr("method", "get");
      form.prepend(`<input type="hidden" name="__u" value="${action.replace(/"/g, "&quot;")}">`);
    });
    $("[integrity], [nonce]").removeAttr("integrity").removeAttr("nonce");
    $("meta[http-equiv]").remove();
    $("base").remove();
    $("head").prepend(shim(base));
    return reply.send($.html());
  }
  if (type.includes("text/css")) return reply.send(rewriteCss(await r.text(), target.href));
  return reply.send(Buffer.from(await r.arrayBuffer()));
});

const port = Number(process.env.PORT) || 8080;
await fastify.listen({ port, host: "0.0.0.0" });
console.log("Running on port " + port);
