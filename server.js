import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import dns from "node:dns/promises";
import net from "node:net";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { WebSocketServer } from "ws";
import * as cheerio from "cheerio";

const publicPath = fileURLToPath(new URL("./public/", import.meta.url));

/* ================= CHAT ================= */
const chat = new WebSocketServer({ noServer: true });
chat.on("connection", (ws) => {
  let last = 0;
  ws.on("message", (raw) => {
    if (Date.now() - last < 400) return; // rate limit
    last = Date.now();
    try {
      const m = JSON.parse(raw.toString());
      const msg = JSON.stringify({
        u: String(m.u).slice(0, 20),
        t: String(m.t).slice(0, 300),
      });
      for (const c of chat.clients) if (c.readyState === 1) c.send(msg);
    } catch {}
  });
});

/* ================= PROXY HELPERS ================= */
// Block private/internal addresses so nobody can use the proxy to probe your network
const isPrivate = (ip) =>
  /^(10\.|127\.|0\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|::ffff:|fc|fd|fe80)/i.test(ip);
async function isSafeHost(host) {
  try {
    const ips = net.isIP(host)
      ? [host]
      : (await dns.lookup(host, { all: true })).map((a) => a.address);
    return ips.length > 0 && ips.every((ip) => !isPrivate(ip));
  } catch {
    return false;
  }
}

// Simple per-IP rate limit: 120 requests per minute
const hits = new Map();
setInterval(() => hits.clear(), 60_000);
const limited = (ip) => {
  const n = (hits.get(ip) || 0) + 1;
  hits.set(ip, n);
  return n > 120;
};

const proxify = (u, base) => {
  try {
    return "/p?url=" + encodeURIComponent(new URL(u, base).href);
  } catch {
    return u;
  }
};
const skip = /^(#|data:|javascript:|mailto:|tel:|blob:|about:)/i;

// Client-side shim: sends fetch()/XHR calls made by the page's own scripts through the proxy
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

/* ================= SERVER ================= */
const fastify = Fastify({
  serverFactory: (handler) => {
    const s = createServer((req, res) => handler(req, res));
    s.on("upgrade", (req, socket, head) => {
      if (req.url.startsWith("/chat"))
        chat.handleUpgrade(req, socket, head, (ws) => chat.emit("connection", ws));
      else socket.destroy();
    });
    return s;
  },
});

fastify.register(fastifyStatic, { root: publicPath });

fastify.get("/p", async (req, reply) => {
  if (limited(req.ip)) return reply.code(429).send("Too many requests");

  // GET forms arrive as /p?__u=<action>&field=value...
  let target;
  try {
    if (req.query.__u) {
      target = new URL(req.query.__u);
      for (const [k, v] of Object.entries(req.query)) if (k !== "__u") target.searchParams.set(k, v);
    } else {
      target = new URL(req.query.url);
    }
  } catch {
    return reply.code(400).send("Bad URL");
  }
  if (!/^https?:$/.test(target.protocol)) return reply.code(400).send("Bad protocol");
  if (!(await isSafeHost(target.hostname))) return reply.code(403).send("Blocked host");

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
  } catch {
    return reply.code(502).send("Could not reach that site.");
  }

  // Redirects go back through the proxy (so they get re-checked too)
  const loc = r.headers.get("location");
  if (r.status >= 300 && r.status < 400 && loc) return reply.redirect(proxify(loc, target.href));

  const type = r.headers.get("content-type") || "application/octet-stream";
  reply.code(r.status).header("content-type", type);
  // Deliberately NOT forwarded: CSP, X-Frame-Options, content-encoding, content-length, cookies

  if (type.includes("text/html")) {
    const $ = cheerio.load(await r.text());
    const base = target.href;
    const rewriteAttr = (sel, attr) =>
      $(sel).each((_, el) => {
        const v = $(el).attr(attr);
        if (v && !skip.test(v)) $(el).attr(attr, proxify(v, base));
      });
    [["a","href"],["area","href"],["link","href"],["script","src"],["img","src"],
     ["iframe","src"],["source","src"],["video","src"],["video","poster"],
     ["audio","src"],["embed","src"]].forEach(([s, a]) => rewriteAttr(s, a));

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
      form.attr("action", "/p");
      form.attr("method", "get"); // only GET forms (searches) are supported
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
