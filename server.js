import { createServer } from "node:http";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";
import { WebSocketServer } from "ws";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const publicPath = fileURLToPath(new URL("./public/", import.meta.url));
logging.set_level(logging.NONE);
Object.assign(wisp.options, {
  allow_udp_streams: false,
  dns_servers: ["1.1.1.3", "1.0.0.3"],
});

// ---- chat (WebSocket broadcast) ----
const chat = new WebSocketServer({ noServer: true });
chat.on("connection", (ws) => {
  let last = 0;
  ws.on("message", (raw) => {
    if (Date.now() - last < 400) return; // basic rate limit
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

// ---- http + websocket upgrades (wisp for proxy, /chat for chat) ----
const fastify = Fastify({
  serverFactory: (handler) => {
    const s = createServer((req, res) => handler(req, res));
    s.on("upgrade", (req, socket, head) => {
      if (req.url.startsWith("/wisp/")) wisp.routeRequest(req, socket, head);
      else if (req.url.startsWith("/chat"))
        chat.handleUpgrade(req, socket, head, (ws) => chat.emit("connection", ws));
      else socket.destroy();
    });
    return s;
  },
});

fastify.register(fastifyStatic, { root: publicPath, decorateReply: true });
fastify.register(fastifyStatic, { root: scramjetPath, prefix: "/scram/", decorateReply: false });
fastify.register(fastifyStatic, { root: libcurlPath, prefix: "/libcurl/", decorateReply: false });
fastify.register(fastifyStatic, { root: baremuxPath, prefix: "/baremux/", decorateReply: false });

const port = Number(process.env.PORT) || 8080;
await fastify.listen({ port, host: "0.0.0.0" });
console.log("Running on port " + port);
