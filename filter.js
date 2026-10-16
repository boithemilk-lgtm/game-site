// Shared content filter for the proxy and chat. Keep the lists in server.py in sync with these.

export const DOMAINS = [
  // adult
  "pornhub.com","xvideos.com","xnxx.com","xhamster.com","redtube.com","youporn.com","onlyfans.com","fansly.com",
  "chaturbate.com","stripchat.com","livejasmin.com","bongacams.com","cam4.com","myfreecams.com","brazzers.com",
  "spankbang.com","eporner.com","tube8.com","thumbzilla.com","motherless.com","e-hentai.org","nhentai.net",
  // gambling
  "bet365.com","draftkings.com","fanduel.com","stake.com","pokerstars.com","bovada.lv","betway.com","williamhill.com",
  // gore / shock / extremist boards
  "bestgore.com","liveleak.com","kaotic.com","theync.com","4chan.org",
  // proxies / VPNs (so nobody can chain out of your filter)
  "croxyproxy.com","hidemyass.com","nordvpn.com","expressvpn.com","protonvpn.com","surfshark.com","windscribe.com",
  "tunnelbear.com","cyberghostvpn.com","proxysite.com","hide.me","kproxy.com","vpnbook.com","hidester.com",
  "4everproxy.com","torproject.org",
];
const BAD_TLDS = new Set(["xxx", "porn", "adult", "sex"]);
const HOST_KEYWORDS = ["porn","xvideo","xnxx","xhamster","redtube","youporn","onlyfans","hentai","nsfw","camgirl",
  "erotic","fetish","casino","gambl","vpn","proxy","unblock"];
const TERMS = new Set(["porn","porno","pornhub","xxx","hentai","nude","nudes","onlyfans","nsfw","rule34","xvideos",
  "xnxx","xhamster","camgirl","camgirls","blowjob","handjob","creampie","gangbang","milf","boobs","pussy",
  "bestgore","beheading"]);
const PHRASES = ["sex video","sex videos","sex tape","naked girls","naked women","gore video","gore videos","nude pics"];

const matchExtra = (text, tokens, words) =>
  words.some((w) => (w.includes(" ") ? text.includes(w) : tokens.includes(w)));

// Returns a reason string if the URL is blocked, otherwise null
export function checkUrl(urlStr, extraDomains = [], extraWords = []) {
  let u;
  try { u = new URL(urlStr); } catch { return "Invalid address"; }
  if (!/^https?:$/.test(u.protocol)) return "Blocked protocol";
  const host = u.hostname.toLowerCase().replace(/\.$/, "");
  for (const d of [...DOMAINS, ...extraDomains]) if (host === d || host.endsWith("." + d)) return "Blocked site";
  if (BAD_TLDS.has(host.split(".").pop())) return "Adult site";
  const compact = host.replace(/[.\-]/g, "");
  if (HOST_KEYWORDS.some((k) => compact.includes(k))) return "Blocked site";
  let raw = u.pathname + " " + u.search;
  try { raw = decodeURIComponent(raw); } catch {}
  const text = raw.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  const tokens = text.split(" ");
  if (tokens.some((t) => TERMS.has(t))) return "Blocked search or page";
  if (PHRASES.some((p) => text.includes(p))) return "Blocked search or page";
  if (matchExtra(text, tokens, extraWords)) return "Blocked search or page";
  return null;
}

// Forces strict SafeSearch on the big search engines
export function safeSearch(u) {
  const h = u.hostname;
  if (!u.searchParams.has("q")) return u;
  if (/(^|\.)duckduckgo\.com$/.test(h) && ["/", "/html", "/html/", "/lite", "/lite/"].includes(u.pathname)) u.searchParams.set("kp", "1");
  else if (/(^|\.)google\.[a-z.]+$/.test(h) && u.pathname === "/search") u.searchParams.set("safe", "active");
  else if (/(^|\.)bing\.com$/.test(h)) u.searchParams.set("adlt", "strict");
  return u;
}

/* ---------- chat filter ---------- */
const LEET = { "0":"o","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a","$":"s","!":"i","+":"t" };
const rep = (w) => w.split("").map((c) => c + "+").join(""); // allows stretched letters: fuuuck
const PREFIX = new RegExp("^(" + ["fuck","shit","bitch","cunt","nigg","fagg","whore","slut","asshole","dickhead"].map(rep).join("|") + ")");
const EXACT = new RegExp("^(" + ["ass","asshat","dumbass","dick","cock","pussy","penis","vagina","retard","retarded","fag",
  "kike","spic","chink","tranny","coon","gook","wetback","porn","porno","nude","nudes","boobs","cum","cumshot",
  "blowjob","handjob","kys"].map(rep).join("|") + ")s*$");
const ALLOW = new Set(["niggle","niggled","niggling","shiitake","shitake"]);
const CHAT_PHRASES = ["kill yourself","kill your self","go die","send nudes"];

function candidates(text) {
  const out = new Set(), toks = [];
  for (const chunk of text.toLowerCase().split(/\s+/)) {
    if (!chunk) continue;
    // only de-leet chunks that contain letters, so numbers like "455" stay harmless
    const m = /[a-z]/.test(chunk) ? chunk.replace(/[013457@$!+]/g, (c) => LEET[c]) : chunk;
    const stripped = m.replace(/[^a-z]/g, "");
    if (stripped) out.add(stripped);
    for (const p of m.split(/[^a-z]+/)) if (p) { out.add(p); toks.push(p); }
  }
  let run = ""; // catches "f u c k"
  for (const t of [...toks, ""]) {
    if (t.length === 1) run += t;
    else { if (run.length >= 3) out.add(run); run = ""; }
  }
  return [...out];
}

// Returns a reason string if the message should be blocked, otherwise null
export function checkChat(text, extraWords = [], extraDomains = []) {
  for (const c of candidates(text)) {
    if (ALLOW.has(c)) continue;
    if (PREFIX.test(c) || EXACT.test(c)) return "language";
  }
  const clean = text.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim();
  const tokens = clean.split(" ");
  if (CHAT_PHRASES.some((p) => clean.includes(p))) return "language";
  if (matchExtra(clean, tokens, extraWords)) return "language";
  const links = text.match(/(?:https?:\/\/|www\.)[^\s]+|\b[a-z0-9-]+\.(?:com|net|org|io|xyz|me|tv|gg|co)\b[^\s]*/gi) || [];
  for (const l of links) {
    if (checkUrl(/^https?:/i.test(l) ? l : "https://" + l, extraDomains, extraWords)) return "link";
  }
  return null;
}
