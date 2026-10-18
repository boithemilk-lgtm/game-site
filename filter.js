// Shared URL and chat filters. Keep server.py's small safety checks in sync.
export const DOMAINS = [
  "pornhub.com","xvideos.com","xnxx.com","xhamster.com","redtube.com","youporn.com","onlyfans.com","fansly.com",
  "chaturbate.com","stripchat.com","bet365.com","draftkings.com","fanduel.com","stake.com","roobet.com",
  "goregrish.com","bestgore.fun","theync.com","kiwifarms.st","4chan.org"
];
export const BLOCKED_TLDS = [".zip",".mov"];
export const WORDS = ["porn","hentai","xxx","gambling","casino","suicide instructions"];
const HOST_KEYWORDS = ["porn","xxx","sexcam","adulttube","gambling"];
const CHAT_TERMS = ["nigger","faggot","retard","kys","kill yourself","rape you","send nudes","child porn"];
const CHAT_SWEARS = ["fuck","shit","bitch","cunt","motherfucker"];
function normalizeHost(host){return String(host||"").toLowerCase().replace(/^www\./,"").replace(/\.$/,"");}
export function checkUrl(input, extraDomains=[], extraWords=[]){
  let u; try { u = new URL(input); } catch { return {ok:false,reason:"invalid URL"}; }
  if(!["http:","https:"].includes(u.protocol)) return {ok:false,reason:"only http and https links are allowed"};
  const host=normalizeHost(u.hostname);
  if(!host || host.includes("\\") || host.includes("%")) return {ok:false,reason:"invalid host"};
  const domains=[...DOMAINS,...extraDomains].map(normalizeHost);
  if(domains.some(d=>host===d||host.endsWith("."+d))) return {ok:false,reason:"site blocked by filter"};
  if(BLOCKED_TLDS.some(t=>host.endsWith(t))) return {ok:false,reason:"domain ending blocked by filter"};
  if(HOST_KEYWORDS.some(w=>host.includes(w))) return {ok:false,reason:"site blocked by filter"};
  const haystack=(host+u.pathname+u.search).toLowerCase();
  if([...WORDS,...extraWords].some(w=>String(w).trim() && haystack.includes(String(w).toLowerCase()))) return {ok:false,reason:"URL blocked by filter"};
  return {ok:true,url:u};
}
export function safeSearch(q){return "https://duckduckgo.com/html/?kp=1&q="+encodeURIComponent(String(q||""));}
export function checkChat(input, extraWords=[]){
  const text=String(input||"").trim();
  if(!text) return {ok:false,reason:"message is empty"};
  if(text.length>300) return {ok:false,reason:"message is too long"};
  const lower=text.toLowerCase();
  if(/https?:\/\/|www\./i.test(text)) return {ok:false,reason:"links are disabled in chat"};
  if([...CHAT_TERMS,...CHAT_SWEARS,...extraWords].some(w=>String(w).trim() && lower.includes(String(w).toLowerCase()))) return {ok:false,reason:"message blocked by chat filter"};
  return {ok:true,text};
}
