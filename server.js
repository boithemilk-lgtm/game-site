import Fastify from 'fastify';
import fastifyStatic from '@fastify/static';
import { WebSocketServer, WebSocket } from 'ws';
import { createHmac, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { readFile, mkdir, appendFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import dns from 'node:dns/promises';
import net from 'node:net';
import https from 'node:https';
import { load } from 'cheerio';
import { checkUrl, checkChat, safeSearch } from './filter.js';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=Fastify({logger:true, bodyLimit:1024*1024, trustProxy:false});
const PORT=Number(process.env.PORT||8080);
const HOST=process.env.HOST||'0.0.0.0';
const SECRET=process.env.APP_SECRET;
if(!SECRET || SECRET.length<32) { console.error('APP_SECRET must be set to a random secret of at least 32 characters.'); process.exit(1); }
const ADMIN_NAME=(process.env.ADMIN_NAME||'jackwobbe').toLowerCase();
const ADMIN_CODE=process.env.ADMIN_CODE||randomBytes(12).toString('hex');
const REMOTE_WS=(process.env.REMOTE_WS||'').trim();
const DATA_DIR=path.join(__dirname,'data');
const DB_PATH=path.join(DATA_DIR,'db.json');
let db={users:[],blockedDomains:[],blockedWords:[],events:[],chat:[]};
const sockets=new Set();
const sessionCookie='nova_session';
const now=()=>Date.now();
const safeEqual=(a,b)=>{const x=Buffer.from(String(a));const y=Buffer.from(String(b));return x.length===y.length&&timingSafeEqual(x,y)};
const sign=(s)=>createHmac('sha256',SECRET).update(s).digest('base64url');
function tokenFor(user){const payload=Buffer.from(JSON.stringify({id:user.id,name:user.name,admin:!!user.admin,exp:now()+7*864e5})).toString('base64url');return payload+'.'+sign(payload)}
function verifyToken(token){try{const [p,s]=String(token||'').split('.');if(!p||!s||!safeEqual(sign(p),s))return null;const v=JSON.parse(Buffer.from(p,'base64url').toString());if(v.exp<now())return null;return v}catch{return null}}
function cookieToken(req){const raw=req.headers.cookie||'';const m=raw.split(';').map(x=>x.trim()).find(x=>x.startsWith(sessionCookie+'='));return m?decodeURIComponent(m.slice(sessionCookie.length+1)):''}
function currentUser(req){const t=cookieToken(req);const v=verifyToken(t);if(!v)return null;return db.users.find(u=>u.id===v.id&&!u.banned)||null}
function publicUser(u){return {id:u.id,name:u.name,admin:!!u.admin,created:u.created,token:tokenFor(u)}}
async function save(){await mkdir(DATA_DIR,{recursive:true});await import('node:fs/promises').then(fs=>fs.writeFile(DB_PATH,JSON.stringify(db,null,2),'utf8'))}
async function logEvent(kind,who,detail){db.events.unshift({ts:now(),kind,who:who||'system',detail:String(detail||'').slice(0,500)});db.events=db.events.slice(0,500);await save().catch(()=>{})}
function needAuth(req,reply){const u=currentUser(req);if(!u){reply.code(401).send({error:'Please sign in first.'});return null}return u}
function needAdmin(req,reply){const u=needAuth(req,reply);if(!u)return null;if(!u.admin){reply.code(403).send({error:'Admin access required.'});return null}return u}
function pushChat(m){db.chat.push(m);db.chat=db.chat.slice(-100);const data=JSON.stringify({type:'msg',...m});for(const ws of sockets)if(ws.readyState===WebSocket.OPEN)ws.send(data);save().catch(()=>{})}
function sendAll(obj){const s=JSON.stringify(obj);for(const ws of sockets)if(ws.readyState===WebSocket.OPEN)ws.send(s)}
await mkdir(DATA_DIR,{recursive:true});
try{db=JSON.parse(await readFile(DB_PATH,'utf8'))}catch{await save()}
if(!db.users.some(u=>u.name.toLowerCase()===ADMIN_NAME))console.log(`Admin setup code (keep private): ${ADMIN_CODE}`);
await app.register(fastifyStatic,{root:path.join(__dirname,'public'),prefix:'/'});
app.get('/config.js',async(_req,reply)=>reply.type('application/javascript').send(`window.NOVA_REMOTE_WS=${JSON.stringify(REMOTE_WS)};`));
app.get('/health',async()=>({ok:true,service:'nova-arcade'}));
app.get('/api/me',async(req,reply)=>{const u=currentUser(req);if(!u)return reply.code(401).send({error:'Not signed in'});return publicUser(u)});
app.post('/api/signup',async(req,reply)=>{
 const name=String(req.body?.username||'').trim();const pass=String(req.body?.password||'');const code=String(req.body?.code||'');
 if(!/^[a-zA-Z0-9_]{3,16}$/.test(name))return reply.code(400).send({error:'Username must be 3–16 letters, numbers, or underscores.'});
 if(pass.length<8||pass.length>200)return reply.code(400).send({error:'Password must be at least 8 characters.'});
 if(db.users.some(u=>u.name.toLowerCase()===name.toLowerCase()))return reply.code(409).send({error:'That username is already taken.'});
 const admin=name.toLowerCase()===ADMIN_NAME;
 if(admin&&!safeEqual(code,ADMIN_CODE))return reply.code(403).send({error:'Invalid admin setup code.'});
 const salt=randomBytes(16).toString('hex');const hash=scryptSync(pass,salt,64).toString('hex');const u={id:randomBytes(12).toString('hex'),name,salt,hash,admin,created:now(),banned:false,muted:false};db.users.push(u);await save();reply.header('Set-Cookie',`${sessionCookie}=${encodeURIComponent(tokenFor(u))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${req.protocol==='https' ? '; Secure':''}`);await logEvent('signup',name,'Account created');return publicUser(u);
});
app.post('/api/login',async(req,reply)=>{
 const name=String(req.body?.username||'').trim();const pass=String(req.body?.password||'');const u=db.users.find(x=>x.name.toLowerCase()===name.toLowerCase());
 if(!u||u.banned||!safeEqual(scryptSync(pass,u.salt,64).toString('hex'),u.hash))return reply.code(401).send({error:'Username or password is incorrect.'});
 reply.header('Set-Cookie',`${sessionCookie}=${encodeURIComponent(tokenFor(u))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800${req.protocol==='https' ? '; Secure':''}`);return publicUser(u);
});
app.post('/api/logout',async(req,reply)=>{reply.header('Set-Cookie',`${sessionCookie}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);return {ok:true}});
app.get('/api/admin/overview',async(req,reply)=>{if(!needAdmin(req,reply))return;const onlineIds=new Set([...sockets].filter(ws=>ws.readyState===WebSocket.OPEN).map(ws=>ws.userId));return {stats:{users:db.users.length,online:onlineIds.size,banned:db.users.filter(u=>u.banned).length,muted:db.users.filter(u=>u.muted).length,messages:db.chat.length},users:db.users.map(u=>({id:u.id,name:u.name,admin:!!u.admin,banned:!!u.banned,muted:!!u.muted,created:u.created,online:onlineIds.has(u.id)})),blockedDomains:db.blockedDomains,blockedWords:db.blockedWords,chat:db.chat.slice(-30).reverse(),events:db.events}});
app.post('/api/admin/user',async(req,reply)=>{const admin=needAdmin(req,reply);if(!admin)return;const name=String(req.body?.name||'');const action=String(req.body?.action||'');const u=db.users.find(x=>x.name===name);if(!u)return reply.code(404).send({error:'User not found'});if(u.admin)return reply.code(400).send({error:'Admin accounts cannot be changed here.'});if(!['ban','unban','mute','unmute','delete'].includes(action))return reply.code(400).send({error:'Unknown action'});if(action==='delete'){db.users=db.users.filter(x=>x.id!==u.id);for(const ws of sockets){if(ws.userId===u.id){try{ws.close(1008,'Account deleted')}catch{}}}db.chat=db.chat.filter(m=>m.u!==u.name);sendAll({type:'hist',msgs:db.chat});await save();await logEvent('user-delete',admin.name,`${name} account deleted`);return {ok:true}}if(action==='ban'){u.banned=true;for(const ws of sockets){if(ws.userId===u.id){try{ws.close(1008,'Banned')}catch{}}}}if(action==='unban')u.banned=false;if(action==='mute')u.muted=true;if(action==='unmute')u.muted=false;await save();await logEvent('user-'+action,admin.name,name);return {ok:true}});
app.post('/api/admin/list',async(req,reply)=>{const admin=needAdmin(req,reply);if(!admin)return;const type=req.body?.type==='domain'?'blockedDomains':req.body?.type==='word'?'blockedWords':null;const value=String(req.body?.value||'').trim().toLowerCase();if(!type||!value||value.length>120)return reply.code(400).send({error:'Invalid list item'});if(req.body.action==='add'){if(!db[type].includes(value))db[type].push(value)}else if(req.body.action==='remove')db[type]=db[type].filter(x=>x!==value);else return reply.code(400).send({error:'Unknown action'});await save();await logEvent(`list-${req.body.action}`,admin.name,`${type}: ${value}`);return {ok:true}});
app.post('/api/admin/chat',async(req,reply)=>{const admin=needAdmin(req,reply);if(!admin)return;const {action,id}=req.body||{};if(action==='clear'){const count=db.chat.length;db.chat=[];sendAll({type:'clear'});await save();await logEvent('chat-clear',admin.name,`Cleared ${count} chat messages`);return {ok:true}}if(action==='delete'){const msg=db.chat.find(m=>m.id===id);db.chat=db.chat.filter(m=>m.id!==id);sendAll({type:'del',id});await save();await logEvent('chat-delete',admin.name,msg?`${msg.u}: ${msg.t}`:'Message removed');return {ok:true}}return reply.code(400).send({error:'Unknown action'} )});

// Basic public HTTP proxy with strict URL checks and private-network blocking.
function isPrivateIp(ip){if(net.isIPv4(ip)){const [a,b]=ip.split('.').map(Number);return a===10||a===127||a===0||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||(a===192&&b===168)||(a===100&&b>=64&&b<=127)||a>=224}if(net.isIPv6(ip)){const s=ip.toLowerCase();return s==='::1'||s==='::'||s.startsWith('fc')||s.startsWith('fd')||s.startsWith('fe8')||s.startsWith('fe9')||s.startsWith('fea')||s.startsWith('feb')||s.startsWith('::ffff:127.')||s.startsWith('::ffff:10.')}return true}
async function safeTarget(raw){const result=checkUrl(raw,db.blockedDomains,db.blockedWords);if(!result.ok)throw new Error(result.reason);const u=result.url;if(u.username||u.password)throw new Error('URLs with embedded credentials are blocked.');const ips=await dns.lookup(u.hostname,{all:true,verbatim:true}).catch(()=>[]);if(!ips.length||ips.some(x=>isPrivateIp(x.address)))throw new Error('That host is not allowed.');return u}
app.get('/p',async(req,reply)=>{
 let target;try{target=await safeTarget(String(req.query?.url||''))}catch(e){return reply.code(400).type('text/plain').send('Blocked: '+e.message)}
 try{
  const response=await fetch(target,{redirect:'manual',signal:AbortSignal.timeout(12000),headers:{'user-agent':'Mozilla/5.0 NovaArcadeProxy/1.0','accept':'text/html,application/xhtml+xml'}});
  if(response.status>=300&&response.status<400){const loc=response.headers.get('location');if(!loc)return reply.code(502).send('Redirect blocked');const next=new URL(loc,target);await safeTarget(next.href);return reply.redirect('/p?url='+encodeURIComponent(next.href),302)}
  const type=response.headers.get('content-type')||'';if(!type.includes('text/html'))return reply.code(415).type('text/plain').send('This proxy only displays HTML pages.');
  let html=await response.text();if(html.length>2_000_000)return reply.code(413).send('Page is too large.');
  const $=load(html);$('base').remove();$('script').each((_,el)=>{const src=$(el).attr('src');if(src){try{$(el).attr('src','/p?url='+encodeURIComponent(new URL(src,target).href))}catch{}}});$('link[href],img[src],iframe[src],source[src]').each((_,el)=>{const attr=$(el).is('link')?'href':'src';try{const raw=$(el).attr(attr);if(raw&&!raw.startsWith('data:'))$(el).attr(attr,'/p?url='+encodeURIComponent(new URL(raw,target).href))}catch{}});$('a[href],form[action]').each((_,el)=>{const attr=$(el).is('form')?'action':'href';try{const raw=$(el).attr(attr);if(raw&&!raw.startsWith('#')&&!raw.startsWith('javascript:'))$(el).attr(attr,'/p?url='+encodeURIComponent(new URL(raw,target).href))}catch{}});
  reply.header('content-security-policy',"default-src 'self' data: blob: https: http: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'");return reply.type('text/html; charset=utf-8').send($.html());
 }catch(e){return reply.code(502).type('text/plain').send('Could not load that page: '+e.message)}
});

const wss=new WebSocketServer({noServer:true});
app.server.on('upgrade',(req,socket,head)=>{
 const pathname=new URL(req.url,'http://localhost').pathname;
 if(pathname!=='/chat'){socket.destroy();return}
 const u=verifyToken(new URL(req.url,'http://localhost').searchParams.get('token'))||currentUser({headers:req.headers});
 if(!u){socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');socket.destroy();return}
 wss.handleUpgrade(req,socket,head,ws=>wss.emit('connection',ws,u));
});
wss.on('connection',(ws,u)=>{const user=db.users.find(x=>x.id===u.id);if(!user||user.banned){ws.close(1008,'Banned');return}sockets.add(ws);ws.userId=u.id;ws.send(JSON.stringify({type:'hist',msgs:db.chat}));ws.on('message',async raw=>{try{const parsed=JSON.parse(raw.toString());const fresh=db.users.find(x=>x.id===u.id);if(!fresh||fresh.banned)return ws.close(1008,'Banned');if(fresh.muted){ws.send(JSON.stringify({type:'sys',t:'You are muted.'}));return}const check=checkChat(parsed.t,db.blockedWords);if(!check.ok){ws.send(JSON.stringify({type:'sys',t:check.reason}));return}pushChat({id:randomBytes(8).toString('hex'),u:fresh.name,t:check.text,admin:!!fresh.admin,ts:now()})}catch{}});ws.on('close',()=>sockets.delete(ws))});
// Optional remote browser websocket is hosted by server.py on its own port/tunnel.
app.addHook('onClose',async()=>{for(const ws of sockets)ws.close()});
await app.listen({port:PORT,host:HOST});
console.log(`Nova Arcade listening on http://${HOST}:${PORT}`);
if(REMOTE_WS)console.log('Remote Chrome endpoint configured.');else console.log('Remote Chrome is disabled until REMOTE_WS is configured.');
