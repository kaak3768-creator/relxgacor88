const express=require("express"),path=require("path"),crypto=require("crypto"),{randomInt}=crypto;
const app=express();app.use(express.json());const PUB=path.join(__dirname,"..","public");app.use(express.static(PUB));app.get("/",(q,r)=>r.sendFile(path.join(PUB,"index.html")));
const MIN=5000000,MAX=1000000000,PAY_TO="DimsGuyy1",SERVER="relx";
const RURL=process.env.UPSTASH_REDIS_REST_URL||process.env.KV_REST_API_URL,RTOK=process.env.UPSTASH_REDIS_REST_TOKEN||process.env.KV_REST_API_TOKEN;
const ADMIN_KEY=process.env.ADMIN_KEY,SECRET=process.env.AUTH_SECRET||(RURL?null:"dev-secret");

/* ---- Penyimpanan: Upstash Redis (Vercel) atau memori (lokal) ---- */
const M=new Map();
function mem(c,...a){const k=a[0];switch(c){
 case"GET":return M.has(k)?M.get(k):null;
 case"SET":if(a.includes("NX")&&M.has(k))return null;M.set(k,String(a[1]));return"OK";
 case"DEL":return M.delete(k)?1:0;
 case"SADD":{const s=M.get(k)||new Set();s.add(a[1]);M.set(k,s);return 1}
 case"SMEMBERS":return[...(M.get(k)||[])];
 case"MGET":return a.map(x=>M.has(x)?M.get(x):null);
 case"INCRBY":{const v=(+M.get(k)||0)+ +a[1];M.set(k,String(v));return v}
 case"LPUSH":{const l=M.get(k)||[];l.unshift(a[1]);M.set(k,l);return l.length}
 case"LRANGE":return(M.get(k)||[]).slice(+a[1],+a[2]+1);
 case"LTRIM":M.set(k,(M.get(k)||[]).slice(+a[1],+a[2]+1));return"OK";
 case"EVAL":{const key=a[2],amt=+a[3],v=+M.get(key)||0;if(v>=amt){M.set(key,String(v-amt));return v-amt}return -1}}}
async function rc(...a){if(!RURL)return mem(...a);
 const r=await fetch(RURL,{method:"POST",headers:{Authorization:"Bearer "+RTOK},body:JSON.stringify(a.map(String))}),d=await r.json();
 if(d.error)throw Error(d.error);return d.result}
const LUA="local v=tonumber(redis.call('get',KEYS[1]) or '0') if v>=tonumber(ARGV[1]) then return redis.call('decrby',KEYS[1],ARGV[1]) else return -1 end";
const take=async(lc,b)=>(await rc("EVAL",LUA,1,"bal:"+lc,b))>=0;
const bal=async lc=>parseInt(await rc("GET","bal:"+lc))||0;
const add=(lc,n)=>rc("INCRBY","bal:"+lc,n);
const log=async(name,type,amount)=>{await rc("LPUSH","history",JSON.stringify({type,username:name,amount,at:new Date().toISOString()}));if(!randomInt(20))await rc("LTRIM","history",0,499)};
const J=s=>{try{return JSON.parse(s)}catch(e){return null}};

/* ---- Auth ---- */
const hmac=p=>crypto.createHmac("sha256",SECRET).update(p).digest("base64url");
const sign=lc=>{if(!SECRET)throw Error("AUTH_SECRET belum diset di environment");const p=Buffer.from(JSON.stringify({u:lc,e:Date.now()+30*864e5})).toString("base64url");return p+"."+hmac(p)};
function who(q){if(!SECRET)return;const[p,s]=(q.get("authorization")||"").slice(7).split(".");if(!p||!s)return;const h=hmac(p);
 if(h.length!==s.length||!crypto.timingSafeEqual(Buffer.from(h),Buffer.from(s)))return;const d=J(Buffer.from(p,"base64url").toString());return d&&d.e>Date.now()?d.u:void 0}
const hashPw=(pw,salt)=>crypto.scryptSync(pw,salt,32).toString("hex");
const mkPw=pw=>{const salt=crypto.randomBytes(16).toString("hex");return{salt,hash:hashPw(pw,salt)}};
const okPw=(pw,u)=>{const h=hashPw(pw,u.salt);return crypto.timingSafeEqual(Buffer.from(h),Buffer.from(u.hash))};
const bad=(r,m,c=400)=>r.status(c).json({error:m});
const H=fn=>async(q,r)=>{try{await fn(q,r)}catch(e){bad(r,"Server error: "+e.message,500)}};
const auth=async(q,r,n)=>{try{const lc=who(q),u=lc&&J(await rc("GET","user:"+lc));if(!u)return bad(r,"Silakan masuk",401);q.lc=lc;q.name=u.username;n()}catch(e){bad(r,e.message,500)}};
const admin=(q,r,n)=>ADMIN_KEY&&q.get("x-admin-key")===ADMIN_KEY?n():bad(r,ADMIN_KEY?"Admin key salah":"ADMIN_KEY belum diset di environment",401);
const UREG=/^[A-Za-z0-9_]{3,16}$/;

app.get("/api/config",(q,r)=>r.json({min:MIN,payTo:PAY_TO,server:SERVER}));
app.post("/api/register",H(async(q,r)=>{const n=String(q.body.username||"").trim(),pw=String(q.body.password||"");
 if(!UREG.test(n))return bad(r,"Username 3-16 karakter (huruf, angka, _)");if(pw.length<6||pw.length>64)return bad(r,"Password 6-64 karakter");
 const lc=n.toLowerCase();if(!(await rc("SET","user:"+lc,JSON.stringify({username:n,...mkPw(pw),created:Date.now()}),"NX")))return bad(r,"Username sudah dipakai");
 await rc("SADD","users",lc);r.json({token:sign(lc),username:n,balance:0})}));
app.post("/api/login",H(async(q,r)=>{const lc=String(q.body.username||"").trim().toLowerCase(),u=J(await rc("GET","user:"+lc));
 if(!u||!okPw(String(q.body.password||""),u))return bad(r,"Username atau password salah",401);r.json({token:sign(lc),username:u.username,balance:await bal(lc)})}));
app.get("/api/me",auth,H(async(q,r)=>{await rc("SET","seen:"+q.lc,Date.now());r.json({username:q.name,balance:await bal(q.lc)})}));
app.post("/api/deposit",auth,H(async(q,r)=>{const a=q.body.amount;if(!Number.isInteger(a)||a<MIN||a>MAX)return bad(r,"Minimal deposit 5.000.000");
 const d={id:Date.now().toString(36)+randomInt(1e4),username:q.name,amount:a,status:"PENDING",createdAt:new Date().toISOString()};
 await rc("SET","dep:"+d.id,JSON.stringify(d));await rc("SADD","deps",d.id);await rc("SADD","mydeps:"+q.lc,d.id);r.json(d)}));
const deps=async ids=>(ids.length?(await rc("MGET",...ids.map(i=>"dep:"+i))).map(J).filter(Boolean):[]).sort((a,b)=>b.createdAt<a.createdAt?-1:1).slice(0,100);
app.get("/api/mydeposits",auth,H(async(q,r)=>r.json(await deps(await rc("SMEMBERS","mydeps:"+q.lc)))));

/* ---- Admin ---- */
app.get("/api/admin/users",admin,H(async(q,r)=>{const l=await rc("SMEMBERS","users");if(!l.length)return r.json([]);
 const[p,b,s]=await Promise.all([rc("MGET",...l.map(x=>"user:"+x)),rc("MGET",...l.map(x=>"bal:"+x)),rc("MGET",...l.map(x=>"seen:"+x))]);
 r.json(l.map((x,i)=>{const u=J(p[i])||{};return{username:u.username||x,balance:parseInt(b[i])||0,created:u.created,seen:+s[i]||0,online:Date.now()-(+s[i]||0)<20000}}).sort((a,b)=>b.seen-a.seen))}));
app.get("/api/admin/deposits",admin,H(async(q,r)=>r.json(await deps(await rc("SMEMBERS","deps")))));
app.get("/api/admin/history",admin,H(async(q,r)=>r.json((await rc("LRANGE","history",0,99)).map(J))));
app.post("/api/admin/deposit/:id",admin,H(async(q,r)=>{const id=q.params.id,d=J(await rc("GET","dep:"+id));if(!d)return bad(r,"Deposit tidak ditemukan");
 if(!(await rc("SET","depok:"+id,1,"NX")))return bad(r,"Sudah diproses");
 d.status="APPROVED";await rc("SET","dep:"+id,JSON.stringify(d));const b=await add(d.username.toLowerCase(),d.amount);await log(d.username,"DEPOSIT",d.amount);r.json({d,balance:b})}));
app.post("/api/admin/balance",admin,H(async(q,r)=>{const lc=String(q.body.username||"").toLowerCase(),a=q.body.amount;
 if(!J(await rc("GET","user:"+lc))||!Number.isInteger(a)||!a)return bad(r,"Data tidak valid");
 if(a<0&&!(await take(lc,-a)))return bad(r,"Saldo tidak cukup");if(a>0)await add(lc,a);await log(lc,a>0?"ADD":"REMOVE",a);r.json({balance:await bal(lc)})}));
app.post("/api/admin/password",admin,H(async(q,r)=>{const lc=String(q.body.username||"").toLowerCase(),u=J(await rc("GET","user:"+lc)),pw=String(q.body.password||"");
 if(!u||pw.length<6)return bad(r,"User tidak ada / password min 6 karakter");await rc("SET","user:"+lc,JSON.stringify({...u,...mkPw(pw)}));r.json({ok:true})}));

/* ---- Game instan ---- */
const REDS=[1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36],PL=[13,3,1.3,.6,.4,.6,1.3,3,13];
const CASES=[[.2,414],[.5,290],[1,170],[2,80],[5,36],[10,8],[50,2]],WHEEL=[0,1.2,0,1.5,0,1.2,0,2,0,1.5,0,4];
const rnd=()=>randomInt(1e9)/1e9;
const comb=(n,k)=>{let r=1;for(let i=1;i<=k;i++)r=r*(n-k+i)/i;return r};
const shuffle=n=>{const a=[...Array(n).keys()];for(let i=n-1;i>0;i--){const j=randomInt(i+1);[a[i],a[j]]=[a[j],a[i]]}return a};
const I={
 coinflip:p=>{if(!["heads","tails"].includes(p.choice))return;const r=randomInt(2)?"heads":"tails";return{d:{r},m:r===p.choice?1.95:0}},
 roulette:p=>{if(!["red","black","green"].includes(p.choice))return;const n=randomInt(37),c=n?REDS.includes(n)?"red":"black":"green";return{d:{n,c},m:c===p.choice?(c==="green"?35:2):0}},
 dice:p=>{const t=+p.target,o=!!p.over;if(!(t>=2&&t<=98))return;const ch=o?100-t:t,roll=randomInt(1e4)/100;return{d:{roll},m:(o?roll>t:roll<t)?Math.floor(9700/ch)/100:0}},
 limbo:p=>{const t=+p.target;if(!(t>=1.01&&t<=1000))return;const x=Math.max(1,Math.floor(97/(1-rnd()))/100);return{d:{x},m:x>=t?t:0}},
 keno:p=>{const pk=p.picks;if(!Array.isArray(pk)||pk.length<1||pk.length>10||new Set(pk).size!==pk.length||pk.some(n=>!Number.isInteger(n)||n<1||n>40))return;
  const dr=shuffle(40).slice(0,10).map(x=>x+1),h=pk.filter(n=>dr.includes(n)).length,L=pk.length,t=Math.ceil(L/2);
  let m=0;if(h>=t){const pr=comb(10,h)*comb(30,L-h)/comb(40,L);m=Math.min(1000,Math.floor(95/(L-t+1)/pr)/100)}return{d:{dr,h},m}},
 plinko:()=>{const path=[...Array(8)].map(()=>randomInt(2)),bin=path.reduce((a,b)=>a+b,0);return{d:{path,bin},m:PL[bin]}},
 cases:()=>{let x=randomInt(1000);for(const[m,w]of CASES){if(x<w)return{d:{},m};x-=w}},
 wheel:()=>{const i=randomInt(12);return{d:{i},m:WHEEL[i]}}};
const BETERR="Taruhan minimal 5.000.000 dan saldo harus cukup";
const betOk=async(lc,b)=>Number.isInteger(b)&&b>=MIN&&b<=MAX&&await take(lc,b);
app.post("/api/play",auth,H(async(q,r)=>{const{game,bet:b,params:p={}}=q.body,x=I[game]&&I[game](p);if(!x)return bad(r,"Pilihan tidak valid");
 if(!(await betOk(q.lc,b)))return bad(r,BETERR);const pay=Math.floor(b*x.m),nb=await add(q.lc,pay);await log(q.name,"GAME_"+game.toUpperCase(),pay-b);
 r.json({payout:pay,mult:x.m,d:x.d,balance:nb})}));

/* ---- Game bertahap ---- */
const L={flip:{p:.5,max:10},chicken:{p:.8,max:12},pump:{p:.9,max:30}};
const card=()=>({r:["A","2","3","4","5","6","7","8","9","10","J","Q","K"][randomInt(13)],s:"♠♥♦♣"[randomInt(4)]});
const tot=h=>{let t=0,a=0;h.forEach(c=>{if(c.r==="A"){a++;t+=11}else t+=["J","Q","K"].includes(c.r)?10:+c.r});while(t>21&&a){t-=10;a--}return t};
const mm=(m,k)=>{let x=.97;for(let i=0;i<k;i++)x*=(25-i)/(25-m-i);return Math.floor(x*100)/100};
const lm=s=>Math.floor(s.g**s.n*100)/100,SK=lc=>"ses:"+lc,save=(lc,s)=>rc("SET",SK(lc),JSON.stringify(s),"EX",86400);
async function view(lc,s){const v={game:s.game,bet:s.bet,balance:await bal(lc)};
 if(s.game==="bj")return{...v,player:s.p,dealer:[s.d[0]],pt:tot(s.p)};
 if(s.game==="mines")return{...v,picked:s.picked,m:s.m,mult:mm(s.m,s.picked.length)};
 if(s.game==="crash")return{...v,elapsed:Date.now()-s.t0};
 return{...v,n:s.n,mult:lm(s),max:s.max}}
async function end(q,s,pay,x={}){if(!(await rc("DEL",SK(q.lc))))return null;const nb=await add(q.lc,pay);await log(q.name,"GAME_"+s.game.toUpperCase(),pay-s.bet);return{done:true,game:s.game,bet:s.bet,payout:pay,balance:nb,...x}}
function bjEnd(q,s,o){if(o==="stand")while(tot(s.d)<17)s.d.push(card());const pt=tot(s.p),dt=tot(s.d);
 if(o==="stand")o=dt>21||pt>dt?"win":pt===dt?"push":"lose";
 return end(q,s,Math.floor(s.bet*{blackjack:2.5,win:2,push:1,lose:0,bust:0}[o]),{outcome:o,player:s.p,dealer:s.d,pt,dt})}
app.get("/api/resume",auth,H(async(q,r)=>{const s=J(await rc("GET",SK(q.lc)));r.json(s&&s.game?await view(q.lc,s):{none:true})}));
app.post("/api/start",auth,H(async(q,r)=>{const{game,bet:b,params:p={}}=q.body,lc=q.lc;
 if(!["bj","mines","crash",...Object.keys(L)].includes(game))return bad(r,"Game tidak dikenal");
 if(!(await rc("SET",SK(lc),"1","NX","EX",86400))){const o=J(await rc("GET",SK(lc)));return bad(r,"Masih ada ronde berjalan"+(o&&o.game?": "+o.game:""))}
 if(!(await betOk(lc,b))){await rc("DEL",SK(lc));return bad(r,BETERR)}
 const s={game,bet:b};
 if(game==="bj"){s.p=[card(),card()];s.d=[card(),card()]}
 else if(game==="mines"){s.m=[1,3,5,10].includes(+p.mines)?+p.mines:3;s.mines=shuffle(25).slice(0,s.m);s.picked=[]}
 else if(game==="crash"){s.t0=Date.now();s.cp=Math.min(1000,Math.max(1,Math.floor(97/(1-rnd()))/100))}
 else{Object.assign(s,L[game]);s.g=.97/s.p;s.n=0}
 await save(lc,s);if(game==="bj"&&tot(s.p)===21)return r.json(await bjEnd(q,s,"blackjack"));r.json(await view(lc,s))}));
app.post("/api/act",auth,H(async(q,r)=>{const lc=q.lc,s=J(await rc("GET",SK(lc))),a=q.body.action;if(!s||!s.game)return bad(r,"Tidak ada ronde aktif");
 const E=async(p,x)=>{const o=await end(q,s,p,x);o?r.json(o):bad(r,"Ronde sudah selesai")},V=async()=>{await save(lc,s);r.json(await view(lc,s))};
 if(s.game==="bj"){
  if(a==="hit"){s.p.push(card());if(tot(s.p)>21)return r.json(await bjEnd(q,s,"bust")||{error:"Ronde sudah selesai"});return V()}
  if(a==="stand")return r.json(await bjEnd(q,s,"stand")||{error:"Ronde sudah selesai"})}
 else if(s.game==="mines"){
  if(a==="pick"){const i=+q.body.idx;if(!(i>=0&&i<25)||s.picked.includes(i))return bad(r,"Kotak tidak valid");
   if(s.mines.includes(i))return E(0,{lost:true,mines:s.mines,hit:i,picked:s.picked});
   s.picked.push(i);if(s.picked.length===25-s.m)return E(Math.floor(s.bet*mm(s.m,s.picked.length)),{mines:s.mines,picked:s.picked,mult:mm(s.m,s.picked.length)});return V()}
  if(a==="cash"&&s.picked.length)return E(Math.floor(s.bet*mm(s.m,s.picked.length)),{mines:s.mines,picked:s.picked,mult:mm(s.m,s.picked.length)})}
 else if(s.game==="crash"){const cur=Math.exp(.00008*(Date.now()-s.t0));
  if(cur>=s.cp)return E(0,{crashed:true,point:s.cp});
  if(a==="cash"){const m=Math.floor(cur*100)/100;return E(Math.floor(s.bet*m),{mult:m,point:s.cp})}
  return r.json({game:"crash",elapsed:Date.now()-s.t0,balance:await bal(lc)})}
 else{
  if(a==="step"){if(rnd()<s.p){s.n++;if(s.n>=s.max)return E(Math.floor(s.bet*lm(s)),{n:s.n,mult:lm(s)});return V()}return E(0,{lost:true,n:s.n})}
  if(a==="cash"&&s.n)return E(Math.floor(s.bet*lm(s)),{n:s.n,mult:lm(s)})}
 bad(r,"Aksi tidak valid")}));
if(require.main===module)app.listen(process.env.PORT||3000,()=>console.log("RELXGAMBLE running"));
module.exports=app;module.exports.app=app;module.exports.I=I;
