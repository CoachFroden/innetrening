const crypto=require("node:crypto");
const admin=require("firebase-admin");
const COOKIE="innetrening_session";
function init(){if(!admin.apps.length){const raw=process.env.FIREBASE_SERVICE_ACCOUNT_JSON;if(!raw)throw Error("FIREBASE_SERVICE_ACCOUNT_JSON mangler");admin.initializeApp({credential:admin.credential.cert(JSON.parse(raw))})}return admin.firestore()}
function sign(data){return crypto.createHmac("sha256",process.env.PROGRESJON_SESSION_SECRET).update(data).digest("hex")}
function cookie(req){const raw=req.headers.cookie||"";return raw.split(";").map(s=>s.trim()).find(s=>s.startsWith(COOKIE+"="))?.slice(COOKIE.length+1)||""}
function valid(req){const v=cookie(req);const [exp,mac]=v.split(".");if(!exp||!mac||!/^\d+$/.test(exp)||Number(exp)<Date.now())return false;const expected=sign(exp);return mac.length===expected.length&&crypto.timingSafeEqual(Buffer.from(mac),Buffer.from(expected))}
function setCookie(res,value,maxAge){res.setHeader("Set-Cookie",COOKIE+"="+value+"; Path=/api/progresjon; HttpOnly; Secure; SameSite=Strict; Max-Age="+maxAge)}
function send(res,status,body){res.status(status).json(body)}
function sanitize(x){return String(x||"").trim().slice(0,100)}
function rateLimit(ip){const key=crypto.createHash("sha256").update(ip).digest("hex");const now=Date.now();const r=attempts.get(key)||{count:0,until:0};if(now>r.until){r.count=0;r.until=now+15*60*1000}r.count++;attempts.set(key,r);return r.count<=12}
const attempts=new Map();
module.exports=async(req,res)=>{res.setHeader("Cache-Control","no-store");try{
if(!process.env.PROGRESJON_SESSION_SECRET||process.env.PROGRESJON_SESSION_SECRET.length<32)return send(res,503,{error:"Serveroppsett mangler"});
const db=init(),body=req.body||{},action=req.method==="GET"?"status":body.action;
if(action==="login"&&req.method==="POST"){
if(!rateLimit(req.headers["x-forwarded-for"]||req.socket.remoteAddress||"unknown"))return send(res,429,{error:"For mange forsøk. Vent 15 minutter."});
const snap=await db.doc("innetrening_settings/access").get();const password=snap.data()?.password;
if(typeof password!=="string"||password.length<8)return send(res,503,{error:"Passord mangler i Firestore (minst 8 tegn)"});
const supplied=String(body.password||"");const a=crypto.createHash("sha256").update(password).digest(),b=crypto.createHash("sha256").update(supplied).digest();
if(!crypto.timingSafeEqual(a,b))return send(res,401,{error:"Feil passord"});
const exp=String(Date.now()+8*60*60*1000);setCookie(res,exp+"."+sign(exp),8*60*60);return send(res,200,{ok:true});
}
if(action==="logout"&&req.method==="POST"){setCookie(res,"",0);return send(res,200,{ok:true})}
if(!valid(req))return send(res,401,{error:"Logg inn for å fortsette"});
if(action==="status")return send(res,200,{ok:true});
if(action==="players"&&req.method==="POST"){const snap=await db.collection("innetrening_players").get();return send(res,200,{players:snap.docs.map(d=>({id:d.id,...d.data(),createdAt:undefined})).sort((a,b)=>a.name.localeCompare(b.name,"no"))})}
if(action==="addPlayer"&&req.method==="POST"){const name=sanitize(body.name);if(name.length<2)return send(res,400,{error:"Ugyldig navn"});const ref=await db.collection("innetrening_players").add({name,createdAt:admin.firestore.FieldValue.serverTimestamp()});return send(res,200,{id:ref.id})}
const playerId=String(body.playerId||"");if(!/^[a-zA-Z0-9]{10,60}$/.test(playerId))return send(res,400,{error:"Ugyldig spiller"});
const playerRef=db.collection("innetrening_players").doc(playerId);
if(action==="results"&&req.method==="POST"){const snap=await playerRef.collection("results").get();return send(res,200,{results:snap.docs.map(d=>({id:d.id,...d.data(),createdAt:undefined})).sort((a,b)=>a.date.localeCompare(b.date))})}
if(action==="addResult"&&req.method==="POST"){const date=String(body.date||"");if(!/^\d{4}-\d{2}-\d{2}$/.test(date))return send(res,400,{error:"Ugyldig dato"});const data={date,createdAt:admin.firestore.FieldValue.serverTimestamp()};for(const [key,min,max] of [["sprint10",.5,30],["sprint20",1,60],["jump",1,500],["pushups",0,200]]){if(body[key]===undefined||body[key]===null||body[key]==="")continue;const n=Number(body[key]);if(!Number.isFinite(n)||n<min||n>max||(key==="pushups"&&!Number.isInteger(n)))return send(res,400,{error:"Ugyldig verdi for "+key});data[key]=n}if(Object.keys(data).length<3)return send(res,400,{error:"Fyll ut minst én test"});await playerRef.collection("results").add(data);return send(res,200,{ok:true})}
if(action==="deleteResult"&&req.method==="POST"){const id=String(body.resultId||"");if(!/^[a-zA-Z0-9]{10,60}$/.test(id))return send(res,400,{error:"Ugyldig resultat"});await playerRef.collection("results").doc(id).delete();return send(res,200,{ok:true})}
return send(res,400,{error:"Ukjent handling"});
}catch(e){console.error("progresjon API",e);return send(res,500,{error:"Serverfeil. Kontroller Vercel-oppsettet."})}};
