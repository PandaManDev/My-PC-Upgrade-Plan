const crypto = require('node:crypto');
const SITE_ORIGIN = process.env.CHAT_ALLOWED_ORIGIN || 'https://pandamandev.github.io';
const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, '');
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';
const ADMIN_SECRET = process.env.CHAT_ADMIN_SECRET || '';

function cors(req,res) {
  const origin=req.headers.origin;
  if(origin===SITE_ORIGIN || origin==='http://localhost:3000') res.setHeader('Access-Control-Allow-Origin',origin);
  res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Methods','GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Cache-Control','no-store');
}
async function redis(command,...args){
  if(!REDIS_URL||!REDIS_TOKEN)throw new Error('Chat storage is not configured.');
  const parts=[command,...args].map(v=>encodeURIComponent(String(v)));
  const response=await fetch(REDIS_URL+'/'+parts.join('/'),{headers:{Authorization:'Bearer '+REDIS_TOKEN}});
  const data=await response.json();if(!response.ok||data.error)throw new Error(data.error||'Storage request failed.');return data.result;
}
function validId(v){return typeof v==='string'&&/^[a-f0-9-]{36}$/i.test(v)}
function safeEqual(a,b){const x=Buffer.from(String(a||'')),y=Buffer.from(String(b||''));return x.length===y.length&&crypto.timingSafeEqual(x,y)}
module.exports=async function handler(req,res){
  cors(req,res);if(req.method==='OPTIONS')return res.status(204).end();
  if(!['GET','POST'].includes(req.method))return res.status(405).json({error:'Method not allowed.'});
  if(req.headers.origin&&req.headers.origin!==SITE_ORIGIN&&req.headers.origin!=='http://localhost:3000')return res.status(403).json({error:'Origin not allowed.'});
  if(!ADMIN_SECRET)return res.status(503).json({error:'Admin inbox is not configured yet.'});
  if(!safeEqual((req.headers.authorization||'').replace(/^Bearer\s+/i,''),ADMIN_SECRET))return res.status(401).json({error:'Invalid admin password.'});
  try{
    if(req.method==='POST'){
      const conversationId=String(req.body&&req.body.conversationId||'');
      const text=typeof(req.body&&req.body.text)==='string'?req.body.text.trim().slice(0,1500):'';
      if(!validId(conversationId)||!text)return res.status(400).json({error:'Conversation and reply text are required.'});
      const message={id:crypto.randomUUID(),conversationId,sender:'owner',senderName:'Site owner',text,createdAt:new Date().toISOString()};
      await redis('sadd','pupchat:conversations',conversationId);await redis('rpush','pupchat:messages:'+conversationId,JSON.stringify(message));await redis('ltrim','pupchat:messages:'+conversationId,-200,-1);
      return res.status(201).json({message});
    }
    if(req.query.action==='messages'){
      const id=String(req.query.conversationId||'');if(!validId(id))return res.status(400).json({error:'Invalid conversation ID.'});
      const raw=await redis('lrange','pupchat:messages:'+id,0,-1);
      return res.status(200).json({conversationId:id,messages:(raw||[]).map(x=>JSON.parse(x))});
    }
    const ids=await redis('smembers','pupchat:conversations')||[];
    const conversations=await Promise.all(ids.slice(0,200).map(async id=>{
      const raw=await redis('lrange','pupchat:messages:'+id,0,-1);const messages=(raw||[]).map(x=>JSON.parse(x));const last=messages[messages.length-1];
      return {conversationId:id,messagesCount:messages.length,lastMessage:last?last.text:'',lastAt:last?last.createdAt:'',visitorName:(messages.find(m=>m.sender==='visitor')||{}).senderName||'Visitor'};
    }));
    conversations.sort((a,b)=>String(b.lastAt).localeCompare(String(a.lastAt)));
    return res.status(200).json({conversations});
  }catch(error){console.error('Chat admin error:',error.message);return res.status(503).json({error:'Inbox is temporarily unavailable.'})}
};
