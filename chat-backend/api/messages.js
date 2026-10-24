const crypto = require('node:crypto');

const SITE_ORIGIN = process.env.CHAT_ALLOWED_ORIGIN || 'https://pandamandev.github.io';
const REDIS_URL = (process.env.UPSTASH_REDIS_REST_URL || '').replace(/\/$/, '');
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || '';

function cors(req, res) {
  const origin = req.headers.origin;
  if (origin === SITE_ORIGIN || origin === 'http://localhost:3000') res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store');
}

async function redis(command, ...args) {
  if (!REDIS_URL || !REDIS_TOKEN) throw new Error('Chat storage is not configured.');
  const parts = [command, ...args].map(v => encodeURIComponent(String(v)));
  const response = await fetch(REDIS_URL + '/' + parts.join('/'), {headers:{Authorization:'Bearer ' + REDIS_TOKEN}});
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(data.error || 'Storage request failed.');
  return data.result;
}
function validId(value) { return typeof value === 'string' && /^[a-f0-9-]{36}$/i.test(value); }
function cleanText(value) { return typeof value === 'string' ? value.trim().slice(0, 1500) : ''; }
function cleanName(value) { return typeof value === 'string' ? value.trim().slice(0, 50) : ''; }

module.exports = async function handler(req, res) {
  cors(req, res);
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!['GET','POST'].includes(req.method)) return res.status(405).json({error:'Method not allowed.'});
  if (req.headers.origin && req.headers.origin !== SITE_ORIGIN && req.headers.origin !== 'http://localhost:3000') return res.status(403).json({error:'Origin not allowed.'});
  try {
    if (req.method === 'POST') {
      const text = cleanText(req.body && req.body.text);
      if (!text) return res.status(400).json({error:'Write a message first.'});
      const conversationId = validId(req.body && req.body.conversationId) ? req.body.conversationId : crypto.randomUUID();
      const name = cleanName(req.body && req.body.name) || 'Visitor';
      const message = {id:crypto.randomUUID(),conversationId,sender:'visitor',senderName:name,text,createdAt:new Date().toISOString()};
      await redis('sadd','pupchat:conversations',conversationId);
      await redis('rpush','pupchat:messages:'+conversationId,JSON.stringify(message));
      await redis('ltrim','pupchat:messages:'+conversationId,-200, -1);
      const raw = await redis('lrange','pupchat:messages:'+conversationId,0,-1);
      return res.status(201).json({conversationId,messages:(raw||[]).map(x=>JSON.parse(x))});
    }
    const conversationId = String(req.query.conversationId || '');
    if (!validId(conversationId)) return res.status(400).json({error:'Invalid conversation ID.'});
    const raw = await redis('lrange','pupchat:messages:'+conversationId,0,-1);
    return res.status(200).json({messages:(raw||[]).map(x=>JSON.parse(x))});
  } catch (error) {
    console.error('Chat API error:', error.message);
    return res.status(503).json({error:'Chat is temporarily unavailable. Please try again later.'});
  }
};
