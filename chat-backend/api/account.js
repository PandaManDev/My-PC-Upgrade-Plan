const crypto = require('node:crypto');
const { db, one } = require('../lib/db');

const ALLOWED_ORIGINS = new Set([
  'https://pandamandev.github.io',
  'http://localhost:3000'
]);
const configuredOrigin = (process.env.CHAT_ALLOWED_ORIGIN || '').replace(/\/$/, '');
if (configuredOrigin) ALLOWED_ORIGINS.add(configuredOrigin);

const secret = () => process.env.CHAT_AUTH_SECRET || process.env.CHAT_ADMIN_SECRET || '';
const emailHash = email => crypto.createHash('sha256').update(email.toLowerCase()).digest('hex');

function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  return body + '.' + signature;
}

function verify(token) {
  try {
    const [body, signature] = String(token || '').split('.');
    if (!body || !signature) return null;
    const expected = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
    if (!safeEqual(signature, expected)) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return payload.exp > Date.now() ? payload : null;
  } catch {
    return null;
  }
}

function userView(user) {
  return {
    id: user.id,
    email: user.email,
    displayName: user.display_name || '',
    createdAt: user.created_at || null,
    profilePicture: user.profile_picture || ''
  };
}

async function getAccount(email) {
  return one(db().from('chat_accounts').select('*').eq('email_hash', emailHash(email)));
}

module.exports = async function accountHandler(req, res) {
  const origin = typeof req.headers.origin === 'string' ? req.headers.origin.replace(/\/$/, '') : '';

  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Vary', 'Origin');

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }

  if (req.method === 'OPTIONS') {
    if (origin && !ALLOWED_ORIGINS.has(origin)) {
      return res.status(403).json({ error: 'Origin not allowed.' });
    }
    return res.status(204).end();
  }

  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return res.status(403).json({ error: 'Origin not allowed.' });
  }

  if (!['GET', 'POST'].includes(req.method)) {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  if (!secret() || !process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(503).json({
      error: 'Account storage is not configured. Set Supabase server variables and CHAT_AUTH_SECRET in Vercel.'
    });
  }

  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};
    const action = String((req.query && req.query.action) || body.action || '');

    if (req.method === 'POST' && (action === 'register' || action === 'login')) {
      const email = String(body.email || '').trim().toLowerCase();
      const password = String(body.password || '');

      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
        return res.status(400).json({ error: 'Enter a valid email address.' });
      }
      if (password.length < 8 || password.length > 128) {
        return res.status(400).json({ error: 'Password must be 8–128 characters.' });
      }

      let user = await getAccount(email);

      if (action === 'register') {
        if (user) return res.status(409).json({ error: 'An account with that email already exists.' });

        const salt = crypto.randomBytes(16).toString('hex');
        user = {
          id: crypto.randomUUID(),
          email,
          email_hash: emailHash(email),
          salt,
          password_hash: crypto.scryptSync(password, salt, 64).toString('hex'),
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          wishlist: {},
          display_name: '',
          profile_picture: ''
        };

        const { error } = await db().from('chat_accounts').insert(user);
        if (error) throw error;
      } else {
        if (!user || !safeEqual(
          crypto.scryptSync(password, user.salt, 64).toString('hex'),
          user.password_hash
        )) {
          return res.status(401).json({ error: 'Email or password is incorrect.' });
        }
      }

      const token = sign({
        sub: user.id,
        email: user.email,
        exp: Date.now() + 30 * 24 * 60 * 60 * 1000
      });

      return res.status(action === 'register' ? 201 : 200).json({
        token,
        user: userView(user)
      });
    }

    const authorization = String(req.headers.authorization || '');
    const token = authorization.replace(/^Bearer\s+/i, '');
    const session = verify(token);

    if (!session || typeof session.sub !== 'string' || typeof session.email !== 'string') {
      return res.status(401).json({ error: 'Please sign in again.' });
    }

    const user = await getAccount(session.email);
    if (!user || user.id !== session.sub) {
      return res.status(401).json({ error: 'Account not found. Please sign in again.' });
    }

    if (req.method === 'GET' || action === 'me') {
      return res.status(200).json({ user: userView(user), wishlist: user.wishlist || {} });
    }

    const patch = { updated_at: new Date().toISOString() };

    if (action === 'profilePicture') {
      const picture = typeof body.profilePicture === 'string' ? body.profilePicture : '';
      if (
        picture.length > 180000 ||
        !(picture === '' || /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+=*$/.test(picture))
      ) {
        return res.status(400).json({ error: 'Choose a valid JPG, PNG, or WebP image under 150 KB.' });
      }
      patch.profile_picture = picture;
    } else if (action === 'displayName') {
      const name = typeof body.displayName === 'string' ? body.displayName.trim() : '';
      if (name.length > 32 || /[<>\u0000-\u001f]/.test(name)) {
        return res.status(400).json({ error: 'Account name must be 32 characters or fewer and cannot contain control characters.' });
      }
      patch.display_name = name;
    } else if (action === 'save') {
      if (!body.wishlist || typeof body.wishlist !== 'object' || Array.isArray(body.wishlist)) {
        return res.status(400).json({ error: 'Wishlist data is invalid.' });
      }
      patch.wishlist = body.wishlist;
    } else {
      return res.status(400).json({ error: 'Unknown account action.' });
    }

    const { data, error } = await db()
      .from('chat_accounts')
      .update(patch)
      .eq('email_hash', emailHash(session.email))
      .select('*')
      .single();

    if (error) throw error;
    return res.status(200).json(action === 'save' ? { ok: true } : { user: userView(data) });
  } catch (error) {
    console.error('Account API error:', error && error.message ? error.message : 'Unknown error');
    return res.status(503).json({ error: 'Account service is temporarily unavailable.' });
  }
};
