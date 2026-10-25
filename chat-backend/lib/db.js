const { createClient } = require('@supabase/supabase-js');

let client;

function serverKey() {
  // Supabase's newer sb_secret_ key is also a server-side key that bypasses RLS.
  // Prefer it when configured; retain support for the legacy service-role JWT.
  return process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY || '';
}

function validateServerKey(key) {
  if (!key) {
    throw new Error('Supabase server key is missing. Set SUPABASE_SECRET_KEY (recommended) or SUPABASE_SERVICE_ROLE_KEY in Vercel.');
  }

  // Legacy Supabase anon keys are JWTs with role=anon and do not bypass RLS.
  if (key.startsWith('eyJ')) {
    try {
      const payloadPart = key.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadPart, 'base64url').toString('utf8'));
      if (payload.role && payload.role !== 'service_role') {
        throw new Error('Supabase key has role "' + payload.role + '". Use a server-side secret/service-role key, not an anon/publishable key.');
      }
    } catch (error) {
      if (error && error.message && error.message.startsWith('Supabase key has role')) throw error;
      throw new Error('Supabase server key is not a valid JWT. Check the Vercel environment variable.');
    }
  }

  if (key.startsWith('sb_publishable_')) {
    throw new Error('A public publishable Supabase key cannot be used by this server. Set SUPABASE_SECRET_KEY in Vercel.');
  }
  if (key.startsWith('sb_secret_')) return;
  if (key.startsWith('eyJ')) return;

  throw new Error('Unrecognized Supabase server key format. Check the Vercel environment variable.');
}

function db() {
  const url = process.env.SUPABASE_URL;
  const key = serverKey();

  if (!url) throw new Error('SUPABASE_URL is missing in Vercel.');
  validateServerKey(key);

  if (!client) {
    client = createClient(url, key, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false
      }
    });
  }
  return client;
}

async function one(query) {
  const { data, error } = await query.maybeSingle();
  if (error) throw error;
  return data;
}

async function rows(query) {
  const { data, error } = await query;
  if (error) throw error;
  return data || [];
}

module.exports = { db, one, rows };
