
import { createClient } from "npm:@supabase/supabase-js@2";
import { scrypt } from "node:crypto";
import { promisify } from "node:util";

const scryptAsync = promisify(scrypt);
const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SECRET_KEY") ?? Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const AUTH_SECRET = Deno.env.get("CHAT_AUTH_SECRET") ?? Deno.env.get("CHAT_ADMIN_SECRET") ?? "";
const ADMIN_SECRET = Deno.env.get("CHAT_ADMIN_SECRET") ?? "";
const ADMIN_EMAIL = (Deno.env.get("CHAT_ADMIN_EMAIL") ?? "").trim().toLowerCase();
const IPAPI_KEY = (Deno.env.get("IPAPI_KEY") ?? "").trim();

// Gift authorization key is synced from GitHub Actions Secret GIFT_AUTH_KEY
// into the Supabase Edge Function environment during deployment.
const GIFT_AUTH_KEY = Deno.env.get("GIFT_AUTH_KEY") ?? "";
const GIFT_SHIPPING_ADDRESS = Deno.env.get("GIFT_SHIPPING_ADDRESS") ?? "";

const SITE_ORIGIN = "https://pandamandev.github.io";
const ALLOWED = new Set([SITE_ORIGIN, "http://localhost:3000"]);
const db = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false }
});
const encoder = new TextEncoder();

const json = (
  body: unknown,
  status = 200,
  origin = ""
) => new Response(JSON.stringify(body), {
  status,
  headers: {
    "Content-Type": "application/json",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Allow-Origin": origin || SITE_ORIGIN,
    "Vary": "Origin"
  }
});

const emailHash = async (email: string) =>
  hex(await crypto.subtle.digest("SHA-256", encoder.encode(email.toLowerCase())));

function hex(bytes: ArrayBuffer) {
  return [...new Uint8Array(bytes)]
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function fromHex(s: string) {
  return new Uint8Array((s.match(/.{1,2}/g) ?? []).map(x => parseInt(x, 16)));
}

function b64url(bytes: Uint8Array) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function unb64url(s: string) {
  const raw = atob(
    s.replace(/-/g, "+").replace(/_/g, "/") +
    "=".repeat((4 - s.length % 4) % 4)
  );
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

async function hmac(body: string) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(AUTH_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  return b64url(
    new Uint8Array(
      await crypto.subtle.sign("HMAC", key, encoder.encode(body))
    )
  );
}

async function sign(payload: Record<string, unknown>) {
  const body = b64url(encoder.encode(JSON.stringify(payload)));
  return body + "." + await hmac(body);
}

async function verify(token: string) {
  try {
    const [body, signature] = token.split(".");
    if (!body || !signature || !AUTH_SECRET ||
        !constantEqual(signature, await hmac(body))) return null;

    const p = JSON.parse(new TextDecoder().decode(unb64url(body)));
    return p.exp > Date.now() &&
      typeof p.sub === "string" &&
      typeof p.email === "string" ? p : null;
  } catch {
    return null;
  }
}

function constantEqual(a: string, b: string) {
  if (a.length !== b.length) return false;
  let v = 0;
  for (let i = 0; i < a.length; i++) v |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return v === 0;
}

function userView(u: any) {
  return {
    id: u.id,
    email: u.email,
    displayName: u.display_name || "",
    createdAt: u.created_at || null,
    profilePicture: u.profile_picture || ""
  };
}

async function getAccount(email: string) {
  const { data, error } = await db.from("chat_accounts")
    .select("*")
    .eq("email_hash", await emailHash(email))
    .maybeSingle();
  if (error) throw error;
  return data;
}

async function account(req: Request, url: URL) {
  const body = req.method === "POST"
    ? await req.json().catch(() => ({}))
    : {};
  const action = url.searchParams.get("action") || body.action || "";

  if (req.method === "POST" && ["register", "login"].includes(action)) {
    const email = String(body.email || "").trim().toLowerCase();
    const password = String(body.password || "");

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254)
      return { error: "Enter a valid email address.", status: 400 };

    if (password.length < 8 || password.length > 128)
      return { error: "Password must be 8–128 characters.", status: 400 };

    let user = await getAccount(email);

    if (action === "register") {
      if (user)
        return { error: "An account with that email already exists.", status: 409 };

      const saltBytes = crypto.getRandomValues(new Uint8Array(16));
      const salt = hex(saltBytes.buffer);
      const derived = await scryptAsync(password, salt, 64) as Buffer;

      user = {
        id: crypto.randomUUID(),
        email,
        email_hash: await emailHash(email),
        salt,
        password_hash: derived.toString("hex"),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        wishlist: {},
        display_name: "",
        profile_picture: ""
      };

      const { error } = await db.from("chat_accounts").insert(user);
      if (error) throw error;
    } else {
      if (!user)
        return { error: "Email or password is incorrect.", status: 401 };

      const derived = await scryptAsync(password, user.salt, 64) as Buffer;
      if (!constantEqual(derived.toString("hex"), user.password_hash))
        return { error: "Email or password is incorrect.", status: 401 };
    }

    return {
      token: await sign({
        sub: user.id,
        email: user.email,
        exp: Date.now() + 30 * 24 * 60 * 60 * 1000
      }),
      user: userView(user),
      status: action === "register" ? 201 : 200
    };
  }

  const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const session = await verify(token);
  if (!session) return { error: "Please sign in again.", status: 401 };

  const user = await getAccount(session.email);
  if (!user || user.id !== session.sub)
    return { error: "Account not found. Please sign in again.", status: 401 };

  if (req.method === "GET" || action === "me")
    return { user: userView(user), wishlist: user.wishlist || {} };

  const patch: Record<string, unknown> = {
    updated_at: new Date().toISOString()
  };

  if (action === "profilePicture") {
    const picture = typeof body.profilePicture === "string" ? body.profilePicture : "";
    if (picture.length > 180000 ||
        !(picture === "" || /^data:image\/(?:jpeg|png|webp);base64,[A-Za-z0-9+/]+=*$/.test(picture)))
      return { error: "Choose a valid JPG, PNG, or WebP image under 150 KB.", status: 400 };
    patch.profile_picture = picture;
  } else if (action === "displayName") {
    const name = typeof body.displayName === "string" ? body.displayName.trim() : "";
    if (name.length > 32 || /[<>\u0000-\u001f]/.test(name))
      return { error: "Account name must be 32 characters or fewer and cannot contain control characters.", status: 400 };
    patch.display_name = name;
  } else if (action === "save") {
    if (!body.wishlist || typeof body.wishlist !== "object" || Array.isArray(body.wishlist))
      return { error: "Wishlist data is invalid.", status: 400 };
    patch.wishlist = body.wishlist;
  } else {
    return { error: "Unknown account action.", status: 400 };
  }

  const { data, error } = await db.from("chat_accounts")
    .update(patch)
    .eq("email_hash", await emailHash(session.email))
    .select("*")
    .single();
  if (error) throw error;
  return action === "save" ? { ok: true } : { user: userView(data) };
}

function validId(v: unknown): v is string {
  return typeof v === "string" && /^[a-f0-9-]{36}$/i.test(v);
}

async function verifyOwner(req: Request) {
  return await verify(
    (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "")
  );
}

async function messages(req: Request, url: URL) {
  const session = await verifyOwner(req);
  const isAdmin = !!session && !!ADMIN_EMAIL &&
    session.email.toLowerCase() === ADMIN_EMAIL;

  if (!session)
    return { error: "Please sign in to your account to use chat.", status: 401 };

  if (req.method === "POST") {
    const requestedBody = await req.clone().json().catch(() => ({}));
    if (["reply", "delete-conversation"].includes(requestedBody.action) && !isAdmin)
      return {
        error: "Administrator access required. Check the CHAT_ADMIN_EMAIL Supabase secret and redeploy pup-api.",
        status: 403
      };
  }

  if (req.method === "GET" && !url.searchParams.get("conversationId") && !isAdmin)
    return {
      error: "Administrator access required to view all conversations. Check the CHAT_ADMIN_EMAIL Supabase secret and redeploy pup-api.",
      status: 403
    };

  const clientIp = (
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-real-ip") ||
    req.headers.get("x-client-ip") ||
    req.headers.get("x-forwarded-for") || ""
  ).split(",")[0].trim().slice(0, 100) || "Unavailable";

  const publicMessage = (m: any, includeIp = isAdmin) => ({
    id: m.id,
    conversationId: m.conversation_id,
    sender: m.sender,
    senderName: m.sender_name,
    profilePicture: m.profile_picture,
    text: m.text,
    createdAt: m.created_at,
    ...(includeIp && m.ip_address
      ? { ipAddress: String(m.ip_address).slice(0, 100) }
      : {})
  });

  const body = req.method === "POST"
    ? await req.json().catch(() => ({}))
    : {};

  if (req.method === "POST" && isAdmin) {
    if (body.action === "delete-conversation") {
      const conversationId = String(body.conversationId || "");
      if (!validId(conversationId))
        return { error: "Invalid conversation ID.", status: 400 };

      const { data: existing, error: findError } = await db
        .from("chat_conversations").select("id")
        .eq("id", conversationId).maybeSingle();
      if (findError) throw findError;

      const { data: existingMessage, error: messageFindError } = await db
        .from("chat_messages").select("id")
        .eq("conversation_id", conversationId).limit(1).maybeSingle();
      if (messageFindError) throw messageFindError;

      if (!existing && !existingMessage)
        return { error: "Conversation not found.", status: 404 };

      const { error: deleteMessagesError } = await db
        .from("chat_messages").delete().eq("conversation_id", conversationId);
      if (deleteMessagesError) throw deleteMessagesError;

      const { error: deleteConversationError } = await db
        .from("chat_conversations").delete().eq("id", conversationId);
      if (deleteConversationError) throw deleteConversationError;

      return { success: true, conversationId, status: 200 };
    }

    if (body.action !== "reply")
      return { error: "Administrator accounts can only reply to or delete conversations.", status: 405 };

    const text = typeof body.text === "string" ? body.text.trim().slice(0, 1500) : "";
    const conversationId = String(body.conversationId || "");
    if (!text) return { error: "Write a reply first.", status: 400 };
    if (!validId(conversationId)) return { error: "Invalid conversation ID.", status: 400 };

    const { data: existingConversation, error: conversationError } = await db
      .from("chat_conversations").select("id,owner_id")
      .eq("id", conversationId).maybeSingle();
    if (conversationError) throw conversationError;

    let conversation: any = existingConversation;

    if (!conversation) {
      const { data: firstMessage, error: messageError } = await db
        .from("chat_messages").select("owner_id")
        .eq("conversation_id", conversationId).limit(1).maybeSingle();
      if (messageError) throw messageError;
      if (!firstMessage) return { error: "Conversation not found.", status: 404 };

      const { data: restored, error: restoreError } = await db
        .from("chat_conversations")
        .upsert({
          id: conversationId,
          owner_id: firstMessage.owner_id || null,
          updated_at: new Date().toISOString()
        })
        .select("id,owner_id").single();
      if (restoreError) throw restoreError;
      conversation = restored;
    }

    const now = new Date().toISOString();
    const { error: insertError } = await db.from("chat_messages").insert({
      id: crypto.randomUUID(),
      conversation_id: conversationId,
      owner_id: conversation.owner_id,
      sender: "owner",
      sender_name: "Panda PC Support",
      profile_picture: "",
      text,
      ip_address: null,
      created_at: now
    });
    if (insertError) throw insertError;

    const { error: updateError } = await db.from("chat_conversations")
      .update({ updated_at: now }).eq("id", conversationId);
    if (updateError) throw updateError;

    const { data: rows, error } = await db.from("chat_messages")
      .select("*").eq("conversation_id", conversationId)
      .order("created_at", { ascending: true }).limit(500);
    if (error) throw error;

    return {
      conversationId,
      messages: (rows || []).map(publicMessage),
      status: 201
    };
  }

  if (req.method === "POST" && isAdmin)
    return { error: "Admin access is read-only for this action.", status: 405 };

  if (req.method === "POST") {
    const text = typeof body.text === "string" ? body.text.trim().slice(0, 1500) : "";
    if (!text) return { error: "Write a message first.", status: 400 };

    const requested = String(body.conversationId || "");
    let conversationId = validId(requested) ? requested : crypto.randomUUID();

    if (validId(requested)) {
      const { data: existing, error } = await db.from("chat_conversations")
        .select("*").eq("id", conversationId).maybeSingle();
      if (error) throw error;

      if (existing?.owner_id && existing.owner_id !== session.sub)
        return { error: "This conversation belongs to another account.", status: 403 };

      if (!existing) conversationId = crypto.randomUUID();

      if (existing && !existing.owner_id) {
        const { error: e } = await db.from("chat_conversations")
          .update({ owner_id: session.sub }).eq("id", conversationId);
        if (e) throw e;
      }
    }

    const { error: ce } = await db.from("chat_conversations").upsert({
      id: conversationId,
      owner_id: session.sub,
      updated_at: new Date().toISOString()
    });
    if (ce) throw ce;

    const { data: acct } = await db.from("chat_accounts")
      .select("profile_picture,display_name")
      .eq("email_hash", await emailHash(session.email)).maybeSingle();

    const now = new Date().toISOString();
    const message = {
      id: crypto.randomUUID(),
      conversation_id: conversationId,
      owner_id: session.sub,
      sender: "visitor",
      sender_name: String(body.name || session.email.split("@")[0]).trim().slice(0, 50),
      profile_picture: acct?.profile_picture || "",
      text,
      ip_address: clientIp,
      created_at: now
    };

    const { error: me } = await db.from("chat_messages").insert(message);
    if (me) throw me;

    const { error: ue } = await db.from("chat_conversations")
      .update({ updated_at: now }).eq("id", conversationId);
    if (ue) throw ue;

    const { data: rows, error } = await db.from("chat_messages")
      .select("*").eq("conversation_id", conversationId)
      .order("created_at", { ascending: true }).limit(500);
    if (error) throw error;

    return {
      conversationId,
      messages: (rows || []).map(publicMessage),
      status: 201
    };
  }

  const id = url.searchParams.get("conversationId") || "";

  if (!id) {
    let query = db.from("chat_conversations")
      .select("*").order("updated_at", { ascending: false }).limit(200);
    if (!isAdmin) query = query.eq("owner_id", session!.sub);

    const { data: convs, error } = await query;
    if (error) throw error;
    const conversationRows = convs || [];

    if (isAdmin) {
      const { data: allMessages, error: messageError } = await db.from("chat_messages")
        .select("conversation_id,owner_id,sender,sender_name,ip_address,text,created_at")
        .order("created_at", { ascending: false }).limit(5000);
      if (messageError) throw messageError;

      const knownIds = new Set(conversationRows.map((c: any) => c.id));
      const recovered = new Map<string, any>();

      for (const m of allMessages || []) {
        if (!m.conversation_id || knownIds.has(m.conversation_id)) continue;
        const entry = recovered.get(m.conversation_id) || {
          id: m.conversation_id,
          owner_id: m.owner_id || null,
          updated_at: m.created_at || "",
          _messages: []
        };
        entry._messages.push(m);
        if (m.created_at && (!entry.updated_at || m.created_at > entry.updated_at))
          entry.updated_at = m.created_at;
        recovered.set(m.conversation_id, entry);
      }

      for (const c of recovered.values()) conversationRows.push(c);
      conversationRows.sort((a: any, b: any) =>
        String(b.updated_at || "").localeCompare(String(a.updated_at || ""))
      );
    }

    const conversations = await Promise.all(conversationRows.map(async (c: any) => {
      let list: any[];

      if (Array.isArray(c._messages)) {
        list = c._messages.slice().sort((a: any, b: any) =>
          String(a.created_at || "").localeCompare(String(b.created_at || ""))
        );
      } else {
        const { data: ms, error: messageError } = await db.from("chat_messages")
          .select("*").eq("conversation_id", c.id)
          .order("created_at", { ascending: true }).limit(500);
        if (messageError) throw messageError;
        list = ms || [];
      }

      const last = list[list.length - 1];
      const firstVisitor = list.find((m: any) => m.sender === "visitor");

      return {
        conversationId: c.id,
        updatedAt: c.updated_at || last?.created_at || "",
        visitorName: firstVisitor?.sender_name || "Website visitor",
        visitorIpAddress: firstVisitor?.ip_address || null,
        lastMessage: last ? publicMessage(last) : null,
        messagesCount: list.length
      };
    }));

    return { conversations };
  }

  if (!validId(id)) return { error: "Invalid conversation ID.", status: 400 };

  const { data: existingConversation, error: ce } = await db.from("chat_conversations")
    .select("*").eq("id", id).maybeSingle();
  if (ce) throw ce;

  let c: any = existingConversation;

  if (!c && isAdmin) {
    const { data: firstMessage, error: messageError } = await db.from("chat_messages")
      .select("owner_id").eq("conversation_id", id).limit(1).maybeSingle();
    if (messageError) throw messageError;
    if (firstMessage) c = { id, owner_id: firstMessage.owner_id || null };
  }

  if (!c || (!isAdmin && c.owner_id && c.owner_id !== session!.sub))
    return { error: "This conversation belongs to another account.", status: 403 };

  if (!isAdmin && !c.owner_id) {
    const { error } = await db.from("chat_conversations")
      .update({ owner_id: session!.sub }).eq("id", id);
    if (error) throw error;
  }

  const { data: rows, error } = await db.from("chat_messages")
    .select("*").eq("conversation_id", id)
    .order("created_at", { ascending: true }).limit(500);
  if (error) throw error;

  return { conversationId: id, messages: (rows || []).map(publicMessage) };
}

async function giftAddress(req: Request) {
  if (req.method !== "POST")
    return { error: "Method not allowed.", status: 405 };

  if (!GIFT_AUTH_KEY.trim())
    return {
      error: "Gift authorization key is not configured. Add the GIFT_AUTH_KEY GitHub Actions secret and run the deployment workflow.",
      status: 503
    };

  if (!GIFT_SHIPPING_ADDRESS.trim())
    return {
      error: "Gift shipping address is not configured. Set GIFT_SHIPPING_ADDRESS in Supabase Edge Function secrets and redeploy pup-api.",
      status: 503
    };

  const body = await req.json().catch(() => ({}));
  const key = typeof body?.key === "string" ? body.key.trim() : "";

  if (!key || key.length > 256)
    return { error: "Enter your gift authorization key.", status: 400 };

  // Store only a one-way hash of the network address, never the supplied key
  // or shipping address. Eight failed attempts trigger a temporary block.
  const forwarded = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
  const remote = forwarded || req.headers.get("x-real-ip") || "unknown";
  const ipHash = await emailHash("gift:" + remote);
  const now = Date.now();

  const { data: row, error: readError } = await db.from("gift_access_attempts")
    .select("*").eq("ip_hash", ipHash).maybeSingle();
  if (readError) throw readError;

  if (row?.blocked_until && Date.parse(row.blocked_until) > now)
    return { error: "Too many attempts. Please try again later.", status: 429 };

  const windowMs = 15 * 60 * 1000;
  const sameWindow = row?.window_started && now - Date.parse(row.window_started) < windowMs;
  const attempts = sameWindow ? Number(row.attempts || 0) : 0;

  if (!constantEqual(key, GIFT_AUTH_KEY)) {
    const nextAttempts = attempts + 1;
    const blockedUntil = nextAttempts >= 8
      ? new Date(now + 30 * 60 * 1000).toISOString()
      : null;

    const record = {
      ip_hash: ipHash,
      attempts: blockedUntil ? 0 : nextAttempts,
      window_started: sameWindow ? row.window_started : new Date(now).toISOString(),
      blocked_until: blockedUntil
    };

    const { error } = await db.from("gift_access_attempts")
      .upsert(record, { onConflict: "ip_hash" });
    if (error) throw error;

    return {
      error: blockedUntil
        ? "Too many incorrect keys. Try again in 30 minutes."
        : "That authorization key is not valid.",
      status: blockedUntil ? 429 : 401
    };
  }

  const { error: resetError } = await db.from("gift_access_attempts")
    .upsert({
      ip_hash: ipHash,
      attempts: 0,
      window_started: new Date(now).toISOString(),
      blocked_until: null
    }, { onConflict: "ip_hash" });
  if (resetError) throw resetError;

  return {
    address: GIFT_SHIPPING_ADDRESS,
    message: "Authorization accepted."
  };
}

async function securityCheck(req: Request) {
  if (req.method !== "POST")
    return { error: "Method not allowed.", status: 405 };

  if (!IPAPI_KEY)
    return { error: "Proxy detection is not configured yet.", status: 503 };

  const body = await req.json().catch(() => ({}));
  const ip = String(body?.ip ?? "").trim();

  if (!ip || ip.length > 45 ||
      !/^[0-9a-fA-F:.]+$/.test(ip) ||
      (!ip.includes(".") && !ip.includes(":"))) {
    return { error: "A valid public IP address is required.", status: 400 };
  }

  const response = await fetch(
    "https://api.ipapi.is/?q=" + encodeURIComponent(ip) +
    "&key=" + encodeURIComponent(IPAPI_KEY),
    {
      method: "GET",
      headers: { "Accept": "application/json" },
      signal: AbortSignal.timeout(5000),
      cache: "no-store"
    }
  );

  if (!response.ok) {
    console.warn("IP reputation lookup returned status", response.status);
    return { error: "Proxy detection is temporarily unavailable.", status: 503 };
  }

  const data = await response.json().catch(() => null);
  if (!data || typeof data !== "object" ||
      typeof data.is_proxy !== "boolean") {
    return { error: "Proxy detection response did not include security flags.", status: 503 };
  }

  return {
    is_proxy: data.is_proxy === true,
    is_vpn: data.is_vpn === true,
    is_tor: data.is_tor === true
  };
}

async function call(req: Request, url: URL) {
  const auth = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
  const admin = !!ADMIN_SECRET && constantEqual(auth, ADMIN_SECRET);
  const session = await verifyOwner(req);

  if (!admin && !session)
    return { error: "Please sign in to use voice calling.", status: 401 };

  const body = req.method === "POST"
    ? await req.json().catch(() => ({}))
    : {};

  const id = String(url.searchParams.get("conversationId") || body.conversationId || "");
  if (!validId(id)) return { error: "Invalid conversation ID.", status: 400 };

  const role = body.role === "admin" || url.searchParams.get("role") === "admin"
    ? "admin"
    : "visitor";

  if (role === "admin" && !admin)
    return { error: "Admin authorization required.", status: 401 };

  const idle = {
    conversationId: id,
    status: "idle",
    visitorCandidates: [],
    adminCandidates: []
  };

  const { data: row, error: readError } = await db.from("chat_calls")
    .select("data").eq("conversation_id", id).maybeSingle();
  if (readError) throw readError;

  const d: any = row?.data || idle;

  if (req.method === "GET") return d;

  const action = String(body.action || "");

  if (action === "start") {
    if (role !== "visitor" || !body.offer || typeof body.offer.sdp !== "string")
      return { error: "Call offer is missing.", status: 400 };

    Object.assign(d, {
      status: "ringing",
      offer: body.offer,
      answer: null,
      visitorCandidates: [],
      adminCandidates: [],
      updatedAt: new Date().toISOString()
    });
  } else if (action === "accept") {
    if (role !== "admin" || !body.answer || typeof body.answer.sdp !== "string")
      return { error: "Call answer is missing.", status: 400 };

    Object.assign(d, {
      answer: body.answer,
      status: "active",
      updatedAt: new Date().toISOString()
    });
  } else if (action === "candidate") {
    if (!body.candidate)
      return { error: "Candidate is missing.", status: 400 };

    const k = role === "admin" ? "adminCandidates" : "visitorCandidates";
    d[k] = Array.isArray(d[k]) ? d[k] : [];
    if (d[k].length < 100) d[k].push(body.candidate);
    d.updatedAt = new Date().toISOString();
  } else if (action === "end") {
    d.status = "ended";
    d.updatedAt = new Date().toISOString();
  } else if (action === "decline") {
    if (role !== "admin")
      return { error: "Only admins can decline calls.", status: 400 };

    Object.assign(d, {
      status: "declined",
      offer: null,
      answer: null,
      visitorCandidates: [],
      adminCandidates: [],
      updatedAt: new Date().toISOString()
    });
  } else {
    return { error: "Unknown call action.", status: 400 };
  }

  const { error } = await db.from("chat_calls").upsert({
    conversation_id: id,
    data: d,
    updated_at: new Date().toISOString()
  }, { onConflict: "conversation_id" });
  if (error) throw error;

  return d;
}

Deno.serve(async (req) => {
  const origin = req.headers.get("origin") || "";

  if (origin && !ALLOWED.has(origin))
    return json({ error: "Origin not allowed." }, 403, SITE_ORIGIN);

  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": origin || SITE_ORIGIN,
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
        "Vary": "Origin"
      }
    });
  }

  if (!SUPABASE_URL || !SERVICE_KEY || !AUTH_SECRET) {
    return json({
      error: "Supabase API is not configured. Set SUPABASE_URL, SUPABASE_SECRET_KEY, and CHAT_AUTH_SECRET in Supabase Edge Function secrets."
    }, 503, origin);
  }

  if (!["GET", "POST"].includes(req.method))
    return json({ error: "Method not allowed." }, 405, origin);

  try {
    const url = new URL(req.url);
    const route = url.pathname.split("/").filter(Boolean).at(-1) || "";
    let result: any;

    if (route === "gift-address") result = await giftAddress(req);
    else if (route === "security-check") result = await securityCheck(req);
    else if (route === "account") result = await account(req, url);
    else if (route === "messages") result = await messages(req, url);
    else if (route === "call") result = await call(req, url);
    else return json({ error: "Unknown API route." }, 404, origin);

    const status = Number(result?.status || 200);
    delete result.status;
    return json(result, status, origin);
  } catch (e: unknown) {
    // Supabase/PostgREST often throws plain objects rather than Error instances.
    // Log useful diagnostics without returning internal details to the browser.
    let diagnostic = "Unserializable thrown value";
    if (e instanceof Error) {
      diagnostic = [e.name, e.message].filter(Boolean).join(": ");
    } else if (typeof e === "string") {
      diagnostic = e;
    } else if (e && typeof e === "object") {
      const value = e as Record<string, unknown>;
      const fields = ["name", "message", "code", "details", "hint"]
        .map((key) => {
          const field = value[key];
          return field === undefined || field === null || field === ""
            ? ""
            : key + "=" + String(field);
        })
        .filter(Boolean);
      try {
        diagnostic = fields.length
          ? fields.join(" | ")
          : JSON.stringify(e) || diagnostic;
      } catch {
        diagnostic = fields.join(" | ") || diagnostic;
      }
    } else if (e !== null && e !== undefined) {
      diagnostic = String(e);
    }
    console.error("pup-api error:", diagnostic.slice(0, 1500));
    return json({ error: "Service is temporarily unavailable." }, 503, origin);
  }
});
