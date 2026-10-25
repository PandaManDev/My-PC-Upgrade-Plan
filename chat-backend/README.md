# Pandas PC Upgrade Plan — Supabase Chat Backend

## Required setup

1. Run `supabase/schema.sql` in the [Supabase SQL Editor](https://supabase.com/dashboard/project/jitmbvmeeyqjekyxaluk/sql/new).
2. In Vercel project `pandas-pc-upgrade-chat`, set these environment variables for Production (and Preview if needed):
   - `SUPABASE_URL=https://jitmbvmeeyqjekyxaluk.supabase.co`
   - `SUPABASE_SECRET_KEY` = the project's **server-side secret key** (recommended; typically starts with `sb_secret_`), OR `SUPABASE_SERVICE_ROLE_KEY` = legacy service-role key.
   - `CHAT_AUTH_SECRET` = keep the existing private value; do not rotate unless you intend to invalidate existing sessions.
   - `CHAT_ADMIN_SECRET` = keep the existing private value.
   - `CHAT_ALLOWED_ORIGIN=https://pandamandev.github.io` (origin only: no repository path, trailing slash, or hash).
3. Redeploy the Vercel project after environment variable changes.

## Troubleshooting the account service

The API's server-side Supabase key must be a **secret/service-role** key. Do not use a publishable key or legacy `anon` JWT; those run under the `anon` role and will be blocked by the enabled row-level security (RLS) policies. The backend now validates common key formats and emits a specific server-side error when a public key is supplied.

If registration still reports a row-level security error, verify the key is from this exact Supabase project and that it is the secret/service-role key. Keep RLS enabled; do not add permissive public policies to work around a server-key problem.

The Vercel environment variable list can show secret values as blank when not decrypted. Do not share secret values in screenshots or chat.

## Storage note

This migration does not automatically import records from the previously suspended Vercel Blob store. If that store can be re-enabled/exported, import the records before switching production. If it is inaccessible, existing accounts stored only there may need to be recreated.

Never commit Supabase server keys or place them in browser JavaScript. The project root directory in Vercel should be `chat-backend`.
