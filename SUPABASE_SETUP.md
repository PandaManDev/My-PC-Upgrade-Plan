# Move Pandas PC Upgrade Plan off Vercel

This repository is being prepared to serve the website from GitHub Pages and its account/chat API from Supabase Edge Functions.

## Important compatibility note

The current account system stores scrypt password hashes in `public.chat_accounts` and uses signed 30-day tokens. This function ports that existing system to Supabase Edge Functions so current accounts can continue using the same password and existing account/wishlist/chat rows can remain in place. It does **not** silently convert those accounts to Supabase Auth. A later Supabase Auth migration would need a deliberate password-reset or verified account-linking flow.

## 1. Keep existing data

Do not drop or recreate `chat_accounts`, `chat_conversations`, `chat_messages`, or `chat_calls`. If the tables do not exist yet, run `chat-backend/supabase/schema.sql` in the Supabase SQL Editor. It creates tables if absent and enables RLS; it does not drop existing rows.

## 2. Set Edge Function secrets

In Supabase Dashboard → Project Settings / Edge Functions secrets, set:

- `SUPABASE_URL` = `https://jitmbvmeeyqjekyxaluk.supabase.co`
- `SUPABASE_SECRET_KEY` = your server-side Supabase secret key (preferred), or `SUPABASE_SERVICE_ROLE_KEY` = the legacy service-role key
- `CHAT_AUTH_SECRET` = the existing secret used to sign the current account tokens. **Use the same value as the current backend or existing saved sessions will need to sign in again.** Never put this value in website JavaScript or commit it to GitHub.
- `CHAT_ADMIN_SECRET` = the existing voice-call admin secret if owner/admin calling is enabled.
- `CHAT_ADMIN_EMAIL` = `JJB@petlovers.com` (the account email allowed to read the website chat inbox). This is checked server-side; do not add it to frontend JavaScript.
- `IPAPI_KEY` = your API key from [ipapi.is](https://ipapi.is/app/signup). This is required for proxy/VPN/Tor detection because anonymous requests no longer include those security flags. Keep this key only in Supabase Edge Function secrets; never add it to `index.html` or commit it to GitHub.

Never use a publishable/anon key as the server key. Never commit any secret values.

## 3. Deploy the Edge Function

Install the Supabase CLI, sign in, and from this repository run:

```sh
supabase login
supabase link --project-ref jitmbvmeeyqjekyxaluk
supabase functions deploy pup-api --no-verify-jwt
```

The function supports these routes:
- `/functions/v1/pup-api/account`
- `/functions/v1/pup-api/messages`
- `/functions/v1/pup-api/call`
- `/functions/v1/pup-api/security-check` (visitor proxy/VPN/Tor detection; requires `IPAPI_KEY`)

## 4. Verify before switching the public site

Test account login, registration with a new test email, wishlist save/load, chat-history listing, sending a chat message, and call signaling. Do not delete or disable the old backend until these pass. The existing password hashing and token signing must be tested in the deployed Deno runtime before cutover.

## 5. GitHub Pages cutover

Once the Edge Function is deployed and tests pass, change the account API base in `index.html` to:

```js
const API = 'https://jitmbvmeeyqjekyxaluk.supabase.co/functions/v1/pup-api/account';
```

Change the chat API base to:

```js
const CHAT_API_BASE = 'https://jitmbvmeeyqjekyxaluk.supabase.co/functions/v1/pup-api';
```

The chat code then calls `/messages`; voice code should call `/call`. Only make this cutover after the function is deployed, otherwise the live website's account/chat features will stop working. GitHub Pages will publish the static site from the configured branch/folder after the HTML change is committed.

## Current status

The function and setup instructions are source files only until deployed to Supabase and tested. The repository's current `index.html` still points to the former Vercel API, so the migration is not complete yet.
