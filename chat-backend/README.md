# Pandas PC Upgrade Plan — Supabase Chat Backend

1. Run `supabase/schema.sql` in Supabase SQL Editor: https://supabase.com/dashboard/project/jitmbvmeeyqjekyxaluk/sql/new
2. In Vercel project `pandas-pc-upgrade-chat`, set:
   - `SUPABASE_URL=https://jitmbvmeeyqjekyxaluk.supabase.co`
   - `SUPABASE_SERVICE_ROLE_KEY` = your server-only `sb_secret_...` or legacy service_role key
   - Keep existing `CHAT_AUTH_SECRET` and `CHAT_ADMIN_SECRET` values unchanged
   - `CHAT_ALLOWED_ORIGIN=https://pandamandev.github.io`
3. Apply to Production and Preview as needed, then redeploy. Project root directory: `chat-backend`.

Never commit the Supabase server key or put it in browser JavaScript. RLS is enabled and no public policies are created; backend access uses the server key.

Data note: this migration does not automatically import records from the suspended Vercel Blob store. If Blob can be re-enabled/exported, import records before switching production. If inaccessible, accounts may need to be recreated.
