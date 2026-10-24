# Pandas PC Upgrade Plan — Custom Chat Backend

This is a custom-coded two-way chat API and private owner inbox. It does not embed a third-party chat widget.

## Required environment variables

Configure these in the Vercel project (never put them in public GitHub files):

- `UPSTASH_REDIS_REST_URL`: private Upstash Redis REST URL.
- `UPSTASH_REDIS_REST_TOKEN`: private Upstash Redis REST token.
- `CHAT_ADMIN_SECRET`: long random secret used to unlock `/admin.html`.
- `CHAT_ALLOWED_ORIGIN`: `https://pandamandev.github.io`.

The backend stores messages in Redis lists and conversation IDs in a Redis set. It limits each conversation to the latest 200 messages. Use a strong unique admin secret and do not share it.

## Deploy

Create a Vercel project from this repository with root directory `chat-backend`. Add the environment variables above, then deploy. The frontend at GitHub Pages must use the resulting deployment URL in `CHAT_API_BASE` in the main `index.html`, including the `/api` suffix.

Owner inbox: `https://YOUR-CHAT-BACKEND.vercel.app/admin.html`.

## Security notes

The admin API checks a bearer secret server-side using a constant-time comparison. The secret is entered into the owner dashboard and is not stored in localStorage. The public API only exposes messages when a visitor has the unguessable conversation ID stored in their browser. CORS is restricted to the configured website origin. Use HTTPS, rotate secrets if exposed, and consider adding abuse throttling before opening the chat widely.
