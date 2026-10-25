# Legacy Chat Backend (Archived)

The current PC Upgrade Plan site is hosted on GitHub Pages and uses Supabase Edge Functions for its backend.

The old `chat-backend/api/` files were written for Vercel's serverless runtime and are retained only as legacy reference code. They are not part of the current deployment path.

## Current deployment

- **Website:** GitHub Pages — https://pandamandev.github.io/My-PC-Upgrade-Plan/
- **Backend:** Supabase Edge Function `pup-api`
- **Supabase setup notes:** See the root `SUPABASE_SETUP.md`

## Vercel

The legacy `vercel.json` configuration has been removed from this repository. **To stop Vercel from automatically attempting deployments, disconnect this GitHub repository from the old Vercel project** in Vercel Project Settings → Git → Disconnect Repository (wording may vary). Removing repository configuration files alone cannot disable an external Vercel Git integration.

Do not add server-side keys, passwords, or other secrets to this repository.
