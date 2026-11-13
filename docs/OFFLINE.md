# KeyVEX — Offline-first & Cloudflare deployment

## How it works
- **First sign-in / sign-up** (and Google login) are online. After that the vault opens with **no network**: the app shell is cached by the service worker, the account session + encrypted vault live in IndexedDB, and the PIN unlocks it locally.
- **View / copy / add / edit / delete** work offline. Each change is written to the encrypted local cache and queued in the IndexedDB outbox (`v6_sync_queue`).
- **Auto-sync**: when the connection returns (and every 30 s while changes are queued) the outbox is pushed to Firestore in order. Entry IDs are stable and writes are idempotent, so nothing is duplicated; syncing also works while the vault is locked.
- **Banner**: "You're offline" (with the number of queued changes) while offline, "Back online — syncing…" when it returns.
- **Online-only**: Google login, password-reset email, changing the account password, "verify with Google".
- **Offline-allowed**: changing the Passkey with the current Passkey, and "Forgot Passkey?" verified with the account password (checked against the salted PBKDF2 digest stored on the device).

## iPhone
Open the site in Safari → Share → **Add to Home Screen**, then sign in once *inside* the Home Screen app (it has its own storage). Installed apps are exempt from Safari's 7-day storage clean-up; the app also asks the browser for persistent storage.

## Cloudflare (Workers Static Assets)
1. Build command: `npm run build`  ·  Deploy command: `npx wrangler deploy` (`wrangler.jsonc` already points to `./dist`, SPA fallback on).
2. Set the `VITE_FIREBASE_*` and `VITE_GOOGLE_CLIENT_ID` variables in **Settings → Variables and Secrets → Build** (they are baked in at build time).
3. Firebase Console → Authentication → Settings → **Authorized domains**: add your `*.workers.dev` / custom domain. Google Cloud Console → OAuth client → add the same origin to **Authorized JavaScript origins**.
4. `public/_headers` supplies CSP/HSTS and no-cache for `index.html`, `sw.js`, `manifest.webmanifest`; `/assets/*` is immutable.
5. After each deploy the service worker (versioned per build) updates itself and shows "New version — Reload".

## Install (Add to Home Screen)
- Android / desktop Chrome & Edge: the app is installable (manifest, icons, screenshots, service worker). KeyVEX shows its own **Install** banner (dismissible, remembered 7 days) and a **Settings → Install app** row; both call the native install dialog.
- iPhone / iPad: Safari has no install API, so a one-time hint and the same Settings row show the Share → Add to Home Screen steps.

## Firebase Console checklist (login, Google sign-in, e-mails)
1. Authentication → Sign-in method: enable **Email/Password** and **Google**.
2. Authentication → Settings → **Authorized domains**: add the exact `*.workers.dev` / custom domain.
3. Google Cloud → OAuth client → **Authorized JavaScript origins**: add the same origin.
4. Password-reset and verification e-mails are sent by Firebase. Check Authentication → Templates (sender, spam folder). The reset e-mail returns to `/?passwordReset=1`.
