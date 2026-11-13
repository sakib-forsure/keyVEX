# KeyVEX v1.0.0 (First Official Release / v2.4.0 Hardened) — Engineering & Security Audit (`docs/ENGINEERING_AUDIT.md`)

## 1. Internal Dependency Map

```
index.html + public/_headers + netlify.toml + render.yaml + vite.config.js + scripts/build.mjs + scripts/csp.mjs
  └── src/main.js (Theme + Service Worker v5 + Update Reload Banner + Bootstrap)
        └── src/ui/app.js (Router, Auth State Listener, Auto-Lock, 60s Sync Flush, Logout/Lock Lifecycle)
              ├── src/ui/screens/login.js     (Continue with Google, Email/Password Login, Remember Device, Forgot Password, TOTP Prompt)
              ├── src/ui/screens/register.js  (Full Name, Email, Password, Confirm Password, Continue with Google)
              ├── src/ui/screens/passkey.js   (Email Verify Banner w/ 60s Cooldown & 5s Poll, Passkey Setup & Unlock, Forgot Passkey Sheet)
              ├── src/ui/screens/vault.js     (Encrypted Vault Dashboard, 120ms Debounced Search, >500 Virtualization, AbortController Cleanup)
              └── src/core/vault.js           (2-Layer Auth, requirePasskey Step-Up & Cryptographic Coordinator)
                    ├── Layer 1 (Identity): src/core/firebase.js + src/core/firebase-config.js
                    │     ├── Google OAuth 2.0 (Lazy GIS Loader w/ 15s Timeout, 1 Retry & Post-Auth Script Unload)
                    │     ├── Firebase Identity Toolkit (signUp, signInWithPassword, signInWithIdp, sendOobCode, lookup, update, delete)
                    │     ├── Secure Token Service (firebaseRefreshSession + automatic token renewal)
                    │     └── Cloud Firestore (users/{uid}, entries/{entryId}, tombstones/{entryId} with updateMask & updateTime preconditions)
                    └── Layer 2 (Vault Security): src/core/crypto.js + src/core/idb.js + src/core/api.js
                          ├── PBKDF2-HMAC-SHA256 (600,000 iterations, per-vault 256-bit kdf.salt) + HKDF-SHA256 -> lookup, auth, AES-KW KEK
                          ├── AES-256-GCM entry encryption with AAD binding (keyvex:{vaultId}:entry:{entryId})
                          ├── Non-extractable IndexedDB AES-GCM CryptoKey wrapping device vaultEntropy (wrappedDeviceEntropy)
                          ├── Short-lived (≤ 5 min, single-use) Password / Google verification for Passkey reset (meta.accountResetWrapped)
                          └── IndexedDB (`v6_users`, `v6_accounts`, `v6_entries`, `v6_sync_queue`, `v6_migration_backups`)
```

## 2. Security & Architecture Audit Summary (v1.0.0 (First Official Release / v2.4.0 Hardened))

1. **Removed Insecure Email-Link Passkey Reset & Recovery Key (Parts 1–3, F1–F3)**:
   - Removed `?mode=resetPasskey`, `sendPasskeyResetEmail`, `emailLinkConfirmed`, and the 128-bit Recovery Key.
   - Replaced with `showForgotPasskeySheet(ctx)` requiring fresh re-authentication via **Account Password** (`firebaseSignIn`) or **Google** (`firebaseSignInWithGoogleToken` with strict `email` and `uid` matching) before unlocking a 5-minute single-use `resetPasskeyAfterVerification(newPasskey)` gate.
2. **Mandatory Passkey Step-Up (`requirePasskey`, Part 4 & F6)**:
   - Enforced `requirePasskey(passkey)` in `src/core/vault.js` across all sensitive actions (`setAccountPassword`, `changePasskey`, `changeMasterPassword`, `enableTotp`, `disableTotp`, `exportBackup`, `importEntries`, `remove`, and `deleteAccount`).
3. **Device Entropy Protection & Persistent Exponential Lockout (B1, B2)**:
   - `vaultEntropy` is wrapped on-device with a non-extractable `AES-256-GCM` `CryptoKey` in IndexedDB (`wrappedDeviceEntropy`) and wiped on sign-out unless `"Remember this device"` is enabled.
   - Wrong-Passkey counters are persisted per-UID in IndexedDB (`30 s`, `1 m`, `5 m`, `15 m`, `1 h` lockouts) so reloading the page never resets the counter.
4. **Bounded Tombstone Subcollection & Optimistic Concurrency (B3, B4, B5)**:
   - Moved deletion tombstones out of unbounded `meta.deletedEntries` into `/users/{uid}/tombstones/{entryId}` with 90-day pruning so `meta` remains `< 20 KB` even after 2,000+ deletions.
   - Added monotonic `meta.metaRev` and Firestore `updateMask.fieldPaths` + `currentDocument.updateTime` preconditions with automatic conflict merging.
5. **Hashed Production Build, Unified CSP & Atomic Rate Limiting (B6, B7, B9)**:
   - Eliminated un-hashed `/assets/src/**` output in `scripts/build.mjs`, unified CSP in `scripts/csp.mjs`, and upgraded `server/rateLimit.js` to use atomic Redis Lua `EVAL` throttling with `IP_FREE_TRIES = 25` and `AUTH_FREE_TRIES = 5`.
