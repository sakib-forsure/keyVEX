# KeyVEX Changelog

## Production-readiness pass

- **Fixed (Cloudflare):** the service worker cached `/index.html` as a *redirected* response (Cloudflare redirects `/index.html` to `/`); browsers refuse such responses for navigations, which would break offline start. Responses are now rebuilt without the redirect flag.
- **Added:** in-app Install button (banner + Settings row) using `beforeinstallprompt`; how-to sheet for iOS / other browsers.
- **Fixed:** manifest screenshots were the 512px icon labelled narrow/wide; replaced with real screenshots. Manifest colours aligned with the app theme.

## Offline-first release

- **Fixed:** `public/sw.js` contained `export` statements, which is a syntax error for a classic service worker, so it never registered and the app could not open offline. Rewritten; the build now stamps it with every hashed JS/CSS/font file so the whole shell is cached at install time (cache-first for `/assets/*`, cached shell for navigations).
- Added "You're offline" / "Back online" banner, iPhone Home Screen meta tags + install hint, persistent-storage request.
- All Firebase/Firestore requests time out after 15 s instead of hanging; saves/deletes never wait more than 4 s for the network.
- Flush/sync are serialised (no concurrent double-sends); queued changes now sync even while the vault is locked, every 30 s and on reconnect.
- Offline "Forgot Passkey?" via account password (local digest); Google verification, password reset email and account-password change report a clear offline message and do not count as wrong attempts.
- Passkey reset no longer silently replaces a vault that still has data when the old key cannot be unwrapped (previously it created an empty vault and could overwrite the cloud copy).
- Build writes `dist/.assetsignore`; `docs/OFFLINE.md` documents Cloudflare setup.


## v1.0.0 (First Official Release / v2.4.0 Hardened) — Security Simplification, Step-Up Hardening & Sync Concurrency

### Part 1 & Part 2 — Complete Removal of Email-Link Passkey Reset & Recovery Key
- **Removed Email-Link Passkey Reset (`src/core/vault.js`, `src/core/firebase.js`, `src/ui/screens/passkey.js`, `src/ui/app.js`)**:
  - Deleted `sendPasskeyResetEmail`, `firebaseSendPasskeyResetEmail`, `passkeyResetToken`, `passkeyResetRequestedAt`, `PASSKEY_RESET_TTL_MS`, `emailLinkConfirmed`, and `?mode=resetPasskey` URL handling (eliminating Findings F1 and F2).
  - Kept `?mode=resetPassword` exclusively for Firebase Account Password resets and `?mode=verifyEmail` exclusively for email verification status updates (never touching Passkey reset state).
- **Removed 128-Bit Recovery Key (`src/core/crypto.js`, `src/core/vault.js`, `src/ui/screens/passkey.js`, `src/ui/errors.js`)**:
  - Deleted `generateRecoveryKey`, `deriveRecoveryKek`, `unlockWithRecoveryKey`, `resetPasskeyWithRecovery`, and `RECOVERY_INVALID`.
  - `setupPasskey()` and `resetPasskeyAfterVerification()` now return `{ ok: true }` and automatically strip legacy `recoveryWrapped`, `recoverySalt`, `emailResetWrapped`, and `emailResetSalt` on next metadata write.

### Part 3 — New "Forgot Passkey?" Sheet (Password / Google Verification Only)
- **Rewrote `showForgotPasskeySheet(ctx)` (`src/ui/screens/passkey.js`, `src/core/vault.js`)**:
  - Step 1 shows **Verify with Password** (only when `acct.hasPassword`) and/or **Verify with Google** (only when `acct.providers` includes `google.com`), with the `"or"` divider rendered only when both options are available.
  - Password verification always authenticates against Firebase (`firebaseSignIn`) when configured; Google verification always authenticates via `firebaseSignInWithGoogleToken`, verifies matching `email` and `uid`, and rejects when Firebase is unconfigured (fixing Finding F3).
  - Verification state (`#passkeyResetVerifiedAt`) lives in `src/core/vault.js`, expires after **5 minutes**, is **single-use**, and is cleared on lock, sign-out, or sheet close. Five failed verification attempts lock the sheet for 60 seconds.

### Part 4 — Mandatory Passkey Step-Up (`requirePasskey`)
- **Enforced `requirePasskey(passkey)` in `src/core/vault.js` (`src/ui/sheets/settings.js`, `src/ui/sheets/detail.js`)**:
  - Added `requirePasskey(passkey)` in `Vault` with 5-strike exponential lockout and a 60-second step-up cache (`#stepUpUntil`) cleared on lock/sign-out/auto-lock.
  - Enforced Passkey verification as the first step in `deleteAccount`, `changePasskey`, `changeMasterPassword`, `setAccountPassword`, `enableTotp`, `disableTotp`, `exportBackup`, `importEntries`, and `remove`.

### Part 5 & Part 8 — Deep Security Audit Fixes (F1–F12 & B1–B28)
- **Account Reset Envelope & Honest Security Documentation (F4, B18)**: Renamed `emailResetWrapped`/`Salt` to `accountResetWrapped`/`Salt`, stripped weak envelopes from exported backups, and updated `README.md` and `SECURITY.md` to state the exact client-side `AES-256-GCM` + account-identity recovery model and future "Strict Mode" option.
- **App-Level Lock (UI Only) & TOTP Hardening (F5, B13)**: Relabeled TOTP to `"App-level lock (UI only)"`, stopped persisting `totpSecret` in plaintext IndexedDB, added constant-time verification, replay protection, 5-try lockout, strict Base32 decoding, a local zero-network SVG QR code generator, and 8 one-time hashed backup codes.
- **Non-Extractable Device Entropy Wrapping & Persistent Lockout (B1, B2)**: Wrapped `vaultEntropy` on-device using a non-extractable `AES-256-GCM` `CryptoKey` stored in IndexedDB (`wrappedDeviceEntropy`), cleared on sign-out unless `"Remember this device"` is enabled, expanded `BAD_PINS` in `src/core/strength.js`, and persisted per-UID wrong-Passkey counters with exponential lockouts (`30s` to `1h`).
- **Firestore Tombstone Subcollection, Monotonic `metaRev` & Optimistic Concurrency (B3, B4, B5, B8, F9)**: Moved deletion tombstones to `/users/{uid}/tombstones/{entryId}` with 90-day pruning so `meta` stays `< 20 KB` across thousands of deletes; added monotonic `meta.metaRev` and `currentDocument.updateTime` + `updateMask.fieldPaths` concurrency control; updated `firestore.rules` to require verified email or `google.com` provider and matching `request.auth.token.email`.
- **Production Build, Unified CSP, Service Worker & Rate Limiter Hardening (B6, B7, B9, B16, F10, F11)**: Removed un-hashed `/assets/src/**` output in `scripts/build.mjs`, created single-source `scripts/csp.mjs`, bumped Service Worker cache to `keyvex-shell-v5` while blocking `oobCode`/`token`/`mode` URLs from caching, and fixed `server/rateLimit.js` atomic Redis throttling and `IP_FREE_TRIES = 25` vs `AUTH_FREE_TRIES = 5`.
