# Security Notes & Cryptographic Design — KeyVEX v1.0.0 (First Official Release / v2.4.0 Hardened)

## Cryptographic Design (Versioned KDF v2)

```
Identity Layer: Account Password (Firebase Auth / PBKDF2 salt+hash) OR Google Identity Services OAuth 2.0
Vault Layer:    Vault Passkey (4/6-digit PIN, or 8-digit / Strong Passkey) + 256-bit Vault Entropy + 256-bit Per-Vault Random Salt (kdf.salt)
                ──PBKDF2-SHA256 (600,000 iter, kdf.salt)──▶ root ──HKDF-SHA256──▶ lookup | auth | KEK
                ──AES-KW──▶ wraps 256-bit AES-GCM Vault Key (vk)
Forgot Passkey: Fresh Re-Authentication (Account Password OR Google OAuth, valid ≤ 5 min, single-use)
                ──PBKDF2-SHA256 + HKDF-SHA256──▶ Account Reset KEK ──AES-KW──▶ unwraps vk (meta.accountResetWrapped)
```

| Value | Where it lives | Purpose |
|---|---|---|
| `kdf.salt` | Firestore (`/users/{uid}.meta.kdf.salt`) + IndexedDB | 256-bit random per-vault salt preventing cross-vault precomputation (`kdf.version = 2`) |
| `vaultEntropy` | Wrapped in `meta.wrappedEntropyPassword` & `meta.wrappedEntropyAccount`; wrapped on-device under a non-extractable AES-GCM `CryptoKey` (`wrappedDeviceEntropy`) | 256-bit high-entropy secret combined with the Vault Passkey |
| `accountResetWrapped` | Firestore (`/users/{uid}.meta.accountResetWrapped`) + IndexedDB (stripped from exported backups) | Allows resetting a forgotten Passkey after fresh Account Password or Google re-verification while preserving vault entries |
| `lookup` | Firestore (`/users/{uid}`) + local IndexedDB cache | 256-bit account lookup identifier (`keyvex:v6:lookup`) |
| `auth` | Never stored in plaintext; hashed via PBKDF2-SHA256 (600k rounds) / scrypt | Proves knowledge of credentials without revealing them |
| `KEK` | Browser volatile memory only (`keyvex:v6:kek`) | Unwraps the random 256-bit vault key via AES-KW |
| Vault key (`vk`) | Browser volatile memory only, `extractable: false` | Encrypts/decrypts entries via AES-256-GCM |

## Security Model & Known Limitations (F4, F5, B1, B2)

* **Client-Side AES-256-GCM Encryption & Account-Identity Reset Trade-off (F4)**:
  - Vault entries are encrypted client-side using `AES-256-GCM` with random 96-bit IVs and AAD binding (`keyvex:<vaultId>:entry:<entryId>`).
  - Because KeyVEX preserves saved passwords when a user clicks **"Forgot Passkey?"** and verifies with their **Account Password** or **Google**, the vault key (`vk`) is also wrapped under `meta.accountResetWrapped` (and `vaultEntropy` under `meta.wrappedEntropyAccount`).
  - Therefore, **account identity (Password or Google) can reset the Passkey**, and the 4/6-digit Passkey is a convenience gate and local step-up check rather than a strong independent secret against an attacker who compromises a live Firebase session and reads Firestore directly.
  - Exported backup files (`exportBackup`) strip `wrappedEntropyAccount` and `accountResetWrapped` so an exported `.json` backup requires both the Passkey and the Account/Master Password.
* **Future Option — "Strict Mode" (Zero-Recovery / Passkey-Bound Mode)**:
  - As a future high-security option, a **"Strict Mode"** toggle can omit `accountResetWrapped` and `wrappedEntropyAccount` altogether so both Account Identity AND Passkey are strictly required to decrypt the vault, and resetting a forgotten Passkey wipes the vault cleanly.
* **Device Entropy Wrapping & "Remember this device" (B1)**:
  - Raw `vaultEntropy` is never stored in plaintext in IndexedDB. It is encrypted with a **non-extractable `AES-256-GCM` `CryptoKey`** generated per browser profile (`wrappedDeviceEntropy`), and is deleted on sign-out unless the user ticks **"Remember this device"** (default OFF).
* **Persistent Passkey Lockout & Offline Guessing Note (B2)**:
  - Wrong Passkey attempts are persisted per-UID in IndexedDB across page reloads with exponential lockouts (`30 s`, `1 m`, `5 m`, `15 m`, `1 h`) enforced in both `unlockWithPasskey` and `requirePasskey`.
  - Note: An attacker with direct OS-level filesystem access who copies raw browser IndexedDB files can still attempt offline guesses against local data (mitigated by B1 non-extractable `CryptoKey` wrapping, clearing wrapped device entropy on sign-out, and choosing an 8-digit or Strong Passkey).
* **Mandatory Passkey Step-Up (`requirePasskey`, PART 4)**:
  - Every sensitive operation inside an unlocked vault (`setAccountPassword`, `changePasskey`, `changeMasterPassword`, `enableTotp`, `disableTotp`, `exportBackup`, `importEntries`, `remove`, `deleteAccount`) requires verifying the current Passkey in `src/core/vault.js`.
* **App-level lock (UI only) — TOTP (F5 & B13)**:
  - The optional RFC 6238 Authenticator prompt is honestly labeled **"App-level lock (UI only)"**. The TOTP secret is never persisted in plaintext IndexedDB (it lives only inside the sealed envelope and in volatile memory), enforces constant-time comparison, replay protection (rejecting reused time-steps), a 5-try / 60s lockout, a local zero-network SVG QR code, and 8 one-time hashed backup codes.
* **Cross-Device Deletion Tombstones & Concurrency (B3, B4, B5)**:
  - Deletion tombstones are stored in `/users/{uid}/tombstones/{entryId}` (and pruned at 90 days / capped so `meta` stays `< 20 KB`).
  - `meta.metaRev` increments monotonically on every credential change; `sync()` adopts newer remote `metaRev` and locks with a notice if the Passkey was changed on another device.
  - Firestore writes use `updateMask.fieldPaths` and `currentDocument.updateTime` preconditions with automatic conflict merge retries.
* **Distributed Server Rate Limiting (B9)**:
  - `server/rateLimit.js` enforces atomic Redis Lua `EVAL` / serialized throttling with **25 free tries per IP** (`auth:ip:<ip>`, `IP_FREE_TRIES = 25`) and **5 free tries per account lookup** (`auth:lookup:<lookup>`, `AUTH_FREE_TRIES = 5`). Window limiters fail open with a warning on Redis outage, while auth throttles fail closed with HTTP `503`.
