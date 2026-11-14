<div align="center">

# 🔐 KeyVEX

### **Keep your life safe.**
**Zero-Knowledge Client-Side Encrypted Password Vault**

`Version 1.0.0 — First Official Release` • `AES-256-GCM` • `PBKDF2-SHA256` • `Cloud Sync` • `Offline-First`

**🌐 Live Demo: [vault.keyvex.workers.dev](https://vault.keyvex.workers.dev)**

</div>

---

## 🚀 Try it

- **Use it now (no install needed):** open [vault.keyvex.workers.dev](https://vault.keyvex.workers.dev) — create an account, set a passkey, and your vault is ready.
- **Install it as an app (free, no app store):** Android — Chrome → Install app · iPhone — Safari → Share → Add to Home Screen · PC — Chrome/Edge → install icon in the address bar. Works offline after the first visit.
- **Run it locally:**
  ```bash
  npm install
  cp .env.example .env   # fill in your own Firebase keys
  npm run dev
  ```
  Build for production with `npm run build` (output: `dist/`).

---

## ✨ Overview

**KeyVEX** is a modern, privacy-first password manager engineered around a strict **Zero-Knowledge Encryption Architecture**. Every password, username, note, and generator history record is encrypted and decrypted locally inside your browser using the native **WebCrypto API** before anything ever leaves your device.

Even when synced across devices via **Google Cloud Firestore**, the server stores only opaque `AES-256-GCM` ciphertext envelopes—meaning nobody (not even the server or database administrator) can ever read your vault data.

---

## 🚀 Highlights

- 🛡️ **True Zero-Knowledge Security** — End-to-end client-side encryption using `AES-256-GCM`, `PBKDF2-HMAC-SHA256` (310,000–900,000 iterations), `HKDF-SHA256`, and `RFC 3394 AES-KW` key wrapping.
- 🔑 **Dual-Layer Access Control** — Authenticate with **Email & Password** or **Continue with Google**, protected by a local **4-Digit or 6-Digit Passkey** lock for instant daily unlocking.
- ☁️ **Real-Time Cloud Sync + Offline Vault** — Automatic conflict-free merging (`Last-Write-Wins` with tombstone tracking) between local `IndexedDB` storage and [Cloud Firestore](https://firebase.google.com/docs/firestore).
- ⚡ **Built-In Security Audit** — Live vault health score with automatic detection of weak, reused, compromised, and aging passwords.
- 🎲 **Smart Password & Passphrase Generator** — High-entropy character and multi-word passphrase generator with an encrypted history popup modal (`YYYY-MM-DD HH:MM:SS` timestamps, character counts, one-click copy, and selective deletion).
- 🔄 **One-Click Backup & Restore** — Export encrypted `.json` backups or plaintext `.csv` archives, and import credentials from Chrome, Bitwarden, 1Password, or CSV directly into your main vault.
- 🎨 **5 Signature Glassmorphic Themes** — Ships with **Ocean** (Default), **Sunset**, **Aurora**, **Monolith**, and **Daylight** with full dark/light adaptability.
- 🧭 **Native URL Routing & In-App Password Reset** — Clean browser history navigation (`/login`, `/register`, `/passkey`, `/vault`) and built-in Firebase password reset confirmation right inside the app.

---

## 🔒 Security Architecture

| Layer | Specification | Purpose |
| :--- | :--- | :--- |
| **Vault Cipher** | `AES-256-GCM` (96-bit IV + 128-bit Auth Tag) | Authenticated encryption for all vault items and generator history |
| **Key Derivation** | `PBKDF2-HMAC-SHA256` (310k–900k iterations) | Derives wrapping keys from user credentials and passkeys |
| **Subkey Expansion** | `HKDF-SHA256` | Separates encryption keys, verification hashes, and device salts |
| **Key Wrapping** | `RFC 3394 AES-KW` / `AES-GCM` | Wraps the 256-bit Data Encryption Key (`DEK`) across auth providers |
| **Local Storage** | `IndexedDB` (`keyvex_db_v2`) | Offline-first encrypted persistence on the user's device |
| **Cloud Sync** | [Firebase Authentication](https://firebase.google.com/docs/auth) + [Cloud Firestore](https://firebase.google.com/docs/firestore) | Zero-knowledge encrypted cloud backup and cross-device sync |

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
| :--- | :--- |
| `/` or `Ctrl / Cmd + K` | Focus search bar |
| `Alt + N` | Add a new password |
| `Alt + G` | Open Password Generator |
| `Alt + L` | Lock vault immediately |
| `Alt + S` | Open Settings |
| `?` | Show Keyboard Shortcuts guide |
| `Esc` | Close active modal / sheet |

---

## 👨‍💻 Author

<div align="center">

**KeyVEX Version 1.0 (`v1.0.0` — First Official Release)**  
Designed & Developed by **Abdullah Sakib** ([@sakib-forsure](https://github.com/sakib-forsure))

*Keep your life safe — encrypted on your device before it is ever saved.*

</div>
