/**
 * Single Source of Truth for Content-Security-Policy (`scripts/csp.mjs`).
 *
 * B7 Hardening:
 *   - Drops unused `https://apis.google.com` from `script-src`.
 *   - Replaces wildcard `https://*.google.com` in `frame-src` with `https://accounts.google.com`.
 *   - Replaces wildcard `https://*.googleapis.com` in `connect-src` with the exact Google/Firebase hosts used
 *     (`identitytoolkit`, `securetoken`, `firestore`, `oauth2`, `www.googleapis.com`).
 *   - Adds `worker-src 'self'`, `manifest-src 'self'`, and `upgrade-insecure-requests`.
 */
export const CSP_DIRECTIVES = [
  "default-src 'self'",
  "script-src 'self' https://accounts.google.com https://accounts.google.com/gsi/client",
  "style-src 'self' 'unsafe-inline' https://accounts.google.com https://accounts.google.com/gsi/style",
  "img-src 'self' data: https://lh3.googleusercontent.com https://*.googleusercontent.com https://www.gstatic.com",
  "font-src 'self' data:",
  "connect-src 'self' https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://firestore.googleapis.com https://accounts.google.com https://oauth2.googleapis.com https://www.googleapis.com",
  "frame-src 'self' https://accounts.google.com https://*.firebaseapp.com",
  "worker-src 'self'",
  "manifest-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self' https://accounts.google.com",
  "upgrade-insecure-requests"
];

/** For HTML `<meta http-equiv="Content-Security-Policy">` (which does not support `frame-ancestors`). */
export const META_CSP = CSP_DIRECTIVES.join("; ");

/** For HTTP headers (`server/app.js`, `netlify.toml`, `public/_headers`), which include `frame-ancestors 'none'`. */
export const HEADER_CSP = [...CSP_DIRECTIVES, "frame-ancestors 'none'"].join("; ");

export default HEADER_CSP;
