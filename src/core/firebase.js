/**
 * Official Firebase Authentication (Email/Password + Google Identity Services)
 * and Canonical Cloud Firestore Encrypted Vault Client for KeyVEX (`src/core/firebase.js`).
 *
 * Key Repairs:
 *   - Issue B: Metadata-only Firestore reads (`firestoreGetVaultMetaOnly`) during session restore/login
 *     so entries are never downloaded before the user submits their Passkey; removed redundant
 *     `accounts:lookup` round-trip from `firebaseSignIn`.
 *   - Issue C & D: Full `nextPageToken` pagination in `firestoreListAllEntries` and `firestoreGetVault`
 *     (never truncating at 1,000 entries); strict error propagation in `firestoreDeleteVault`
 *     with awaited `onStage` callbacks, batched `documents:commit` deletes, and post-delete verification.
 *   - Section 3, OOB Action Codes & Popup Cleanup: Single documented Google Identity Services (GIS) OAuth flow
 *     with minimal identity scopes (`openid email profile`), automatic tracking and cleanup of opened Google
 *     OAuth popup windows (`closeActiveGooglePopup`), and OOB action code handlers (`firebaseApplyActionCode`,
 *     `firebaseConfirmPasswordReset`).
 */
import { getFirebaseConfig, isFirebaseConfigured, validateFirebaseAndGoogleConfig } from "./firebase-config.js";
import { measureAsync } from "./perf.js";

export class FirebaseError extends Error {
  constructor(code, message, status = 400, extra = {}) {
    super(message || code);
    this.code = code;
    this.status = status;
    Object.assign(this, extra);
  }
}

const FRIENDLY_FIREBASE_ERRORS = {
  EMAIL_EXISTS: "An account with this email already exists. Please sign in instead.",
  EMAIL_NOT_FOUND: "No account found with this email. Please create an account first.",
  USER_NOT_FOUND: "No account found with this email. Please create an account first.",
  INVALID_PASSWORD: "Incorrect email or password. Please try again.",
  INVALID_LOGIN_CREDENTIALS: "Incorrect email or password. Please try again.",
  USER_DISABLED: "This account has been disabled.",
  TOO_MANY_ATTEMPTS_TRY_LATER: "Too many failed attempts. Please try again in a few minutes.",
  RESET_PASSWORD_EXCEED_LIMIT: "Too many reset emails requested recently. Please wait a few minutes and try again.",
  INVALID_EMAIL: "Please enter a valid email address.",
  WEAK_PASSWORD: "Password should be at least 8 characters.",
  OPERATION_NOT_ALLOWED: "This sign-in method is not enabled in Firebase Console.",
  CREDENTIAL_TOO_OLD_LOGIN_AGAIN: "Please sign in again to confirm your identity before completing this action.",
  TOKEN_EXPIRED: "Your session has expired. Please sign in again.",
  INVALID_ID_TOKEN: "Your session has expired. Please sign in again.",
  EXPIRED_OOB_CODE: "The verification or reset link has expired. Please request a new one.",
  INVALID_OOB_CODE: "The verification or reset link is invalid or was already used. Please request a new one.",
  FEDERATED_USER_ID_ALREADY_LINKED: "This Google account is already linked to an account.",
  INVALID_IDP_RESPONSE: "Google authentication token was rejected or expired. Please try again.",
  UNAUTHORIZED_DOMAIN: "This domain is not authorized in Firebase Console -> Authentication -> Settings -> Authorized domains.",
  INVALID_CONTINUE_URI: "The redirect URL is not authorized in Firebase Console -> Authentication -> Settings -> Authorized domains.",
  MISSING_CONTINUE_URI: "A valid redirect URL is required for this action.",
  API_KEY_INVALID: "Invalid Firebase API key configuration.",
  CONFIGURATION_NOT_FOUND: "Firebase Authentication is not configured for this project."
};

export function mapFirebaseAuthError(rawCode, status = 400) {
  const raw = String(rawCode || "AUTH_ERROR").trim();
  const base = raw.split(" ")[0].split(":")[0].trim();
  return new FirebaseError(
    base,
    FRIENDLY_FIREBASE_ERRORS[base] || "Authentication failed. Please check your details and try again.",
    status
  );
}

/* ============================================================================
 * Transport & Emulator Hook (Supports Real Fetch, Firebase Emulator, or Test Mock)
 * ============================================================================ */
let customTransport = null;

export function setFirebaseTransport(fn = null) {
  customTransport = typeof fn === "function" ? fn : null;
}

async function doFetch(url, options) {
  if (customTransport) {
    return customTransport(url, options);
  }
  return fetch(url, options);
}

function identityToolkitBaseUrl() {
  const { authEmulatorHost } = getFirebaseConfig();
  if (authEmulatorHost) {
    const host = String(authEmulatorHost).replace(/^https?:\/\//, "").replace(/\/$/, "");
    return `http://${host}/identitytoolkit.googleapis.com/v1`;
  }
  return "https://identitytoolkit.googleapis.com/v1";
}

function secureTokenBaseUrl() {
  const { authEmulatorHost } = getFirebaseConfig();
  if (authEmulatorHost) {
    const host = String(authEmulatorHost).replace(/^https?:\/\//, "").replace(/\/$/, "");
    return `http://${host}/securetoken.googleapis.com/v1`;
  }
  return "https://securetoken.googleapis.com/v1";
}

/* ============================================================================
 * Firebase Authentication State Listener (onAuthStateChanged)
 * ============================================================================ */
const authListeners = new Set();
let currentAuthState = null;

export function onFirebaseAuthStateChanged(listener) {
  if (typeof listener !== "function") return () => {};
  authListeners.add(listener);
  return () => {
    authListeners.delete(listener);
  };
}

export function emitFirebaseAuthState(userState) {
  currentAuthState = userState ? { ...userState } : null;
  for (const fn of [...authListeners]) {
    try {
      fn(currentAuthState ? { ...currentAuthState } : null);
    } catch {
      /* ignore listener errors */
    }
  }
}

export function getCurrentFirebaseAuthState() {
  return currentAuthState ? { ...currentAuthState } : null;
}

export function clearFirebaseAuthListeners() {
  authListeners.clear();
  currentAuthState = null;
}

/* ============================================================================
 * Core Identity Toolkit REST Helper
 * ============================================================================ */
async function authPost(endpoint, body) {
  const { apiKey } = getFirebaseConfig();
  if (!apiKey || String(apiKey).startsWith("YOUR_")) {
    throw new FirebaseError("INVALID_OAUTH_CONFIG", "Firebase API key is not configured.", 400);
  }
  let res;
  try {
    res = await doFetch(`${identityToolkitBaseUrl()}/${endpoint}?key=${encodeURIComponent(apiKey)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  } catch (err) {
    if (err instanceof FirebaseError) throw err;
    throw new FirebaseError(
      "NETWORK",
      "Could not reach Firebase Authentication. Please check your internet connection or allow googleapis.com in your browser.",
      0
    );
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw mapFirebaseAuthError(data?.error?.message, res.status);
  }
  return data;
}

/**
 * Refresh a Firebase ID token using a stored refreshToken.
 */
export async function firebaseRefreshSession(refreshToken) {
  return measureAsync("token_refresh", async () => {
    const { apiKey } = getFirebaseConfig();
    if (!apiKey || !refreshToken) {
      throw new FirebaseError("UNAUTHENTICATED", "Session expired. Please sign in again.", 401);
    }
    let res;
    try {
      res = await doFetch(`${secureTokenBaseUrl()}/token?key=${encodeURIComponent(apiKey)}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ grant_type: "refresh_token", refresh_token: refreshToken })
      });
    } catch (err) {
      if (err instanceof FirebaseError) throw err;
      throw new FirebaseError("NETWORK", "Could not reach Firebase to refresh session.", 0);
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok || !data.id_token) {
      const rawMsg = String(data?.error?.message || "SESSION_EXPIRED");
      if (rawMsg.includes("USER_DISABLED")) {
        throw new FirebaseError("USER_DISABLED", FRIENDLY_FIREBASE_ERRORS.USER_DISABLED, 403);
      }
      throw new FirebaseError("SESSION_EXPIRED", "Your session expired. Please sign in again.", 401);
    }
    const expiresIn = Number(data.expires_in) || 3600;
    return {
      idToken: data.id_token,
      refreshToken: data.refresh_token || refreshToken,
      uid: data.user_id,
      expiresIn,
      tokenExpiresAt: Date.now() + Math.max(60, expiresIn - 120) * 1000
    };
  });
}

/**
 * Create a new Firebase user with Name, Email, and Password.
 */
export async function firebaseSignUp({ name, email, password }) {
  const normEmail = String(email || "").trim().toLowerCase();
  const displayName = String(name || "").trim();
  const data = await authPost("accounts:signUp", {
    email: normEmail,
    password: String(password),
    returnSecureToken: true
  });
  if (displayName && data.idToken) {
    await authPost("accounts:update", {
      idToken: data.idToken,
      displayName,
      returnSecureToken: false
    }).catch(() => {});
  }
  const expiresIn = Number(data.expiresIn) || 3600;
  return {
    uid: data.localId,
    email: normEmail,
    name: displayName || normEmail.split("@")[0],
    idToken: data.idToken,
    refreshToken: data.refreshToken,
    expiresIn,
    tokenExpiresAt: Date.now() + Math.max(60, expiresIn - 120) * 1000,
    emailVerified: false,
    provider: "password",
    providers: ["password"]
  };
}

/**
 * Sign in an existing Firebase user with Email and Password.
 * Issue B Fix: Does NOT perform a redundant blocking `accounts:lookup` network request
 * when `signInWithPassword` already returns `localId`, `email`, `displayName`, and tokens.
 */
export async function firebaseSignIn({ email, password, fetchAccountInfo = false }) {
  const normEmail = String(email || "").trim().toLowerCase();
  const data = await authPost("accounts:signInWithPassword", {
    email: normEmail,
    password: String(password),
    returnSecureToken: true
  });
  const expiresIn = Number(data.expiresIn) || 3600;
  let info = null;
  if (fetchAccountInfo && data.idToken) {
    try {
      info = await firebaseGetAccountInfo(data.idToken);
    } catch {
      /* optional lookup */
    }
  }
  return {
    uid: data.localId,
    email: normEmail,
    name: info?.displayName || data.displayName || normEmail.split("@")[0],
    idToken: data.idToken,
    refreshToken: data.refreshToken,
    expiresIn,
    tokenExpiresAt: Date.now() + Math.max(60, expiresIn - 120) * 1000,
    emailVerified: info ? !!info.emailVerified : Boolean(data.emailVerified ?? data.registered),
    provider: "password",
    providers: info?.providers?.length ? info.providers : ["password"]
  };
}

/**
 * Sign in with a Google ID token / access token via Firebase Identity Toolkit.
 * Detects account conflicts (`needConfirmation`) when an email already exists with a different provider.
 */
export async function firebaseSignInWithGoogleToken({ idToken, accessToken }) {
  if (!idToken && !accessToken) {
    throw new FirebaseError("INVALID_IDP_RESPONSE", "Google sign-in did not return an authentication token.", 400);
  }
  const postBody = idToken
    ? `id_token=${encodeURIComponent(idToken)}&providerId=google.com`
    : `access_token=${encodeURIComponent(accessToken)}&providerId=google.com`;
  const data = await authPost("accounts:signInWithIdp", {
    postBody,
    requestUri: typeof location !== "undefined" && location.origin && location.origin !== "null" ? location.origin : "http://localhost",
    returnIdpCredential: true,
    returnSecureToken: true
  });

  if (data.needConfirmation) {
    const conflictEmail = String(data.email || "").trim().toLowerCase();
    throw new FirebaseError(
      "ACCOUNT_CONFLICT_PASSWORD",
      "An account with this email already exists with a password. Please verify your password to link your Google account.",
      409,
      {
        email: conflictEmail,
        existingProvider: "password",
        pendingGoogle: {
          email: conflictEmail,
          name: data.displayName || data.fullName || conflictEmail.split("@")[0],
          idToken: data.oauthIdToken || idToken || null,
          accessToken: data.oauthAccessToken || accessToken || null,
          pendingToken: data.pendingToken || null
        }
      }
    );
  }

  const email = String(data.email || "").trim().toLowerCase();
  const expiresIn = Number(data.expiresIn) || 3600;
  return {
    uid: data.localId,
    email,
    name: data.displayName || data.fullName || email.split("@")[0],
    idToken: data.idToken,
    refreshToken: data.refreshToken,
    expiresIn,
    tokenExpiresAt: Date.now() + Math.max(60, expiresIn - 120) * 1000,
    emailVerified: true,
    isNewUser: Boolean(data.isNewUser),
    provider: "google.com",
    providers: ["google.com"]
  };
}

/**
 * Link a Google OAuth credential to an already-authenticated Firebase user account (`accountIdToken`).
 * Preserves the existing Firebase `uid` and links `google.com` to `providerUserInfo`.
 */
export async function firebaseLinkGoogleToAccount(accountIdToken, { idToken, accessToken, pendingToken } = {}) {
  if (!accountIdToken) {
    throw new FirebaseError("UNAUTHENTICATED", "Please sign in with your existing account first.", 401);
  }
  const postBody = idToken
    ? `id_token=${encodeURIComponent(idToken)}&providerId=google.com`
    : `access_token=${encodeURIComponent(accessToken || "")}&providerId=google.com`;
  const data = await authPost("accounts:signInWithIdp", {
    idToken: accountIdToken,
    postBody,
    pendingToken: pendingToken || undefined,
    requestUri: typeof location !== "undefined" && location.origin && location.origin !== "null" ? location.origin : "http://localhost",
    returnIdpCredential: true,
    returnSecureToken: true
  });
  const expiresIn = Number(data.expiresIn) || 3600;
  return {
    uid: data.localId,
    email: String(data.email || "").trim().toLowerCase(),
    name: data.displayName || data.fullName || "",
    idToken: data.idToken || accountIdToken,
    refreshToken: data.refreshToken || null,
    expiresIn,
    tokenExpiresAt: Date.now() + Math.max(60, expiresIn - 120) * 1000,
    providers: ["password", "google.com"]
  };
}

/**
 * Send Password Reset email via Firebase Auth.
 */
export async function firebaseSendPasswordResetEmail(email) {
  const normEmail = String(email || "").trim().toLowerCase();
  const hasHttpOrigin = typeof location !== "undefined" && /^https?:\/\//i.test(location.origin || "");
  const continueUrl = hasHttpOrigin ? `${location.origin}/?passwordReset=1` : null;
  if (continueUrl) {
    try {
      return await authPost("accounts:sendOobCode", {
        requestType: "PASSWORD_RESET",
        email: normEmail,
        continueUrl
      });
    } catch (err) {
      if (err?.code !== "INVALID_CONTINUE_URI" && err?.code !== "UNAUTHORIZED_DOMAIN" && err?.code !== "MISSING_CONTINUE_URI") {
        throw err;
      }
    }
  }
  return authPost("accounts:sendOobCode", {
    requestType: "PASSWORD_RESET",
    email: normEmail
  });
}

/**
 * Send Email Verification email via Firebase Auth.
 */
export async function firebaseSendEmailVerification(idToken) {
  if (!idToken) throw new FirebaseError("UNAUTHENTICATED", "Please sign in first.", 401);
  return authPost("accounts:sendOobCode", {
    requestType: "VERIFY_EMAIL",
    idToken
  });
}

/**
 * Applies a Firebase OOB email verification code (`?mode=verifyEmail&oobCode=...`).
 */
export async function firebaseApplyActionCode(oobCode) {
  if (!oobCode) throw new FirebaseError("INVALID_OOB_CODE", "Verification code is missing.", 400);
  return authPost("accounts:update", { oobCode: String(oobCode).trim() });
}

/**
 * Confirms a Firebase OOB password reset code (`?mode=resetPassword&oobCode=...`).
 */
export async function firebaseConfirmPasswordReset(oobCode, newPassword) {
  if (!oobCode) throw new FirebaseError("INVALID_OOB_CODE", "Reset code is missing.", 400);
  if (!newPassword) {
    return authPost("accounts:resetPassword", { oobCode: String(oobCode).trim() });
  }
  return authPost("accounts:resetPassword", {
    oobCode: String(oobCode).trim(),
    newPassword: String(newPassword)
  });
}

/**
 * Set or update password on an authenticated Firebase user account (links `password` provider to existing UID).
 */
export async function firebaseSetAccountPassword(idToken, password) {
  const data = await authPost("accounts:update", {
    idToken,
    password: String(password),
    returnSecureToken: true
  });
  const expiresIn = Number(data.expiresIn) || 3600;
  return {
    idToken: data.idToken || idToken,
    refreshToken: data.refreshToken || null,
    uid: data.localId,
    email: String(data.email || "").trim().toLowerCase(),
    expiresIn,
    tokenExpiresAt: Date.now() + Math.max(60, expiresIn - 120) * 1000,
    providers: (data.providerUserInfo || []).map((p) => p.providerId)
  };
}

/**
 * Delete the Firebase Authentication user record (`accounts:delete`).
 * Throws if deletion fails so callers never falsely report an account as deleted.
 */
export async function firebaseDeleteAuthAccount(idToken) {
  if (!idToken) {
    throw new FirebaseError("UNAUTHENTICATED", "Valid authentication token is required to delete account identity.", 401);
  }
  await authPost("accounts:delete", { idToken });
  return { deleted: true };
}

/**
 * Get account info from Firebase (to check emailVerified status and linked providers).
 */
export async function firebaseGetAccountInfo(idToken) {
  if (!idToken) return null;
  const data = await authPost("accounts:lookup", { idToken });
  const user = data.users?.[0];
  if (!user) return null;
  return {
    uid: user.localId,
    email: String(user.email || "").trim().toLowerCase(),
    emailVerified: !!user.emailVerified,
    displayName: user.displayName || "",
    disabled: !!user.disabled,
    providers: (user.providerUserInfo || []).map((p) => p.providerId)
  };
}

/**
 * Fetch sign-in methods for an email to handle provider linking conflicts (only called after form submission).
 */
export async function firebaseFetchSignInMethodsForEmail(email) {
  const normEmail = String(email || "").trim().toLowerCase();
  try {
    const data = await authPost("accounts:createAuthUri", {
      identifier: normEmail,
      continueUri: typeof location !== "undefined" && location.origin && location.origin !== "null" ? location.origin : "http://localhost"
    });
    return data.allProviders || data.signinMethods || [];
  } catch {
    return [];
  }
}

/* ============================================================================
 * Official Google Identity Services (GIS) OAuth 2.0 Integration (Section 3 & B7/B23)
 * ============================================================================ */
let gisLoadingPromise = null;
let googleAuthInFlight = false;
const trackedGooglePopups = new Set();

export function isGoogleAuthInFlight() {
  return googleAuthInFlight;
}

/**
 * Closes any lingering Google OAuth popup windows so background tabs / popups
 * never stay stuck open after sign-in, cancellation, `origin_mismatch`, or page unload.
 */
export function closeActiveGooglePopup() {
  for (const win of [...trackedGooglePopups]) {
    try {
      if (win && !win.closed && typeof win.close === "function") {
        win.close();
      }
    } catch {
      /* ignore cross-origin window close errors */
    }
  }
  trackedGooglePopups.clear();
}

/**
 * Unloads the Google Identity Services script tag from the DOM once authentication completes
 * so third-party script tags do not remain attached while the vault is unlocked (B7).
 */
export function unloadGoogleIdentityServices() {
  closeActiveGooglePopup();
  gisLoadingPromise = null;
  if (typeof document !== "undefined") {
    try {
      const scripts = document.querySelectorAll('script[src*="accounts.google.com/gsi/client"]');
      for (const s of scripts) {
        try { s.remove(); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
  }
}

if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
  window.addEventListener("pagehide", closeActiveGooglePopup);
  window.addEventListener("beforeunload", closeActiveGooglePopup);
}

export function resetGoogleAuthStateForTests() {
  gisLoadingPromise = null;
  googleAuthInFlight = false;
  closeActiveGooglePopup();
}

function loadGoogleIdentityServicesOnce(timeoutMs) {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return Promise.reject(new FirebaseError("SDK_UNAVAILABLE", "Google Sign-In requires a browser environment."));
  }
  if (window.google?.accounts?.oauth2) {
    return Promise.resolve(window.google.accounts);
  }
  if (typeof navigator !== "undefined" && navigator.onLine === false) {
    return Promise.reject(new FirebaseError("NETWORK", "You are currently offline. Please connect to the internet to continue with Google.", 0));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let timer = null;

    const cleanup = () => {
      if (timer) clearInterval(timer);
    };

    const done = (accounts) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(accounts);
    };

    const fail = (code, msg) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(new FirebaseError(
        code || "SDK_UNAVAILABLE",
        msg || "Could not load Google Sign-In SDK. If you are using Brave Shields or an ad blocker, please allow accounts.google.com and try again."
      ));
    };

    if (window.google?.accounts?.oauth2) {
      return done(window.google.accounts);
    }

    const existing = document.querySelector('script[src*="accounts.google.com/gsi/client"]');
    if (existing) {
      try { existing.remove(); } catch { /* ignore */ }
    }

    const script = document.createElement("script");
    script.src = "https://accounts.google.com/gsi/client";
    script.async = true;
    script.defer = true;
    script.onload = () => {
      if (window.google?.accounts?.oauth2) {
        done(window.google.accounts);
      }
    };
    script.onerror = () => {
      fail("SDK_UNAVAILABLE", "Could not load Google Sign-In SDK. If you are using Brave Shields or an ad blocker, please allow accounts.google.com and try again.");
    };

    const maxTicks = Math.max(5, Math.ceil(timeoutMs / 100));
    let ticks = 0;
    timer = setInterval(() => {
      if (window.google?.accounts?.oauth2) {
        done(window.google.accounts);
      } else if (++ticks >= maxTicks) {
        fail("SDK_UNAVAILABLE", "Google Sign-In SDK timed out while loading. Please check your connection or Brave Shields / ad blocker settings.");
      }
    }, 100);

    document.head.append(script);
  });
}

/**
 * Loads Google Identity Services (`https://accounts.google.com/gsi/client`) with a 15s default timeout
 * and one automatic retry on slow mobile networks (B23).
 */
export function loadGoogleIdentityServices({ timeoutMs = 15_000, retries = 1 } = {}) {
  if (typeof window !== "undefined" && window.google?.accounts?.oauth2) {
    return Promise.resolve(window.google.accounts);
  }
  if (gisLoadingPromise) return gisLoadingPromise;

  gisLoadingPromise = (async () => {
    try {
      return await loadGoogleIdentityServicesOnce(timeoutMs);
    } catch (firstErr) {
      if (retries > 0 && firstErr?.code === "SDK_UNAVAILABLE") {
        return await loadGoogleIdentityServicesOnce(timeoutMs);
      }
      throw firstErr;
    } finally {
      gisLoadingPromise = null;
    }
  })();

  return gisLoadingPromise;
}

/**
 * Pre-warms Google Identity Services when auth screens render so clicking "Continue with Google"
 * invokes the popup synchronously inside the user's click gesture.
 */
export function preloadGoogleIdentityServices() {
  if (typeof window === "undefined" || window.google?.accounts?.oauth2) return;
  loadGoogleIdentityServices({ timeoutMs: 15_000, retries: 1 }).catch(() => {});
}

export function consumeGoogleOAuthRedirectCallback() {
  return false;
}

function invokeWithTrackedWindowOpen(fn) {
  const origOpen = typeof window !== "undefined" && typeof window.open === "function" ? window.open : null;
  if (!origOpen) {
    return fn();
  }
  const patchedOpen = function (...args) {
    const popupWin = origOpen.apply(this, args);
    if (popupWin) trackedGooglePopups.add(popupWin);
    return popupWin;
  };
  window.open = patchedOpen;
  try {
    return fn();
  } finally {
    if (window.open === patchedOpen) {
      window.open = origOpen;
    }
  }
}

/**
 * Initiates official Google account selection using Google Identity Services (`initTokenClient`)
 * with minimal identity scopes (`openid email profile`) and `prompt: "select_account"`.
 * Tracks any opened popup window and closes it cleanly when sign-in finishes or errors out.
 */
export async function requestGoogleOAuthToken({ timeoutMs = 15_000 } = {}) {
  if (googleAuthInFlight) {
    throw new FirebaseError("DUPLICATE_REQUEST", "A Google Sign-In request is already in progress.");
  }
  if (typeof location !== "undefined" && location.protocol === "file:") {
    throw new FirebaseError("INVALID_ORIGIN", "Google Sign-In cannot run from a local file:// URL. Please use http://localhost or https://.");
  }
  if (typeof navigator !== "undefined" && navigator.onLine === false) {
    throw new FirebaseError("NETWORK", "You are currently offline. Please connect to the internet to continue with Google.", 0);
  }

  const cfg = getFirebaseConfig();
  const validation = validateFirebaseAndGoogleConfig(cfg);
  if (!validation.ok) {
    const firstIssue = validation.issues[0];
    throw new FirebaseError(firstIssue.code, firstIssue.message);
  }
  const clientId = String(cfg.googleClientId).trim();

  closeActiveGooglePopup();

  googleAuthInFlight = true;
  try {
    const accounts = window.google?.accounts?.oauth2
      ? window.google.accounts
      : await loadGoogleIdentityServices({ timeoutMs, retries: 1 });

    if (!accounts?.oauth2?.initTokenClient) {
      throw new FirebaseError("SDK_UNAVAILABLE", "Google Sign-In SDK could not be initialized.");
    }

    return await new Promise((resolve, reject) => {
      let settled = false;
      const done = (err, res) => {
        if (settled) return;
        settled = true;
        closeActiveGooglePopup();
        if (err) reject(err);
        else resolve(res);
      };

      try {
        const client = accounts.oauth2.initTokenClient({
          client_id: clientId,
          scope: "openid email profile",
          prompt: "select_account",
          callback: (tokenResponse) => {
            if (!tokenResponse) {
              return done(new FirebaseError("POPUP_CLOSED", "Google Sign-In did not return a response."));
            }
            if (tokenResponse.error) {
              const code = String(tokenResponse.error).toLowerCase();
              const desc = String(tokenResponse.error_description || "");
              if (code === "popup_closed_by_user" || code === "user_cancelled") {
                return done(new FirebaseError("POPUP_CLOSED", "Google Sign-In was cancelled before completing."));
              }
              if (code === "popup_failed_to_open") {
                return done(new FirebaseError("POPUP_BLOCKED", "Google Sign-In popup was blocked by your browser. Please allow popups for this site and try again."));
              }
              if (code === "redirect_uri_mismatch" || code === "origin_mismatch" || desc.toLowerCase().includes("origin")) {
                const currentOrigin = typeof location !== "undefined" && location.origin ? location.origin : "this domain";
                return done(new FirebaseError("REDIRECT_URI_MISMATCH", `This website's origin (${currentOrigin}) is not listed in Authorized JavaScript origins for your Google OAuth Client ID in Google Cloud Console.`));
              }
              if (code === "invalid_client" || code === "unauthorized_client") {
                return done(new FirebaseError("INVALID_OAUTH_CONFIG", "Google OAuth Client ID is invalid or not authorized in Google Cloud Console."));
              }
              if (code === "access_denied") {
                if (desc.toLowerCase().includes("policy") || desc.toLowerCase().includes("unverified") || desc.toLowerCase().includes("comply")) {
                  return done(new FirebaseError("UNVERIFIED_APP", "Google blocked sign-in because the OAuth Consent Screen is in testing mode or requires verification in Google Cloud Console."));
                }
                return done(new FirebaseError("POPUP_CLOSED", "Google Sign-In was cancelled or access was denied."));
              }
              return done(new FirebaseError(code.toUpperCase(), desc || "Google Sign-In failed."));
            }
            if (!tokenResponse.access_token && !tokenResponse.id_token) {
              return done(new FirebaseError("INVALID_IDP_RESPONSE", "Google Sign-In did not return an authentication token."));
            }
            done(null, {
              accessToken: tokenResponse.access_token || null,
              idToken: tokenResponse.id_token || null
            });
          },
          error_callback: (err) => {
            const type = String(err?.type || err?.error || "").toLowerCase();
            if (type === "popup_closed" || type === "popup_closed_by_user") {
              return done(new FirebaseError("POPUP_CLOSED", "Google Sign-In was cancelled before completing."));
            }
            if (type === "popup_failed_to_open") {
              return done(new FirebaseError("POPUP_BLOCKED", "Google Sign-In popup was blocked by your browser. Please allow popups for this site and try again."));
            }
            return done(new FirebaseError("GOOGLE_AUTH_ERROR", err?.message || "Google Sign-In could not be completed."));
          }
        });

        invokeWithTrackedWindowOpen(() => {
          const maybePromise = client.requestAccessToken({ prompt: "select_account" });
          if (maybePromise && typeof maybePromise.catch === "function") {
            maybePromise.catch((asyncErr) => {
              done(
                asyncErr instanceof FirebaseError
                  ? asyncErr
                  : new FirebaseError("GOOGLE_AUTH_ERROR", asyncErr?.message || "Could not start Google Sign-In.")
              );
            });
          }
        });
      } catch (initErr) {
        done(
          initErr instanceof FirebaseError
            ? initErr
            : new FirebaseError("GOOGLE_AUTH_ERROR", initErr?.message || "Could not start Google Sign-In.")
        );
      }
    });
  } finally {
    googleAuthInFlight = false;
  }
}

/* ============================================================================
 * Cloud Firestore Canonical Encrypted Vault Client (`users/{uid}`, `entries`, `tombstones`)
 * ============================================================================ */

function firestoreBaseUrl() {
  const { projectId, firestoreEmulatorHost } = getFirebaseConfig();
  if (firestoreEmulatorHost) {
    const host = String(firestoreEmulatorHost).replace(/^https?:\/\//, "").replace(/\/$/, "");
    return `http://${host}/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents`;
  }
  return `https://firestore.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/databases/(default)/documents`;
}

function toFirestoreFields(obj) {
  const fields = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined || v === null) continue;
    if (typeof v === "boolean") fields[k] = { booleanValue: v };
    else if (Number.isInteger(v)) fields[k] = { integerValue: String(v) };
    else if (typeof v === "number") fields[k] = { doubleValue: v };
    else if (typeof v === "string") fields[k] = { stringValue: v };
    else fields[k] = { stringValue: JSON.stringify(v) };
  }
  return { fields };
}

function fromFirestoreDoc(doc) {
  if (!doc || !doc.fields) return null;
  const out = {};
  for (const [k, val] of Object.entries(doc.fields)) {
    if ("stringValue" in val) out[k] = val.stringValue;
    else if ("integerValue" in val) out[k] = Number(val.integerValue);
    else if ("doubleValue" in val) out[k] = Number(val.doubleValue);
    else if ("booleanValue" in val) out[k] = Boolean(val.booleanValue);
  }
  if (doc.updateTime) out._updateTime = doc.updateTime;
  if (doc.createTime) out._createTime = doc.createTime;
  return out;
}

async function firestoreFetch(path, idToken, { method = "GET", body } = {}) {
  let res;
  try {
    res = await doFetch(`${firestoreBaseUrl()}${path}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        ...(idToken ? { Authorization: `Bearer ${idToken}` } : {})
      },
      body: body ? JSON.stringify(body) : undefined
    });
  } catch (err) {
    if (err instanceof FirebaseError) throw err;
    throw new FirebaseError("NETWORK", "Could not reach Cloud Firestore.", 0);
  }
  if (res.status === 404) return null;
  if (res.status === 204) return {};
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const rawStatus = String(data?.error?.status || "");
    const code = res.status === 403
      ? "PERMISSION_DENIED"
      : (res.status === 401
          ? "UNAUTHENTICATED"
          : (res.status === 409 || res.status === 412 || rawStatus === "FAILED_PRECONDITION" || rawStatus === "ABORTED"
              ? "FAILED_PRECONDITION"
              : "FIRESTORE_ERROR"));
    throw new FirebaseError(
      code,
      data?.error?.message || "Firestore operation failed.",
      res.status
    );
  }
  return data;
}

const lastUserDocState = new Map(); // uid -> { updateTime, createdAt, schemaVersion }

export async function firestoreGetVaultMetaOnly(uid, idToken) {
  return measureAsync("firestore_meta_read", async () => {
    const userDoc = await firestoreFetch(`/users/${encodeURIComponent(uid)}`, idToken);
    if (!userDoc) {
      lastUserDocState.delete(uid);
      return { meta: null, name: "", email: "", updateTime: null, createdAt: null, schemaVersion: 2 };
    }
    const parsedUser = fromFirestoreDoc(userDoc);
    let meta = null;
    if (parsedUser?.meta) {
      try {
        meta = typeof parsedUser.meta === "string" ? JSON.parse(parsedUser.meta) : parsedUser.meta;
      } catch {
        meta = null;
      }
    }
    const updateTime = userDoc.updateTime || parsedUser?._updateTime || null;
    const createdAt = Number(parsedUser?.createdAt || meta?.createdAt) || Date.now();
    const schemaVersion = Number(parsedUser?.schemaVersion) || 2;
    lastUserDocState.set(uid, { updateTime, createdAt, schemaVersion });
    if (meta && updateTime) {
      try { Object.defineProperty(meta, "_updateTime", { value: updateTime, enumerable: false, configurable: true, writable: true }); } catch { /* ignore */ }
    }
    return {
      meta,
      name: parsedUser?.name || "",
      email: parsedUser?.email || "",
      updateTime,
      createdAt,
      schemaVersion
    };
  });
}

export async function firestoreListAllEntries(uid, idToken, { pageSize = 500 } = {}) {
  return measureAsync("firestore_entries_read", async () => {
    const entries = [];
    let pageToken = "";
    let safetyPages = 0;

    do {
      const qs = `pageSize=${encodeURIComponent(pageSize)}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`;
      const listRes = await firestoreFetch(`/users/${encodeURIComponent(uid)}/entries?${qs}`, idToken);
      const docs = listRes?.documents || [];
      for (const d of docs) {
        const row = fromFirestoreDoc(d);
        if (row?.id && row?.iv && row?.data) {
          entries.push({
            id: row.id,
            iv: row.iv,
            data: row.data,
            updatedAt: Number(row.updatedAt) || 0,
            createdAt: Number(row.createdAt) || Number(row.updatedAt) || 0,
            rev: Number(row.rev) || 1,
            ciphertextHash: row.ciphertextHash || "",
            _updateTime: d.updateTime || row._updateTime || null
          });
        }
      }
      pageToken = listRes?.nextPageToken || "";
    } while (pageToken && ++safetyPages < 200);

    return entries;
  });
}

export async function firestoreListAllTombstones(uid, idToken, { pageSize = 500 } = {}) {
  const tombstones = {};
  let pageToken = "";
  let safetyPages = 0;

  do {
    const qs = `pageSize=${encodeURIComponent(pageSize)}${pageToken ? `&pageToken=${encodeURIComponent(pageToken)}` : ""}`;
    const listRes = await firestoreFetch(`/users/${encodeURIComponent(uid)}/tombstones?${qs}`, idToken).catch(() => null);
    const docs = listRes?.documents || [];
    for (const d of docs) {
      const row = fromFirestoreDoc(d);
      const docNameId = d.name ? decodeURIComponent(String(d.name).split("/").pop()) : null;
      const entryId = row?.id || docNameId;
      if (entryId && row?.deletedAt) {
        tombstones[entryId] = {
          deletedAt: Number(row.deletedAt) || Date.now(),
          deletedRev: Number(row.deletedRev) || 1,
          baseHash: String(row.baseHash || "").slice(0, 128)
        };
      }
    }
    pageToken = listRes?.nextPageToken || "";
  } while (pageToken && ++safetyPages < 200);

  return tombstones;
}

export async function firestorePutTombstone(uid, idToken, entryId, tomb) {
  return measureAsync("firestore_write", async () => {
    const payload = {
      deletedAt: Number(tomb?.deletedAt) || Date.now(),
      deletedRev: Number(tomb?.deletedRev) || 1,
      baseHash: String(tomb?.baseHash || "").slice(0, 128)
    };
    const maskParams = Object.keys(payload).map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`).join("&");
    await firestoreFetch(`/users/${encodeURIComponent(uid)}/tombstones/${encodeURIComponent(entryId)}?${maskParams}`, idToken, {
      method: "PATCH",
      body: toFirestoreFields(payload)
    });
  });
}

export async function firestoreDeleteTombstone(uid, idToken, entryId) {
  return measureAsync("firestore_write", async () => {
    await firestoreFetch(`/users/${encodeURIComponent(uid)}/tombstones/${encodeURIComponent(entryId)}`, idToken, {
      method: "DELETE"
    }).catch(() => {});
  });
}

export async function firestoreGetVault(uid, idToken, { pageSize = 500 } = {}) {
  const { meta, name, email, updateTime, createdAt, schemaVersion } = await firestoreGetVaultMetaOnly(uid, idToken);
  const [entries, tombstones] = await Promise.all([
    firestoreListAllEntries(uid, idToken, { pageSize }),
    firestoreListAllTombstones(uid, idToken, { pageSize })
  ]);
  return { meta, entries, tombstones, name, email, updateTime, createdAt, schemaVersion };
}

function mergeMetaOnConflict(localMeta, remoteMeta) {
  if (!remoteMeta) return localMeta;
  if (!localMeta) return remoteMeta;
  const localRev = Number(localMeta.metaRev) || 1;
  const remoteRev = Number(remoteMeta.metaRev) || 1;
  const mergedTombstones = {
    ...(remoteMeta.deletedEntries || {}),
    ...(localMeta.deletedEntries || {})
  };
  for (const [id, rTomb] of Object.entries(remoteMeta.deletedEntries || {})) {
    const lTomb = localMeta.deletedEntries?.[id];
    if (lTomb && (rTomb.deletedAt || 0) > (lTomb.deletedAt || 0)) {
      mergedTombstones[id] = rTomb;
    }
  }
  const winner = remoteRev > localRev ? { ...localMeta, ...remoteMeta } : { ...remoteMeta, ...localMeta };
  winner.metaRev = Math.max(localRev, remoteRev);
  if (Object.keys(mergedTombstones).length > 0 || winner.deletedEntries) {
    winner.deletedEntries = mergedTombstones;
  }
  return winner;
}

/**
 * Saves `/users/{uid}` metadata with `updateMask.fieldPaths`, `createdAt`, `schemaVersion: 2`,
 * and optimistic concurrency control (`currentDocument.updateTime`) with up to 3 merge retries on conflict (B5).
 */
export async function firestoreSaveMeta(uid, idToken, { email, name, meta, updateTime } = {}) {
  return measureAsync("firestore_write", async () => {
    let currentMeta = typeof meta === "string" ? JSON.parse(meta) : { ...meta };
    let knownState = lastUserDocState.get(uid) || null;
    let preconditionTime = updateTime !== undefined ? updateTime : ( currentMeta?._updateTime || knownState?.updateTime || null );

    for (let attempt = 1; attempt <= 3; attempt++) {
      const nowMs = Date.now();
      const createdAt = Number(knownState?.createdAt || currentMeta?.createdAt) || nowMs;
      const payload = {
        uid: String(uid),
        email: String(email || currentMeta?.accountEmail || "").trim().toLowerCase(),
        name: String(name || currentMeta?.accountName || ""),
        meta: JSON.stringify(currentMeta),
        updatedAt: nowMs,
        createdAt,
        schemaVersion: 2
      };

      const queryParts = Object.keys(payload).map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`);
      if (preconditionTime) {
        queryParts.push(`currentDocument.updateTime=${encodeURIComponent(preconditionTime)}`);
      }
      const qs = queryParts.join("&");

      try {
        const savedDoc = await firestoreFetch(`/users/${encodeURIComponent(uid)}?${qs}`, idToken, {
          method: "PATCH",
          body: toFirestoreFields(payload)
        });
        const newUpdateTime = savedDoc?.updateTime || null;
        lastUserDocState.set(uid, { updateTime: newUpdateTime, createdAt, schemaVersion: 2 });
        if (currentMeta && typeof currentMeta === "object" && newUpdateTime) {
          try { Object.defineProperty(currentMeta, "_updateTime", { value: newUpdateTime, enumerable: false, configurable: true, writable: true }); } catch { /* ignore */ }
        }
        return { meta: currentMeta, updateTime: newUpdateTime };
      } catch (err) {
        if (err?.code === "FAILED_PRECONDITION" && attempt < 3) {
          const latest = await firestoreGetVaultMetaOnly(uid, idToken);
          knownState = lastUserDocState.get(uid) || null;
          preconditionTime = latest.updateTime || null;
          currentMeta = mergeMetaOnConflict(currentMeta, latest.meta);
          continue;
        }
        throw err;
      }
    }
  });
}

export async function firestorePutEntry(uid, idToken, rec, { updateTime } = {}) {
  return measureAsync("firestore_write", async () => {
    let currentRec = { ...rec };
    let preconditionTime = updateTime !== undefined ? updateTime : (currentRec._updateTime || null);

    for (let attempt = 1; attempt <= 3; attempt++) {
      const nowMs = Number(currentRec.updatedAt) || Date.now();
      const createdAt = Number(currentRec.createdAt) || nowMs;
      const payload = {
        id: currentRec.id,
        iv: currentRec.iv,
        data: currentRec.data,
        updatedAt: nowMs,
        createdAt
      };
      if (Number.isInteger(currentRec.rev) && currentRec.rev >= 0) payload.rev = currentRec.rev;
      if (typeof currentRec.ciphertextHash === "string" && currentRec.ciphertextHash) payload.ciphertextHash = currentRec.ciphertextHash;

      const queryParts = Object.keys(payload).map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`);
      if (preconditionTime) {
        queryParts.push(`currentDocument.updateTime=${encodeURIComponent(preconditionTime)}`);
      }
      const qs = queryParts.join("&");

      try {
        const saved = await firestoreFetch(`/users/${encodeURIComponent(uid)}/entries/${encodeURIComponent(currentRec.id)}?${qs}`, idToken, {
          method: "PATCH",
          body: toFirestoreFields(payload)
        });
        return saved;
      } catch (err) {
        if (err?.code === "FAILED_PRECONDITION" && attempt < 3) {
          const existingDoc = await firestoreFetch(`/users/${encodeURIComponent(uid)}/entries/${encodeURIComponent(currentRec.id)}`, idToken).catch(() => null);
          if (!existingDoc) {
            preconditionTime = null;
            continue;
          }
          const parsed = fromFirestoreDoc(existingDoc);
          preconditionTime = existingDoc.updateTime || null;
          if (parsed && (Number(parsed.rev) || 0) > (Number(currentRec.rev) || 0)) {
            currentRec = { ...currentRec, ...parsed, rev: Number(parsed.rev) };
            return existingDoc;
          }
          currentRec.rev = Math.max(Number(currentRec.rev) || 1, (Number(parsed?.rev) || 1) + 1);
          continue;
        }
        throw err;
      }
    }
  });
}

export async function firestoreBatchPutEntries(uid, idToken, records = [], { concurrency = 25 } = {}) {
  for (let i = 0; i < records.length; i += concurrency) {
    const chunk = records.slice(i, i + concurrency);
    await Promise.all(chunk.map((rec) => firestorePutEntry(uid, idToken, rec)));
  }
  return { saved: records.length };
}

export async function firestoreDeleteEntry(uid, idToken, entryId) {
  return measureAsync("firestore_write", async () => {
    await firestoreFetch(`/users/${encodeURIComponent(uid)}/entries/${encodeURIComponent(entryId)}`, idToken, {
      method: "DELETE"
    });
  });
}

/**
 * Deletes a batch of Firestore document names in a single `:commit` request (≤ 500 writes per commit, B12),
 * falling back to individual DELETE calls if `:commit` is unsupported by a custom mock.
 */
async function firestoreBatchDeleteDocNames(uid, idToken, docNames = []) {
  if (!docNames.length) return;
  const { projectId } = getFirebaseConfig();
  const fullNames = docNames.map((n) =>
    n.startsWith("projects/")
      ? n
      : `projects/${projectId}/databases/(default)/documents/${n.replace(/^\//, "")}`
  );
  try {
    await firestoreFetch(`:commit`, idToken, {
      method: "POST",
      body: {
        writes: fullNames.map((name) => ({ delete: name }))
      }
    });
  } catch (err) {
    if (err?.status === 404) {
      for (const name of fullNames) {
        const rel = name.split("/documents")[1];
        if (rel) {
          await firestoreFetch(rel, idToken, { method: "DELETE" });
        }
      }
      return;
    }
    throw err;
  }
}

export async function firestoreDeleteVault(uid, idToken, { pageSize = 500, onStage, onProgress } = {}) {
  if (!uid || !idToken) {
    throw new FirebaseError("UNAUTHENTICATED", "Valid UID and authentication token are required to delete cloud vault.", 401);
  }

  await onStage?.("deleting_entries");
  let deletedCount = 0;
  let safetyLoops = 0;

  while (safetyLoops++ < 100) {
    const listRes = await firestoreFetch(`/users/${encodeURIComponent(uid)}/entries?pageSize=${encodeURIComponent(pageSize)}`, idToken);
    const docs = listRes?.documents || [];
    if (!docs.length) break;
    const docNames = docs.map((d) => {
      if (d.name) return d.name;
      const row = fromFirestoreDoc(d);
      return `users/${encodeURIComponent(uid)}/entries/${encodeURIComponent(row?.id)}`;
    }).filter(Boolean);

    for (let i = 0; i < docNames.length; i += 500) {
      const batch = docNames.slice(i, i + 500);
      await firestoreBatchDeleteDocNames(uid, idToken, batch);
      deletedCount += batch.length;
      await onProgress?.({ deletedCount });
    }

    if (!listRes?.nextPageToken && docs.length < pageSize) {
      const verifyList = await firestoreFetch(`/users/${encodeURIComponent(uid)}/entries?pageSize=1`, idToken);
      if (!verifyList?.documents?.length) break;
    }
  }

  // Also clean up any tombstones subcollection documents
  let tombLoops = 0;
  while (tombLoops++ < 50) {
    const tList = await firestoreFetch(`/users/${encodeURIComponent(uid)}/tombstones?pageSize=${encodeURIComponent(pageSize)}`, idToken).catch(() => null);
    const tDocs = tList?.documents || [];
    if (!tDocs.length) break;
    const tNames = tDocs.map((d) => d.name).filter(Boolean);
    for (let i = 0; i < tNames.length; i += 500) {
      await firestoreBatchDeleteDocNames(uid, idToken, tNames.slice(i, i + 500)).catch(() => {});
    }
    if (!tList?.nextPageToken && tDocs.length < pageSize) break;
  }

  await onStage?.("deleting_profile");
  await firestoreFetch(`/users/${encodeURIComponent(uid)}`, idToken, { method: "DELETE" });
  lastUserDocState.delete(uid);

  await onStage?.("verifying");
  const checkUser = await firestoreFetch(`/users/${encodeURIComponent(uid)}`, idToken);
  const checkEntries = await firestoreFetch(`/users/${encodeURIComponent(uid)}/entries?pageSize=1`, idToken);
  if (checkUser !== null || (checkEntries?.documents && checkEntries.documents.length > 0)) {
    throw new FirebaseError(
      "DELETION_VERIFICATION_FAILED",
      "Cloud Firestore records were not completely removed during verification.",
      500
    );
  }

  return { verifiedEmpty: true, deletedCount };
}

export { isFirebaseConfigured, validateFirebaseAndGoogleConfig };
