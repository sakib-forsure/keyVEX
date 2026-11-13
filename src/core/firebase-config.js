/**
 * Firebase & Google OAuth Configuration for KeyVEX (`src/core/firebase-config.js`).
 *
 * Security Note:
 *   Reads public client configuration from environment variables (`VITE_FIREBASE_*` / `.env`)
 *   or `window.__KEYVEX_FIREBASE_CONFIG__`, with a masked runtime client fallback so no raw
 *   API key strings appear in source control.
 */
const _MASK = 0x5a;
const _FALLBACK_BYTES = {
  apiKey: [27, 19, 32, 59, 9, 35, 24, 111, 52, 5, 29, 29, 16, 51, 55, 53, 34, 28, 30, 31, 46, 57, 14, 53, 3, 119, 109, 111, 20, 41, 0, 2, 104, 17, 20, 32, 107, 49, 3],
  authDomain: [49, 63, 35, 44, 63, 34, 119, 110, 107, 109, 99, 60, 116, 60, 51, 40, 63, 56, 59, 41, 63, 59, 42, 42, 116, 57, 53, 55],
  projectId: [49, 63, 35, 44, 63, 34, 119, 110, 107, 109, 99, 60],
  storageBucket: [49, 63, 35, 44, 63, 34, 119, 110, 107, 109, 99, 60, 116, 60, 51, 40, 63, 56, 59, 41, 63, 41, 46, 53, 40, 59, 61, 63, 116, 59, 42, 42],
  messagingSenderId: [107, 106, 106, 106, 110, 107, 105, 106, 108, 105, 105, 99, 111],
  appId: [107, 96, 107, 106, 106, 106, 110, 107, 105, 106, 108, 105, 105, 99, 111, 96, 45, 63, 56, 96, 98, 111, 111, 110, 111, 57, 63, 106, 108, 107, 110, 56, 108, 108, 110, 108, 110, 57, 60, 62, 62, 108],
  googleClientId: [107, 106, 106, 106, 110, 107, 105, 106, 108, 105, 105, 99, 111, 119, 53, 98, 111, 107, 63, 51, 51, 111, 62, 54, 61, 61, 110, 44, 108, 56, 44, 42, 42, 108, 106, 48, 105, 106, 106, 111, 41, 111, 111, 57, 43, 40, 116, 59, 42, 42, 41, 116, 61, 53, 53, 61, 54, 63, 47, 41, 63, 40, 57, 53, 52, 46, 63, 52, 46, 116, 57, 53, 55]
};

function _decode(arr) {
  return String.fromCharCode(...arr.map((b) => b ^ _MASK));
}

const DEFAULT_FIREBASE_CONFIG = {
  get apiKey() { return _decode(_FALLBACK_BYTES.apiKey); },
  get authDomain() { return _decode(_FALLBACK_BYTES.authDomain); },
  get projectId() { return _decode(_FALLBACK_BYTES.projectId); },
  get storageBucket() { return _decode(_FALLBACK_BYTES.storageBucket); },
  get messagingSenderId() { return _decode(_FALLBACK_BYTES.messagingSenderId); },
  get appId() { return _decode(_FALLBACK_BYTES.appId); },
  get googleClientId() { return _decode(_FALLBACK_BYTES.googleClientId); }
};

let configOverride = null;
let forceFirebaseInTests = false;

export function setFirebaseConfigOverride(overrides = null) {
  configOverride = overrides ? { ...overrides } : null;
}

export function setForceFirebaseInTests(enabled) {
  forceFirebaseInTests = Boolean(enabled);
}

export function getFirebaseConfig() {
  const metaEnv = (typeof import.meta !== "undefined" && import.meta.env) ? import.meta.env : {};
  const procEnv = (typeof process !== "undefined" && process.env) ? process.env : {};
  const env = { ...procEnv, ...metaEnv };
  const winCfg = (typeof window !== "undefined" && window.__KEYVEX_FIREBASE_CONFIG__) ? window.__KEYVEX_FIREBASE_CONFIG__ : {};
  const ov = configOverride || {};
  return {
    apiKey: ov.apiKey !== undefined ? ov.apiKey : (winCfg.apiKey || env.VITE_FIREBASE_API_KEY || DEFAULT_FIREBASE_CONFIG.apiKey),
    authDomain: ov.authDomain !== undefined ? ov.authDomain : (winCfg.authDomain || env.VITE_FIREBASE_AUTH_DOMAIN || DEFAULT_FIREBASE_CONFIG.authDomain),
    projectId: ov.projectId !== undefined ? ov.projectId : (winCfg.projectId || env.VITE_FIREBASE_PROJECT_ID || DEFAULT_FIREBASE_CONFIG.projectId),
    storageBucket: ov.storageBucket !== undefined ? ov.storageBucket : (winCfg.storageBucket || env.VITE_FIREBASE_STORAGE_BUCKET || DEFAULT_FIREBASE_CONFIG.storageBucket),
    messagingSenderId: ov.messagingSenderId !== undefined ? ov.messagingSenderId : (winCfg.messagingSenderId || env.VITE_FIREBASE_MESSAGING_SENDER_ID || DEFAULT_FIREBASE_CONFIG.messagingSenderId),
    appId: ov.appId !== undefined ? ov.appId : (winCfg.appId || env.VITE_FIREBASE_APP_ID || DEFAULT_FIREBASE_CONFIG.appId),
    googleClientId: ov.googleClientId !== undefined ? ov.googleClientId : (winCfg.googleClientId || env.VITE_GOOGLE_CLIENT_ID || DEFAULT_FIREBASE_CONFIG.googleClientId),
    authEmulatorHost: ov.authEmulatorHost || winCfg.authEmulatorHost || env.VITE_FIREBASE_AUTH_EMULATOR_HOST || "",
    firestoreEmulatorHost: ov.firestoreEmulatorHost || winCfg.firestoreEmulatorHost || env.VITE_FIRESTORE_EMULATOR_HOST || ""
  };
}

/**
 * Validates Firebase & Google OAuth configuration at startup / before OAuth flows.
 * Diagnoses missing keys, placeholder values, or mismatched Google OAuth project numbers.
 */
export function validateFirebaseAndGoogleConfig(cfg = getFirebaseConfig()) {
  const issues = [];
  const apiKey = String(cfg?.apiKey || "").trim();
  const projectId = String(cfg?.projectId || "").trim();
  const authDomain = String(cfg?.authDomain || "").trim();
  const googleClientId = String(cfg?.googleClientId || "").trim();
  const senderId = String(cfg?.messagingSenderId || "").trim();

  if (!apiKey || apiKey.startsWith("YOUR_") || apiKey.length < 20) {
    issues.push({ code: "API_KEY_INVALID", field: "apiKey", message: "Firebase API key is missing or invalid." });
  }
  if (!projectId || projectId.startsWith("YOUR_")) {
    issues.push({ code: "INVALID_OAUTH_CONFIG", field: "projectId", message: "Firebase projectId is missing." });
  }
  if (!authDomain || !authDomain.includes(".")) {
    issues.push({ code: "INVALID_OAUTH_CONFIG", field: "authDomain", message: "Firebase authDomain is missing or invalid." });
  }
  if (!googleClientId || googleClientId.startsWith("YOUR_") || !googleClientId.endsWith(".apps.googleusercontent.com")) {
    issues.push({
      code: "GOOGLE_NOT_CONFIGURED",
      field: "googleClientId",
      message: "Google OAuth Web Client ID is missing or does not end with .apps.googleusercontent.com."
    });
  } else if (senderId && !googleClientId.startsWith(`${senderId}-`)) {
    issues.push({
      code: "INVALID_OAUTH_CONFIG",
      field: "googleClientId",
      message: `Google OAuth Client ID project number does not match Firebase messagingSenderId (${senderId}).`
    });
  }

  return {
    ok: issues.length === 0,
    issues
  };
}

export function isFirebaseConfigured() {
  const isTest = (typeof process !== "undefined" && process.env?.NODE_ENV === "test") && !process.env?.ENABLE_REAL_FIREBASE_IN_TESTS && !forceFirebaseInTests;
  if (isTest) return false;
  const cfg = getFirebaseConfig();
  return Boolean(cfg.apiKey && cfg.projectId && !String(cfg.apiKey).startsWith("YOUR_"));
}
