const wait = (s) => {
  s = Math.max(1, Math.ceil(s));
  return s >= 60 ? `${Math.ceil(s / 60)} min` : `${s}s`;
};

const MAX_DIAGNOSTIC_LOGS = 100;
const diagnosticRingBuffer = [];

/**
 * Generates a non-sensitive diagnostic correlation ID (`kvx-<timestamp>-<random>`).
 */
export function createCorrelationId() {
  const t = Date.now().toString(36);
  const r = Math.random().toString(36).slice(2, 8);
  return `kvx-${t}-${r}`;
}

/**
 * Classifies an error into a distinct, observable diagnostic category without leaking secrets.
 */
export function classifyError(err) {
  const code = String(err?.code || err?.name || "UNKNOWN_ERROR").toUpperCase();
  const status = Number(err?.status) || 0;

  if (code === "VAULT_WRONG_PASSKEY" || code === "BAD_PASSKEY" || (code === "BAD_CREDENTIALS" && err?.context === "passkey")) {
    return "VAULT_WRONG_PASSKEY";
  }
  if (code === "INVALID_PASSWORD" || code === "INVALID_LOGIN_CREDENTIALS" || code === "BAD_CREDENTIALS") {
    return "AUTH_WRONG_PASSWORD";
  }
  if (code === "SESSION_EXPIRED" || code === "TOKEN_EXPIRED" || code === "INVALID_ID_TOKEN" || code === "CREDENTIAL_TOO_OLD_LOGIN_AGAIN" || code === "UNAUTHENTICATED") {
    return "SESSION_EXPIRED";
  }
  if (code === "NETWORK" || code === "FETCH_ERROR" || code === "TIMEOUT" || (err?.name === "TypeError" && String(err.message).includes("fetch"))) {
    return "NETWORK_OUTAGE";
  }
  if (code === "PERMISSION_DENIED" || code === "FIRESTORE_PERMISSION" || code === "FIRESTORE_ERROR" || status === 403) {
    return "FIRESTORE_PERMISSION";
  }
  if (code === "BAD_VAULT" || code === "CORRUPTED_BACKUP" || code === "MIGRATION_CORRUPT_ENTRY" || code === "DECRYPTION_FAILED" || code === "KDF_ERROR") {
    return "CRYPTO_DECRYPTION_FAILURE";
  }
  if (code === "UI_RENDER_FAILURE") {
    return "UI_RENDER_FAILURE";
  }
  if (code === "DELETION_INCOMPLETE") {
    return "DELETION_INCOMPLETE";
  }
  return "APPLICATION_ERROR";
}

/**
 * Logs auth/vault/UI errors with sanitized code, category, and correlationId.
 * Never logs passwords, PINs, tokens, emails, or plaintext vault entries.
 */
export function logAuthError(tag, err) {
  const correlationId = err?.correlationId || createCorrelationId();
  if (err && typeof err === "object" && !err.correlationId) {
    try { err.correlationId = correlationId; } catch { /* frozen err */ }
  }
  const code = String(err?.code || err?.name || "ERROR").toUpperCase();
  const category = classifyError(err);
  const status = err?.status !== undefined ? Number(err.status) : null;
  const entry = {
    correlationId,
    tag: String(tag || "app"),
    category,
    code,
    status,
    timestamp: Date.now()
  };
  diagnosticRingBuffer.push(entry);
  if (diagnosticRingBuffer.length > MAX_DIAGNOSTIC_LOGS) {
    diagnosticRingBuffer.shift();
  }
  try {
    if (typeof process === "undefined" || process.env?.NODE_ENV !== "test") {
      // eslint-disable-next-line no-console
      console.error(`[KeyVEX ${entry.tag}]`, entry);
    }
  } catch { /* ignore */ }
  return correlationId;
}

export function getDiagnosticLogs() {
  return [...diagnosticRingBuffer];
}

export function clearDiagnosticLogs() {
  diagnosticRingBuffer.length = 0;
}

/**
 * Friendly text for errors from the Vault / Firebase / Google OAuth / IndexedDB.
 */
export function errText(err) {
  if (!err) return "An unexpected error occurred. Please try again.";

  const code = String(err?.code || err?.name || "").toUpperCase();

  if (code === "LOCKED_OUT" || code === "RATE_LIMITED" || code === "TOO_MANY_ATTEMPTS_TRY_LATER") {
    return `Too many attempts. Try again in ${wait(err.retryAfter || 30)}.`;
  }
  if (code === "VAULT_WRONG_PASSKEY" || code === "BAD_PASSKEY" || (code === "BAD_CREDENTIALS" && err?.context === "passkey")) {
    if (Number.isFinite(err.attemptsLeft) && err.attemptsLeft <= 3) {
      return `Incorrect Passkey. ${err.attemptsLeft} ${err.attemptsLeft === 1 ? "try" : "tries"} left before temporary lockout.`;
    }
    return "Incorrect Passkey. Please try again.";
  }
  if (code === "PASSKEY_CHANGED_REMOTELY") {
    return "Passkey was changed on another device. Please enter your new Passkey.";
  }
  if (code === "BAD_CREDENTIALS" || code === "INVALID_LOGIN_CREDENTIALS" || code === "INVALID_PASSWORD") {
    if (err.retryAfter > 0) return `Incorrect credentials. Too many tries — wait ${wait(err.retryAfter)} before trying again.`;
    if (Number.isFinite(err.attemptsLeft) && err.attemptsLeft <= 3) {
      return `Incorrect credentials. ${err.attemptsLeft} ${err.attemptsLeft === 1 ? "try" : "tries"} left before a short lock.`;
    }
    return err.message && !err.message.includes("wrong")
      ? err.message
      : "Incorrect email or password. Please try again.";
  }
  if (code === "NETWORK" || code === "FETCH_ERROR" || code === "TIMEOUT" || (err?.name === "TypeError" && String(err.message).includes("fetch"))) {
    return "Could not reach the server. Please check your internet connection and try again.";
  }
  if (code === "PERMISSION_DENIED" || code === "FIRESTORE_PERMISSION") {
    return "Cloud vault access was denied by security rules. Please verify your email or sign in again.";
  }
  if (code === "FIRESTORE_ERROR") {
    return "Cloud vault service returned an error. Your local encrypted data remains safe.";
  }
  if (code === "BAD_VAULT" || code === "DECRYPTION_FAILED" || code === "KDF_ERROR") {
    return err.message || "Vault decryption failed due to incompatible or corrupted metadata. Your encrypted data has been preserved.";
  }
  if (code === "FILE_TOO_LARGE") {
    return err.message || "File exceeds the 10 MB safety limit.";
  }
  if (code === "DELETION_INCOMPLETE") {
    return err.message || "Account deletion is pending completion. Please retry to finish removing remaining records.";
  }
  if (code === "ACCOUNT_CONFLICT_PASSWORD" || code === "ACCOUNT_CONFLICT") {
    return "An account with this email already exists with a password. Please verify your password to link your Google account.";
  }
  if (code === "GOOGLE_ACCOUNT_ONLY") {
    return "This email is registered with Google Sign-In. Please click 'Continue with Google' to sign in.";
  }
  if (code === "ACCOUNT_EXISTS" || code === "EMAIL_EXISTS") {
    return err.message || "An account with this email already exists. Please sign in instead.";
  }
  if (code === "EMAIL_NOT_FOUND" || code === "USER_NOT_FOUND") {
    return "No account found with this email. Please create an account first.";
  }
  if (code === "USER_DISABLED") {
    return "This account has been disabled. Please contact support.";
  }
  if (code === "INVALID_EMAIL") {
    return "Please enter a valid email address.";
  }
  if (code === "INVALID_NAME") {
    return "Please enter your full name.";
  }
  if (code === "EMAIL_NOT_VERIFIED") {
    return "Please verify your email address. Check your inbox for the verification link.";
  }
  if (code === "OPERATION_NOT_ALLOWED") {
    return "This sign-in method is not enabled in Firebase Console.";
  }
  if (code === "SESSION_EXPIRED" || code === "TOKEN_EXPIRED" || code === "INVALID_ID_TOKEN") {
    return "Your session has expired. Please sign in again.";
  }
  if (code === "QUOTA_EXCEEDED" || code === "QUOTAEXCEEDEDERROR" || code === "IDB_ERROR") {
    return "Your browser blocked or ran out of local storage space. Please enable storage and try again.";
  }
  if (code === "POPUP_CLOSED") {
    return "Google Sign-In was cancelled before completing.";
  }
  if (code === "POPUP_BLOCKED") {
    return "Your browser blocked the Google Sign-In popup. Please allow popups for this site and try again.";
  }
  if (code === "SDK_UNAVAILABLE") {
    return "Could not load Google Sign-In SDK. If you are using Brave Shields or an ad blocker, please allow accounts.google.com and try again.";
  }
  if (code === "REDIRECT_URI_MISMATCH" || code === "ORIGIN_MISMATCH") {
    return "Google OAuth origin or redirect URI is not authorized for this domain in Google Cloud Console.";
  }
  if (code === "UNVERIFIED_APP" || code === "ACCESS_DENIED_POLICY") {
    return "Google blocked sign-in due to OAuth app verification or consent-screen policy settings in Google Cloud Console.";
  }
  if (code === "GOOGLE_NOT_CONFIGURED" || code === "INVALID_OAUTH_CONFIG" || code === "API_KEY_INVALID") {
    return "Google Sign-In is not configured properly. Please check your OAuth Client ID / Firebase configuration or sign in with Email & Password.";
  }
  if (code === "DUPLICATE_REQUEST") {
    return "A sign-in request is already in progress. Please wait.";
  }

  const msg = typeof err?.message === "string" ? err.message.trim() : "";
  if (msg && !msg.toLowerCase().includes("something went wrong") && !msg.toLowerCase().includes("something wrong") && !/^[A-Z0-9_]+$/.test(msg)) {
    return msg;
  }

  return "Unable to complete authentication request. Please check your details and try again.";
}
