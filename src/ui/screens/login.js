import { h, svg } from "../dom.js";
import { icon } from "../icons.js";
import { brand } from "../components/brand.js";
import { field, passwordField, pinField, notice } from "../components/fields.js";
import { openSheet, setBusy } from "../components/sheet.js";
import { masterPasswordSetup } from "../components/masterfield.js";
import { toast } from "../components/feedback.js";
import { errText, logAuthError } from "../errors.js";
import {
  loadGoogleIdentityServices,
  preloadGoogleIdentityServices,
  requestGoogleOAuthToken,
  isGoogleAuthInFlight,
  closeActiveGooglePopup,
  unloadGoogleIdentityServices
} from "../../core/firebase.js";
import { verifyTotpCode } from "../../core/totp.js";

export { loadGoogleIdentityServices };

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const GOOGLE_G_SVG = `<path fill="#4285F4" d="M21.6 12.2c0-.7-.1-1.4-.2-2H12v3.9h5.4a4.6 4.6 0 0 1-2 3v2.5h3.2c1.9-1.7 3-4.3 3-7.4z"/><path fill="#34A853" d="M12 22c2.7 0 5-.9 6.6-2.4l-3.2-2.5c-.9.6-2 1-3.4 1-2.6 0-4.8-1.8-5.6-4.2H3.1v2.6A10 10 0 0 0 12 22z"/><path fill="#FBBC05" d="M6.4 13.9a6 6 0 0 1 0-3.8V7.5H3.1a10 10 0 0 0 0 9l3.3-2.6z"/><path fill="#EA4335" d="M12 5.9c1.5 0 2.8.5 3.8 1.5L18.7 4.5A10 10 0 0 0 3.1 7.5l3.3 2.6C7.2 7.7 9.4 5.9 12 5.9z"/>`;

/**
 * Modal sheet for verifying ownership of an existing Email/Password account
 * before linking Google Sign-In to the same Firebase UID (Phase 5).
 */
export function showLinkGoogleAccountSheet(ctx, pendingGoogle = {}, onComplete) {
  const targetEmail = String(pendingGoogle?.email || "").trim().toLowerCase();
  const pwField = passwordField({
    label: "Existing Account Password",
    name: "link-account-password",
    autocomplete: "current-password",
    autofocus: true,
    placeholder: "Enter your KeyVEX password"
  });
  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Verify & Link Google Account");

  const sheet = openSheet({
    title: "Link Google to Your Account",
    content: h("form", {
      novalidate: true,
      class: "flow",
      onsubmit: async (e) => {
        e.preventDefault();
        msg.replaceChildren();
        const pw = pwField.input.value;
        if (!pw) {
          msg.replaceChildren(notice("err", "Please enter your existing account password to verify ownership."));
          pwField.input.focus();
          return;
        }
        setBusy(btn, true, "Verifying & linking…");
        try {
          const acct = await ctx.vault.linkGoogleProvider({
            email: targetEmail,
            password: pw,
            pendingGoogle
          });
          pwField.input.value = "";
          setBusy(btn, false);
          sheet.close();
          toast(`Google linked to ${acct.email}`);
          onComplete ? onComplete(acct) : ctx.go("passkey");
        } catch (err) {
          setBusy(btn, false);
          logAuthError("linkGoogleProvider", err);
          msg.replaceChildren(notice("err", errText(err)));
        }
      }
    },
      notice("info", `An account for ${targetEmail || "this email"} already exists with a password. Enter your password once to verify ownership and link Google Sign-In.`),
      pwField.root,
      msg,
      btn
    )
  });
  return sheet;
}

/**
 * Optional sheet (used from Settings) for Google users who wish to add an Email/Password login method.
 * PART 4: Requires the user's current Passkey first.
 */
export function showSetAccountPasswordSheet(ctx, onComplete) {
  const acct = ctx.vault.account;
  const acctPinLen = acct?.pinLength || acct?.meta?.pinLength || 6;
  const curPasskey = pinField({
    label: "Enter your Passkey",
    name: "current-passkey",
    length: acctPinLen,
    autofocus: true
  });
  const master = masterPasswordSetup({
    label: "Account Password",
    name: "new-password",
    autofocus: false,
    getPin: () => curPasskey.input.value
  });
  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Save password");

  const sheet = openSheet({
    title: "Set an account password",
    content: h("form", {
      novalidate: true,
      class: "flow",
      onsubmit: async (e) => {
        e.preventDefault();
        msg.replaceChildren();
        if (!curPasskey.input.value) {
          msg.replaceChildren(notice("err", "Enter your current Passkey to continue."));
          curPasskey.input.focus();
          return;
        }
        const m = master.validate();
        if (!m.ok) {
          msg.replaceChildren(notice("err", m.hint));
          return;
        }
        setBusy(btn, true, "Saving password…");
        try {
          await ctx.vault.setAccountPassword(curPasskey.input.value, master.value);
          setBusy(btn, false);
          sheet.close();
          toast("Password saved. You can now sign in with Email & Password or Google.");
          onComplete?.();
        } catch (err) {
          setBusy(btn, false);
          logAuthError("setAccountPassword", err);
          msg.replaceChildren(notice("err", errText(err)));
        }
      }
    },
      h("p", { class: "muted small flow-sub" }, "Enter your Passkey and link a password so you can sign in using your email and password in addition to Google."),
      curPasskey.root,
      master.root,
      msg,
      btn
    )
  });
  return sheet;
}

/**
 * Dedicated Forgot Password sheet (`Login -> Forgot Password -> Enter Email -> Firebase Password Reset -> Confirmation`).
 * Neutral confirmation wording prevents email enumeration (B23).
 */
export function showForgotPasswordSheet(ctx, initialEmail = "", onResetSent) {
  const emailIn = field({
    label: "Email Address",
    name: "reset-email",
    type: "email",
    inputmode: "email",
    autocomplete: "email",
    autofocus: true,
    placeholder: "you@gmail.com"
  });
  if (initialEmail) emailIn.input.value = String(initialEmail).trim();

  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Send Password Reset Email");

  const sheet = openSheet({
    title: "Reset your password",
    content: h("form", {
      novalidate: true,
      class: "flow",
      onsubmit: async (e) => {
        e.preventDefault();
        msg.replaceChildren();
        const em = emailIn.input.value.trim().toLowerCase();
        if (!EMAIL_RE.test(em)) {
          msg.replaceChildren(notice("err", "Please enter a valid email address."));
          emailIn.input.focus();
          return;
        }
        setBusy(btn, true, "Sending reset link…");
        try {
          await ctx.vault.sendPasswordResetEmail(em);
          setBusy(btn, false);
          const confText = `If an account exists for ${em}, a password reset link has been sent. Please check your inbox and spam folder.`;
          msg.replaceChildren(notice("info", confText));
          toast("Password reset email sent");
          onResetSent?.(em, confText);
        } catch (err) {
          setBusy(btn, false);
          logAuthError("sendPasswordResetEmail", err);
          msg.replaceChildren(notice("err", errText(err)));
        }
      }
    },
      h("p", { class: "muted small flow-sub" }, "Enter the email address for your KeyVEX account. We’ll send a link to reset your login password. Your encrypted vault and Passkey remain protected."),
      emailIn.root,
      msg,
      btn
    )
  });
  return sheet;
}

/**
 * F5 & B13: App-level lock (UI only) prompt sheet with replay protection, 5-try lockout, and 8 one-time backup code support.
 */
function showTotpPromptSheet(ctx, secret, onVerified) {
  let useBackupMode = false;
  const totpInput = pinField({
    label: "6-Digit Authenticator Code",
    name: "totp-code",
    length: 6,
    placeholder: "000000",
    autofocus: true,
    autocomplete: "one-time-code",
    hint: "Enter the 6-digit code from your Authenticator app."
  });
  const backupInput = field({
    label: "One-Time Backup Code",
    name: "totp-backup-code",
    placeholder: "XXXX-XXXX",
    autocomplete: "off",
    hint: "Enter one of the 8 backup codes you saved when enabling App-level lock."
  });
  backupInput.root.hidden = true;

  const modeBtn = h("button", {
    class: "link small",
    type: "button",
    onclick: () => {
      useBackupMode = !useBackupMode;
      totpInput.root.hidden = useBackupMode;
      backupInput.root.hidden = !useBackupMode;
      modeBtn.textContent = useBackupMode ? "Use 6-digit Authenticator code instead" : "Lost your phone? Use a backup code";
      msg.replaceChildren();
      (useBackupMode ? backupInput.input : totpInput.input).focus();
    }
  }, "Lost your phone? Use a backup code");

  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
  const submitBtn = h("button", { class: "btn primary", type: "submit" }, "Verify Code");

  let sheet;
  let verified = false;

  const form = h("form", {
    novalidate: true,
    class: "flow",
    onsubmit: async (e) => {
      e.preventDefault();
      msg.replaceChildren();
      setBusy(submitBtn, true, "Verifying…");
      try {
        let ok = false;
        if (useBackupMode) {
          ok = await ctx.vault.verifyTotpBackupCode(backupInput.input.value.trim());
        } else {
          ok = await verifyTotpCode(secret, totpInput.input.value.trim(), 1, {
            throttleKey: ctx.vault.account?.uid || ctx.vault.account?.email || "default"
          });
        }
        if (!ok) {
          setBusy(submitBtn, false);
          msg.replaceChildren(notice("err", useBackupMode
            ? "Invalid or already used backup code."
            : "Invalid 6-digit code. Please check your Authenticator app and try again."));
          totpInput.input.value = "";
          backupInput.input.value = "";
          (useBackupMode ? backupInput.input : totpInput.input).focus();
          return;
        }
        verified = true;
        sheet.close();
        onVerified();
      } catch (err) {
        setBusy(submitBtn, false);
        msg.replaceChildren(notice("err", errText(err)));
      }
    }
  },
    notice("info", "App-level lock (UI only) is active on this account."),
    totpInput.root,
    backupInput.root,
    msg,
    submitBtn,
    modeBtn
  );

  sheet = openSheet({
    title: "App-level lock (UI only)",
    onClose: () => {
      if (!verified) {
        ctx.vault.signOutAccount();
      }
    },
    content: form
  });
}

/**
 * Opens Google's official account picker (`prompt: "select_account"`), authenticates with Firebase,
 * animates the Google button icon while in progress, closes any child popup window on completion,
 * and navigates directly to Vault Passkey Setup or Unlock without requiring an Account Password.
 */
export async function triggerGoogleSignIn(ctx, onError, btnEl = null) {
  if (isGoogleAuthInFlight()) return;
  const textEl = btnEl?.querySelector?.(".google-btn-text") || null;
  const origText = textEl ? textEl.textContent : "Continue with Google";
  if (btnEl) {
    btnEl.disabled = true;
    btnEl.classList.add("is-busy");
    if (textEl) textEl.textContent = "Connecting to Google…";
  }
  try {
    const tokenRes = await requestGoogleOAuthToken();
    closeActiveGooglePopup();
    unloadGoogleIdentityServices();
    const acct = await ctx.vault.signInWithGoogle({
      idToken: tokenRes.idToken,
      accessToken: tokenRes.accessToken
    });
    toast(`Signed in with Google as ${acct.email}`);
    if (acct.totpEnabled && acct.totpSecret) {
      showTotpPromptSheet(ctx, acct.totpSecret, () => ctx.go("passkey"));
    } else {
      ctx.go("passkey");
    }
  } catch (err) {
    closeActiveGooglePopup();
    logAuthError("triggerGoogleSignIn", err);
    if (err?.code === "ACCOUNT_CONFLICT_PASSWORD") {
      showLinkGoogleAccountSheet(ctx, err.pendingGoogle || { email: err.email }, () => ctx.go("passkey"));
      return;
    }
    onError?.(err);
  } finally {
    if (btnEl) {
      btnEl.disabled = false;
      btnEl.classList.remove("is-busy");
      if (textEl) textEl.textContent = origText;
    }
  }
}

export function googleButton(ctx, onError) {
  const btn = h("button", {
    class: "btn glass google-btn",
    type: "button",
    onclick: () => triggerGoogleSignIn(ctx, onError, btn)
  },
    h("span", { class: "google-ico", "aria-hidden": "true" }, svg(GOOGLE_G_SVG, { size: 18, viewBox: "0 0 24 24" })),
    h("span", { class: "google-btn-text" }, "Continue with Google")
  );
  return btn;
}

/**
 * Layer 1 Welcome & Sign In Screen:
 *   Method A: Continue with Google (Official Google account chooser -> Passkey setup or unlock)
 *   Method B: Email & Password (Email + Password -> Sign in, Forgot password?, Create account)
 */
export function loginScreen(ctx, props = {}) {
  preloadGoogleIdentityServices();
  let submitting = false;

  const emailField = field({
    label: "Email Address",
    name: "email",
    type: "email",
    inputmode: "email",
    autocomplete: "username",
    autofocus: true,
    placeholder: "you@gmail.com"
  });

  const password = passwordField({
    label: "Password",
    name: "master-password",
    autocomplete: "current-password",
    maxlength: "128",
    placeholder: "Your account password"
  });

  const rememberCheckbox = h("input", {
    type: "checkbox",
    name: "remember-device",
    checked: null
  });
  const rememberLabel = h("label", { class: "check", style: { alignItems: "center" } },
    rememberCheckbox,
    h("span", { class: "small muted" }, "Remember this device")
  );

  const msg = h("div", { class: "flow-msg", "aria-live": "polite" }, props.notice && notice("info", props.notice));

  const forgotBtn = h("button", {
    class: "link small forgot-btn",
    type: "button",
    onclick: async () => {
      msg.replaceChildren();
      const em = emailField.input.value.trim().toLowerCase();
      if (EMAIL_RE.test(em)) {
        setBusy(forgotBtn, true, "Sending reset link…");
        try {
          await ctx.vault.sendPasswordResetEmail(em);
          setBusy(forgotBtn, false);
          msg.replaceChildren(notice("info", `Password reset link sent to ${em}. Please check your inbox and spam folder.`));
        } catch (err) {
          setBusy(forgotBtn, false);
          logAuthError("sendPasswordResetEmail", err);
          msg.replaceChildren(notice("err", errText(err)));
        }
        return;
      }
      showForgotPasswordSheet(ctx, em, (sentEmail, confText) => {
        emailField.input.value = sentEmail;
        msg.replaceChildren(notice("info", confText));
      });
    }
  }, "Forgot password?");

  const pwWrap = h("div", { class: "pw-step" },
    password.root,
    h("div", { class: "row-between", style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "4px", gap: "8px", flexWrap: "wrap" } },
      rememberLabel,
      forgotBtn
    )
  );

  const btn = h("button", { class: "btn primary", type: "submit" }, "Sign in");
  const card = h("div", { class: "card glass auth-card rise", style: { "--d": "120ms" } });

  emailField.input.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !password.input.value) {
      e.preventDefault();
      msg.replaceChildren();
      const em = emailField.input.value.trim().toLowerCase();
      if (!EMAIL_RE.test(em)) {
        msg.replaceChildren(notice("err", "Please enter a valid email address to continue."));
        return;
      }
      password.input.focus();
    }
  });

  const gBtn = googleButton(ctx, (err) => {
    logAuthError("googleButton", err);
    msg.replaceChildren(notice("err", errText(err)));
  });

  card.append(h("form", {
    novalidate: true,
    class: "flow",
    onsubmit: async (e) => {
      e.preventDefault();
      if (submitting) return;
      msg.replaceChildren();
      const em = emailField.input.value.trim().toLowerCase();
      if (!EMAIL_RE.test(em)) {
        msg.replaceChildren(notice("err", "Please enter a valid email address."));
        emailField.input.focus();
        return;
      }
      const pw = password.input.value;
      if (!pw) {
        msg.replaceChildren(notice("err", "Please enter your account password."));
        password.input.focus();
        return;
      }
      submitting = true;
      setBusy(btn, true, "Signing in…");
      gBtn.disabled = true;
      try {
        closeActiveGooglePopup();
        const acct = await ctx.vault.signInAccount({
          email: em,
          password: pw,
          rememberDevice: Boolean(rememberCheckbox.checked)
        });
        password.input.value = "";
        if (acct?.totpEnabled && acct?.totpSecret) {
          submitting = false;
          setBusy(btn, false);
          gBtn.disabled = false;
          showTotpPromptSheet(ctx, acct.totpSecret, () => ctx.go("passkey"));
        } else {
          ctx.go("passkey");
        }
      } catch (err) {
        submitting = false;
        setBusy(btn, false);
        gBtn.disabled = false;
        logAuthError("signInAccount", err);
        msg.replaceChildren(notice("err", errText(err)));
        password.input.value = "";
        card.classList.remove("rise", "shake");
        void card.offsetWidth;
        card.classList.add("shake");
        password.input.focus();
      }
    }
  },
    h("h2", { class: "flow-title" }, "Sign in to KeyVEX"),
    h("p", { class: "muted small flow-sub" }, "Continue with Google or sign in with your email and password."),
    gBtn,
    h("div", { class: "auth-divider" }, h("span", null, "or continue with email")),
    emailField.root,
    pwWrap,
    msg,
    btn
  ));

  return h("main", { class: "screen center auth" },
    h("div", { class: "rise" }, brand({ size: "xl", tag: "h1" })),
    card,
    h("div", { class: "auth-switch rise", style: { "--d": "220ms" } },
      h("p", { class: "muted small" }, "Don’t have an account?"),
      h("button", { class: "btn glass", type: "button", onclick: () => ctx.go("register") }, icon("plus", 18), "Create account"))
  );
}
