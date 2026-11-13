import { h } from "../dom.js";
import { icon } from "../icons.js";
import { brand } from "../components/brand.js";
import { passwordField, pinField, pinLengthSelector, notice } from "../components/fields.js";
import { openSheet, confirmSheet, setBusy } from "../components/sheet.js";
import { toast } from "../components/feedback.js";
import { checkPin } from "../../core/strength.js";
import { errText, logAuthError } from "../errors.js";
import { requestGoogleOAuthToken, closeActiveGooglePopup, unloadGoogleIdentityServices } from "../../core/firebase.js";

/**
 * 2-Step "Forgot Passkey?" Sheet (`showForgotPasskeySheet`):
 *   - Title: "Reset your Vault Passkey"
 *   - Step 1 (Identity Verification Gate):
 *       - Password field + "Verify with Password" button, shown ONLY if `acct.hasPassword`.
 *       - "Verify with Google" button, shown ONLY if the account's providers include `google.com`.
 *       - Never both hidden. Divider shown ONLY when both are visible.
 *       - Pressing Enter in the password field triggers "Verify with Password".
 *   - Step 2 (Set New Passkey — hidden until Step 1 succeeds):
 *       - 4/6-digit selector (locked to the account's current length by default),
 *       - New Passkey + Confirm New Passkey,
 *       - Submit: "Save New Passkey & Open Vault".
 *   - Clears verification state when the sheet is closed.
 */
export function showForgotPasskeySheet(ctx) {
  const acct = ctx.vault.account;
  const providers = Array.isArray(acct?.providers) ? acct.providers : (acct?.provider ? [acct.provider] : ["password"]);
  const hasPasswordOption = Boolean(acct?.hasPassword || (acct?.provider === "password" && !providers.includes("google.com")));
  const hasGoogleOption = Boolean(providers.includes("google.com") || acct?.provider === "google.com");
  const showPassword = hasPasswordOption || !hasGoogleOption;
  const showGoogle = hasGoogleOption;
  const showBoth = showPassword && showGoogle;

  let resetLen = resolveAccountPinLength(acct) === 4 ? 4 : 6;
  let isVerified = Boolean(ctx.vault.passkeyResetVerified);

  const subtitleText = showBoth
    ? "Verify it's you with your account password or Google."
    : (showGoogle
        ? `Confirm your Google account (${acct?.email || ""}) to set a new Vault Passkey.`
        : "Enter your account password to verify your identity and set a new Vault Passkey.");

  const subtitleEl = h(
    "p",
    { class: "muted small flow-sub" },
    subtitleText
  );

  const reauthPwField = passwordField({
    label: "Account Password",
    name: "reauth-account-password",
    autocomplete: "current-password",
    autofocus: showPassword,
    placeholder: "Enter your KeyVEX account password"
  });

  const verifyPwBtn = h("button", {
    class: "btn primary",
    type: "button",
    onclick: async () => {
      msg.replaceChildren();
      const pw = reauthPwField.input.value;
      if (!pw) {
        msg.replaceChildren(notice("err", "Please enter your account password to verify."));
        reauthPwField.input.focus();
        return;
      }
      setBusy(verifyPwBtn, true, "Verifying password…");
      try {
        await ctx.vault.verifyPasskeyResetIdentity({ password: pw });
        reauthPwField.input.value = "";
        isVerified = true;
        syncStepUi();
        msg.replaceChildren(notice("info", "Account password verified! Choose your new Passkey below."));
        newPk.input.focus();
      } catch (err) {
        logAuthError("verifyPasskeyResetPassword", err);
        msg.replaceChildren(notice("err", errText(err)));
      } finally {
        setBusy(verifyPwBtn, false);
      }
    }
  }, icon("shield", 16), "Verify with Password");

  reauthPwField.input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      verifyPwBtn.click();
    }
  });

  const verifyGoogleBtn = h("button", {
    class: showPassword ? "btn glass" : "btn primary",
    type: "button",
    onclick: async () => {
      msg.replaceChildren();
      setBusy(verifyGoogleBtn, true, "Verifying with Google…");
      try {
        try {
          await ctx.vault.verifyPasskeyResetIdentity({ googleSession: true });
        } catch {
          const tokenRes = await requestGoogleOAuthToken();
          closeActiveGooglePopup();
          unloadGoogleIdentityServices();
          await ctx.vault.verifyPasskeyResetIdentity({
            idToken: tokenRes.idToken,
            accessToken: tokenRes.accessToken
          });
        }
        isVerified = true;
        syncStepUi();
        msg.replaceChildren(notice("info", "Google account verified! Choose your new Passkey below."));
        newPk.input.focus();
      } catch (err) {
        closeActiveGooglePopup();
        logAuthError("verifyPasskeyResetGoogle", err);
        msg.replaceChildren(notice("err", errText(err)));
      } finally {
        setBusy(verifyGoogleBtn, false);
      }
    }
  }, icon("user", 16), "Verify with Google");

  const step1Nodes = [];
  if (showPassword) {
    step1Nodes.push(reauthPwField.root, verifyPwBtn);
  }
  if (showBoth) {
    step1Nodes.push(h("div", { class: "auth-divider" }, h("span", null, "or")));
  }
  if (showGoogle) {
    step1Nodes.push(verifyGoogleBtn);
  }

  const step1Gate = h("div", { class: "grid-gap", "data-step": "1" }, ...step1Nodes);

  const newPk = pinField({
    label: "New Passkey",
    name: "new-passkey",
    length: resetLen,
    placeholder: `${resetLen} digits (0–9)`,
    autocomplete: "off",
    hint: `Choose a new ${resetLen}-digit numeric Passkey.`
  });
  const confirmPk = pinField({
    label: "Confirm New Passkey",
    name: "confirm-new-passkey",
    length: resetLen,
    placeholder: `Repeat ${resetLen} digits`,
    autocomplete: "off"
  });

  const resetLenPicker = pinLengthSelector({
    initial: resetLen === 4 ? 4 : 6,
    onChange: (len) => {
      resetLen = len;
      newPk.setLength(len, true);
      confirmPk.setLength(len, false);
      confirmPk.input.placeholder = `Repeat ${len} digits`;
      if (newPk.hintEl) {
        newPk.hintEl.textContent = `Choose a new ${len}-digit numeric Passkey.`;
      }
      newPk.input.focus();
    }
  });

  const submitBtn = h("button", { class: "btn primary", type: "submit" }, "Save New Passkey & Open Vault");

  const step2NewPasskeyWrap = h("div", { class: "grid-gap", "data-step": "2" },
    notice("info", "Identity verified. Choose your new 4-digit or 6-digit Vault Passkey below:"),
    resetLenPicker.root,
    newPk.root,
    confirmPk.root,
    submitBtn
  );

  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });

  const syncStepUi = () => {
    step1Gate.hidden = isVerified;
    step2NewPasskeyWrap.hidden = !isVerified;
  };
  syncStepUi();

  let sheet;
  const form = h("form", {
    novalidate: true,
    class: "flow",
    onsubmit: async (e) => {
      e.preventDefault();
      msg.replaceChildren();

      if (!isVerified) {
        if (showPassword) {
          verifyPwBtn.click();
          return;
        }
        if (showGoogle) {
          verifyGoogleBtn.click();
          return;
        }
        msg.replaceChildren(
          notice("err", "Please verify your identity first.")
        );
        return;
      }

      const p1 = newPk.input.value.trim();
      const p2 = confirmPk.input.value.trim();
      const pCheck = checkPin(p1, resetLen);
      if (!pCheck.ok) {
        msg.replaceChildren(notice("err", pCheck.hint));
        return;
      }
      if (p1 !== p2) {
        msg.replaceChildren(notice("err", "The new Passkeys don’t match."));
        return;
      }

      setBusy(submitBtn, true, "Saving new Passkey…");
      try {
        await ctx.vault.resetPasskeyAfterVerification(p1);
        sheet.close();
        toast("New Passkey saved — vault unlocked");
        ctx.go("vault");
      } catch (err) {
        logAuthError("resetPasskeyAfterVerification", err);
        if (err?.code === "UNAUTHENTICATED") {
          isVerified = false;
          syncStepUi();
        }
        msg.replaceChildren(notice("err", errText(err)));
      } finally {
        setBusy(submitBtn, false);
      }
    }
  },
    subtitleEl,
    step1Gate,
    step2NewPasskeyWrap,
    msg
  );

  sheet = openSheet({
    title: "Reset your Vault Passkey",
    onClose: () => {
      ctx.vault.clearPasskeyResetVerification?.();
    },
    content: form
  });
  return sheet;
}

/**
 * Resolves the authoritative Passkey length for an existing account from
 * `acct.pinLength` or `acct.meta?.pinLength`. Returns 4, 6, 8, "strong", or null if unknown.
 */
export function resolveAccountPinLength(acct) {
  if (!acct) return null;
  for (const cand of [acct.pinLength, acct.meta?.pinLength]) {
    if (cand === 4 || cand === 6 || cand === 8 || cand === "strong") return cand;
  }
  return null;
}

/**
 * Layer 2 Screen — Vault Passkey Setup (First time) & Everyday Quick-Unlock:
 *   - First-time users (`isSetup === true`) see the Passkey length selector, choose a Passkey, and confirm it.
 *   - Returning users (`isSetup === false`) see the input locked to their account's saved `pinLength`
 *     and the "Forgot Passkey?" link that opens `showForgotPasskeySheet(ctx)`.
 */
export function passkeyScreen(ctx, props = {}) {
  const acct = ctx.vault.account;
  if (!acct) {
    ctx.go("login");
    return h("main", { class: "screen center auth" });
  }

  let isSetup = !acct.hasVault;
  let submitting = false;
  let lockoutTimer = null;

  const storedPinLen = resolveAccountPinLength(acct);
  const setupDefaultLen = storedPinLen === 4 ? 4 : 6;
  const unlockLockedLen = storedPinLen || 6;
  const activeInitialLen = isSetup ? setupDefaultLen : unlockLockedLen;

  const formatLenLabel = (len) => (len === "strong" ? "Strong Passkey" : `${len}-Digit Passkey`);
  const formatPlaceholder = (len) => (len === "strong" ? "8+ chars (letters & numbers)" : `${len} digits (0–9)`);

  const passkey = pinField({
    label: isSetup ? "Create Passkey" : formatLenLabel(unlockLockedLen),
    name: "passkey",
    length: activeInitialLen,
    placeholder: formatPlaceholder(activeInitialLen),
    autofocus: true,
    autocomplete: "off",
    hint: isSetup
      ? "Numbers only (0–9). Avoid simple runs like 1234."
      : (unlockLockedLen === "strong" ? "Enter your strong Passkey." : `Enter your ${unlockLockedLen}-digit numeric Passkey.`)
  });

  const again = pinField({
    label: "Confirm Passkey",
    name: "passkey-confirm",
    length: setupDefaultLen,
    placeholder: `Repeat ${setupDefaultLen} digits`,
    autocomplete: "off"
  });
  const againWrap = h("div", { hidden: !isSetup }, again.root);

  const lenPicker = pinLengthSelector({
    initial: setupDefaultLen,
    onChange: (len) => {
      if (!isSetup) return;
      passkey.setLength(len, true);
      again.setLength(len, false);
      again.input.placeholder = `Repeat ${len} digits`;
      if (passkey.hintEl) {
        passkey.hintEl.textContent = len === 4
          ? "4-digit Passkey selected. Numbers only (0–9)."
          : "6 digits — numbers only (0–9). Avoid simple runs like 123456.";
      }
      passkey.input.focus();
    }
  });
  const lenPickerWrap = h("div", { class: "pin-len-wrap", hidden: !isSetup }, lenPicker.root);

  const msg = h("div", { class: "flow-msg", "aria-live": "polite" }, props.notice && notice("info", props.notice));
  const titleEl = h("h2", { class: "flow-title" }, isSetup ? "Set your Vault Passkey" : "Unlock with Passkey");
  const subEl = h(
    "p",
    { class: "muted small flow-sub" },
    isSetup
      ? "Set a 4 or 6 digit Passkey to encrypt and unlock your vault on any device."
      : (unlockLockedLen === "strong"
          ? "Enter your strong Passkey to open your encrypted vault."
          : `Enter your ${unlockLockedLen}-digit Passkey to open your encrypted vault.`)
  );
  const btn = h("button", { class: "btn primary", type: "submit" }, isSetup ? "Save Passkey & Open Vault" : "Unlock Vault");

  const forgotPasskeyBtn = h(
    "button",
    {
      class: "link small",
      type: "button",
      onclick: () => showForgotPasskeySheet(ctx)
    },
    "Forgot Passkey?"
  );
  const forgotPasskeyWrap = h("div", { hidden: isSetup, style: { textAlign: "center", marginTop: "4px" } }, forgotPasskeyBtn);

  // B2: Check and display persistent lockout countdown on the Passkey screen
  const checkLockoutCountdown = async () => {
    if (isSetup || !ctx.vault.getPasskeyLockoutStatus) return;
    try {
      const status = await ctx.vault.getPasskeyLockoutStatus();
      if (status.locked && status.retryAfter > 0) {
        btn.disabled = true;
        msg.replaceChildren(notice("err", `Too many wrong Passkey attempts. Try again in ${status.retryAfter}s.`));
        if (!lockoutTimer) {
          lockoutTimer = setInterval(async () => {
            if (!card.isConnected) {
              clearInterval(lockoutTimer);
              lockoutTimer = null;
              return;
            }
            const nextStatus = await ctx.vault.getPasskeyLockoutStatus();
            if (nextStatus.locked && nextStatus.retryAfter > 0) {
              btn.disabled = true;
              msg.replaceChildren(notice("err", `Too many wrong Passkey attempts. Try again in ${nextStatus.retryAfter}s.`));
            } else {
              btn.disabled = false;
              msg.replaceChildren();
              clearInterval(lockoutTimer);
              lockoutTimer = null;
            }
          }, 1000);
          lockoutTimer.unref?.();
        }
      }
    } catch { /* ignore */ }
  };

  const applyModeState = () => {
    const curAcct = ctx.vault.account;
    const curLockedLen = resolveAccountPinLength(curAcct) || unlockLockedLen;
    const activeLen = isSetup ? lenPicker.value : curLockedLen;

    lenPickerWrap.hidden = !isSetup;
    againWrap.hidden = !isSetup;
    forgotPasskeyWrap.hidden = isSetup;

    passkey.setLength(activeLen, true);
    passkey.input.placeholder = formatPlaceholder(activeLen);
    const labelTextNode = passkey.root.querySelector?.(".label");
    if (labelTextNode) {
      labelTextNode.textContent = isSetup ? "Create Passkey" : formatLenLabel(curLockedLen);
    }
    if (passkey.hintEl) {
      passkey.hintEl.textContent = isSetup
        ? (activeLen === 4
            ? "4-digit Passkey selected. Numbers only (0–9)."
            : "6 digits — numbers only (0–9). Avoid simple runs like 123456.")
        : (curLockedLen === "strong" ? "Enter your strong Passkey." : `Enter your ${curLockedLen}-digit numeric Passkey.`);
    }
    again.setLength(lenPicker.value, false);
    again.input.placeholder = `Repeat ${lenPicker.value} digits`;

    titleEl.textContent = isSetup ? "Set your Vault Passkey" : "Unlock with Passkey";
    subEl.textContent = isSetup
      ? "Set a 4 or 6 digit Passkey to encrypt and unlock your vault on any device."
      : (curLockedLen === "strong"
          ? "Enter your strong Passkey to open your encrypted vault."
          : `Enter your ${curLockedLen}-digit Passkey to open your encrypted vault.`);
    btn.textContent = isSetup ? "Save Passkey & Open Vault" : "Unlock Vault";
    btn.dataset.label = btn.textContent;
  };

  applyModeState();
  checkLockoutCountdown();

  const card = h("div", { class: "card glass auth-card rise", style: { "--d": "80ms" } });

  const userBadge = h("div", { class: "user-pill glass" },
    icon("user", 16),
    h("span", { class: "user-pill-text" },
      h("strong", null, acct.name || acct.email.split("@")[0]),
      h("small", { class: "muted" }, acct.email)
    )
  );

  const formNodes = [
    userBadge,
    titleEl,
    subEl,
    passkey.root
  ];
  if (isSetup) {
    formNodes.push(lenPickerWrap, againWrap);
  }
  formNodes.push(msg, btn, forgotPasskeyWrap);

  card.append(h("form", {
    novalidate: true,
    class: "flow",
    onsubmit: async (e) => {
      e.preventDefault();
      if (submitting) return;
      msg.replaceChildren();
      const fail = (t) => msg.replaceChildren(notice("err", t));
      const pk = passkey.input.value.trim();

      if (isSetup) {
        const targetLen = lenPicker.value;
        const p = checkPin(pk, targetLen);
        if (!p.ok) return fail(p.hint);
        if (pk !== again.input.value.trim()) return fail("The two Passkeys don’t match.");
        submitting = true;
        setBusy(btn, true, "Securing vault…");
        try {
          await ctx.vault.setupPasskey(pk);
          passkey.input.value = "";
          again.input.value = "";
          toast("Passkey saved — vault unlocked");
          ctx.go("vault");
        } catch (err) {
          logAuthError("setupPasskey", err);
          if (err?.code === "ACCOUNT_EXISTS") {
            isSetup = false;
            lenPickerWrap.remove();
            againWrap.remove();
            applyModeState();
            fail("A vault already exists for this account. Enter your existing Passkey to unlock it.");
          } else {
            fail(errText(err));
          }
        } finally {
          submitting = false;
          setBusy(btn, false);
        }
      } else {
        const curAcct = ctx.vault.account;
        const authoritativeLen = resolveAccountPinLength(curAcct);
        if (authoritativeLen === 4 || authoritativeLen === 6 || authoritativeLen === 8) {
          if (!/^\d+$/.test(pk) || pk.length !== authoritativeLen) {
            card.classList.remove("rise", "shake");
            void card.offsetWidth;
            card.classList.add("shake");
            return fail(`Enter your ${authoritativeLen}-digit Passkey.`);
          }
        } else if (authoritativeLen !== "strong" && !/^\d{4}$|^\d{6}$|^\d{8}$/.test(pk)) {
          card.classList.remove("rise", "shake");
          void card.offsetWidth;
          card.classList.add("shake");
          return fail("Passkey must be 4 or 6 digits.");
        }

        submitting = true;
        setBusy(btn, true, "Unlocking…");
        try {
          await ctx.vault.unlockWithPasskey(pk);
          passkey.input.value = "";
          ctx.go("vault", { skipped: ctx.vault.skipped });
          if (ctx.vault.migrated) toast("Previous vault migrated and unlocked");
        } catch (err) {
          if (err && typeof err === "object") err.context = "passkey";
          logAuthError("unlockWithPasskey", err);
          if (err?.code === "TOO_MANY_TRIES") {
            ctx.go("login", { notice: err.message });
            return;
          }
          if (err?.code === "SESSION_EXPIRED" || err?.code === "TOKEN_EXPIRED") {
            ctx.go("login", { notice: errText(err) });
            return;
          }
          fail(errText(err));
          if (err?.code === "LOCKED_OUT") {
            checkLockoutCountdown();
          }
          passkey.input.value = "";
          card.classList.remove("rise", "shake");
          void card.offsetWidth;
          card.classList.add("shake");
          passkey.input.focus();
        } finally {
          submitting = false;
          setBusy(btn, false);
        }
      }
    }
  }, ...formNodes));

  return h("main", { class: "screen center auth" },
    brand({ size: "sm", slogan: false }),
    card,
    h("div", { class: "auth-switch" },
      h("p", { class: "muted small" }, `Not ${acct.email}?`),
      h("button", {
        class: "btn glass",
        type: "button",
        onclick: async () => {
          const ok = await confirmSheet({
            title: "Sign out of KeyVEX?",
            text: "Your session on this browser will be closed and you will return to the sign-in screen.",
            yes: "Sign out",
            danger: true
          });
          if (!ok) return;
          await ctx.logoutAccount("Signed out of your account.");
        }
      }, icon("lock", 16), "Switch account / Sign out"))
  );
}
