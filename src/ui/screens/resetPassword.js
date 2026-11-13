import { h } from "../dom.js";
import { icon } from "../icons.js";
import { brand } from "../components/brand.js";
import { notice } from "../components/fields.js";
import { setBusy } from "../components/sheet.js";
import { masterPasswordSetup } from "../components/masterfield.js";
import { toast } from "../components/feedback.js";
import { errText, logAuthError } from "../errors.js";

/**
 * Dedicated in-app "Reset your password" page (`/reset-password`).
 *
 * The Firebase reset email links here (set the action URL in Firebase Console → Authentication → Templates →
 * Password reset → Customize action URL → `https://<your-domain>/reset-password`), so the user never lands on the
 * default Firebase-hosted page and no extra tab is opened:
 *
 *   email link → this page (same KeyVEX theme) → New password + Confirm password → Save → Sign in page (same tab).
 *
 * props: { oobCode }  – the one-time code from the email link (kept in memory only; the URL is cleaned by app.js).
 */
export function resetPasswordScreen(ctx, props = {}) {
  const oobCode = String(props.oobCode || "").trim();
  const card = h("div", { class: "card glass auth-card rise" });
  const goLogin = (noticeMsg) => ctx.go("login", { notice: noticeMsg, replaceHistory: true });

  const backToLogin = h("button", {
    class: "btn glass",
    type: "button",
    onclick: () => goLogin()
  }, icon("chevron", 16), "Back to sign in");

  const renderInvalid = (text) => {
    card.replaceChildren(
      h("h2", { class: "flow-title" }, "Reset link unavailable"),
      notice("err", text || "This password reset link is invalid or has expired. Please request a new one from the sign-in page."),
      backToLogin
    );
  };

  const renderForm = (email) => {
    const master = masterPasswordSetup({
      label: "New Password",
      confirmLabel: "Confirm Password",
      name: "reset-new-password",
      autofocus: true
    });
    const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
    const btn = h("button", { class: "btn primary", type: "submit" }, "Save new password");
    let submitting = false;

    card.replaceChildren(h("form", {
      novalidate: true,
      class: "flow",
      onsubmit: async (e) => {
        e.preventDefault();
        if (submitting) return;
        msg.replaceChildren();
        const m = master.validate();
        if (!m.ok) {
          msg.replaceChildren(notice("err", m.hint));
          return;
        }
        submitting = true;
        setBusy(btn, true, "Saving new password…");
        try {
          await ctx.vault.confirmPasswordResetWithOobCode(oobCode, master.value);
          master.clear();
          toast("Password updated — please sign in");
          // Same tab: clear any stale session, then go straight back to the sign-in page.
          await ctx.logoutAccount("Password updated! Please sign in with your new password.");
        } catch (err) {
          submitting = false;
          setBusy(btn, false);
          logAuthError("confirmPasswordResetWithOobCode", err);
          msg.replaceChildren(notice("err", errText(err)));
        }
      }
    },
      h("h2", { class: "flow-title" }, "Reset your password"),
      email
        ? h("p", { class: "muted small flow-sub" }, "for ", h("strong", null, email))
        : h("p", { class: "muted small flow-sub" }, "Choose a new password for your KeyVEX account."),
      master.root,
      msg,
      btn,
      h("button", { class: "link small", type: "button", onclick: () => goLogin() }, "Cancel and go back to sign in")
    ));
  };

  if (!oobCode) {
    renderInvalid();
  } else {
    card.append(h("p", { class: "muted small flow-sub", role: "status" }, "Checking your reset link…"));
    ctx.vault.verifyPasswordResetCode(oobCode)
      .then((res) => {
        if (card.isConnected !== false) renderForm(res?.email || "");
      })
      .catch((err) => {
        logAuthError("verifyPasswordResetCode", err);
        renderInvalid(errText(err));
      });
  }

  return h("main", { class: "screen center auth" },
    brand({ size: "sm", slogan: false }),
    card
  );
}
