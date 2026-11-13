import { h } from "../dom.js";
import { icon } from "../icons.js";
import { brand } from "../components/brand.js";
import { field, notice } from "../components/fields.js";
import { setBusy } from "../components/sheet.js";
import { masterPasswordSetup } from "../components/masterfield.js";
import { toast } from "../components/feedback.js";
import { errText, logAuthError } from "../errors.js";
import { preloadGoogleIdentityServices, closeActiveGooglePopup } from "../../core/firebase.js";
import { googleButton } from "./login.js";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Layer 1 Create Account Screen:
 *   Full Name + Email Address + Password + Confirm Password (or Continue with Google).
 *   After account creation, transitions directly to Layer 2 (`passkeyScreen`)
 *   to set the 4/6-digit Vault Passkey without sending a verification email.
 */
export function registerScreen(ctx) {
  preloadGoogleIdentityServices();
  let submitting = false;

  const nameField = field({
    label: "Full Name",
    name: "name",
    autocomplete: "name",
    autofocus: true,
    maxlength: "80",
    placeholder: "Your full name"
  });
  const emailField = field({
    label: "Email Address",
    name: "email",
    type: "email",
    inputmode: "email",
    autocomplete: "email",
    maxlength: "120",
    placeholder: "you@gmail.com"
  });
  const master = masterPasswordSetup({ label: "Password", name: "master-password", autofocus: false });
  const msg = h("div", { class: "flow-msg" });
  const btn = h("button", { class: "btn primary", type: "submit" }, "Create account");
  const gBtn = googleButton(ctx, (err) => msg.replaceChildren(notice("err", errText(err))));
  const card = h("div", { class: "card glass auth-card" });

  card.append(h("form", {
    novalidate: true,
    class: "flow",
    onsubmit: async (e) => {
      e.preventDefault();
      if (submitting) return;
      msg.replaceChildren();
      const fail = (t) => {
        msg.replaceChildren(notice("err", t));
        card.classList.remove("rise", "shake");
        void card.offsetWidth;
        card.classList.add("shake");
      };
      const nm = nameField.input.value.trim();
      const em = emailField.input.value.trim().toLowerCase();
      if (!nm) {
        nameField.input.focus();
        return fail("Please enter your full name.");
      }
      if (!EMAIL_RE.test(em)) {
        emailField.input.focus();
        return fail("Please enter a valid email address.");
      }
      const m = master.validate();
      if (!m.ok) return fail(m.hint);

      submitting = true;
      setBusy(btn, true, "Creating account…");
      gBtn.disabled = true;
      try {
        closeActiveGooglePopup();
        await ctx.vault.signUpAccount({ name: nm, email: em, password: master.value });
        nameField.input.value = "";
        emailField.input.value = "";
        master.clear();
        toast("Account created — now set your Vault Passkey");
        ctx.go("passkey", { justRegistered: true });
      } catch (err) {
        submitting = false;
        setBusy(btn, false);
        gBtn.disabled = false;
        logAuthError("signUpAccount", err);
        fail(errText(err));
      }
    }
  },
    h("h2", { class: "flow-title" }, "Create your account"),
    h("p", { class: "muted small flow-sub" }, "Continue with Google or register with your name, email, and password."),
    gBtn,
    h("div", { class: "auth-divider" }, h("span", null, "or register with email")),
    nameField.root,
    emailField.root,
    master.root,
    msg,
    btn
  ));

  return h("main", { class: "screen center auth" },
    brand({ size: "sm", slogan: false }),
    card,
    h("div", { class: "auth-switch" },
      h("p", { class: "muted small" }, "Already have an account?"),
      h("button", { class: "btn glass", type: "button", onclick: () => ctx.go("login") }, icon("chevron", 16), "Sign in"))
  );
}
