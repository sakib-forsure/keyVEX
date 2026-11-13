import { h } from "../dom.js";
import { icon } from "../icons.js";
import { passwordField, pinField, pinLengthSelector, notice } from "../components/fields.js";
import { openSheet, confirmSheet, setBusy, closeAllSheets } from "../components/sheet.js";
import { masterPasswordSetup } from "../components/masterfield.js";
import { toast, copySecret } from "../components/feedback.js";
import { getSettings, setSetting, applyTheme, THEMES } from "../settings.js";
import { checkPin } from "../../core/strength.js";
import { readBackup, MAX_IMPORT_FILE_BYTES } from "../../core/backup.js";
import { errText, logAuthError } from "../errors.js";
import { csvToEntries } from "../../core/csv.js";
import { isInstalled, startInstallFlow } from "../components/install.js";
import { generateTotpSecret, verifyTotpCode, getTotpUri, generateQrSvg } from "../../core/totp.js";

const download = (name, text, type = "application/json") => {
  const a = h("a", { href: URL.createObjectURL(new Blob([text], { type })), download: name });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
};

const masterField = (label = "Master Password", extra = {}) =>
  passwordField({ label, name: "master-password", autocomplete: "current-password", maxlength: "128", ...extra });

function row(iconName, title, sub, onclick, danger) {
  return h("button", { class: "setting glass" + (danger ? " danger" : ""), type: "button", onclick },
    h("span", { class: "s-ico" }, icon(iconName, 20)), h("span", { class: "meta" }, h("span", { class: "name" }, title), h("span", { class: "sub" }, sub)), icon("chevron", 16));
}

function formSheet({ title, text, nodes, action, danger = false, run }) {
  const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
  const btn = h("button", { class: "btn " + (danger ? "danger" : "primary"), type: "submit" }, action);
  const form = h("form", { novalidate: true, onsubmit: async (e) => {
    e.preventDefault(); msg.replaceChildren(); setBusy(btn, true, "Checking…");
    try { await run(sheet, msg); }
    catch (err) { logAuthError("settingsForm", err); msg.replaceChildren(notice("err", errText(err))); }
    finally { setBusy(btn, false); }
  } }, text && h("p", { class: "muted" }, text), ...nodes, msg, btn);
  const sheet = openSheet({ title, content: form });
  return sheet;
}

/**
 * International-standard professional About KeyVEX modal (`Version 1.0` — First Official Release).
 * No pill/bubble behind the version name; displays Owner & Developer: Abdullah Sakib.
 */
export function openAbout(ctx) {
  const vault = ctx?.vault;
  return openSheet({
    title: "About KeyVEX",
    content: [
      h("div", { class: "about-card glass" },
        h("div", { class: "about-header" },
          h("strong", { class: "about-title" }, "KeyVEX — Zero-Knowledge Password Manager"),
          h("span", { class: "about-version" }, "Version 1.0 (Version 1.0.0 — First Official Release)")
        ),
        h("p", { class: "muted small" },
          "KeyVEX is an enterprise-grade, zero-knowledge encrypted password vault engineered to protect your digital credentials across devices. Every password, note, and generated secret is sealed locally on your device before ever being stored or synchronized."
        ),
        h("div", { class: "about-specs" },
          h("div", { class: "about-spec-row" }, h("span", { class: "muted" }, "Owner & Developer"), h("strong", null, "Abdullah Sakib")),
          h("div", { class: "about-spec-row" }, h("span", { class: "muted" }, "Release Edition"), h("strong", null, "Version 1.0 (First Official Release)")),
          h("div", { class: "about-spec-row" }, h("span", { class: "muted" }, "Vault Encryption"), h("strong", null, "AES-256-GCM (96-bit IV + Authenticated AAD)")),
          h("div", { class: "about-spec-row" }, h("span", { class: "muted" }, "Key Derivation"), h("strong", null, "PBKDF2-HMAC-SHA256 (600,000 iter) + HKDF")),
          h("div", { class: "about-spec-row" }, h("span", { class: "muted" }, "Key Wrapping"), h("strong", null, "256-bit AES-KW (RFC 3394)")),
          h("div", { class: "about-spec-row" }, h("span", { class: "muted" }, "Identity & Access"), h("strong", null, "2-Layer Auth (Account + 4/6-Digit Passkey)")),
          h("div", { class: "about-spec-row" }, h("span", { class: "muted" }, "Storage Engine"), h("strong", null, vault?.syncStatus === "cloud" ? "Cloud Firestore + Local IndexedDB" : "Encrypted Local IndexedDB"))
        )
      )
    ]
  });
}

export function openSettings(ctx, onChange) {
  const { vault } = ctx;
  const acct = vault.account;
  const isTwoLayer = !!acct?.email;
  const isGoogleAccount = acct?.provider === "google.com";
  const acctPinLen = (acct?.pinLength === 4 || acct?.meta?.pinLength === 4) ? 4 : 6;
  const s = getSettings();

  const lockSeg = h("div", { class: "seg", role: "radiogroup", "aria-label": "Auto-lock" },
    [1, 5, 15, 30].map((m) => h("button", { type: "button", role: "radio", class: s.autoLockMin === m ? "on" : "", "aria-checked": String(s.autoLockMin === m),
      onclick: (e) => { setSetting("autoLockMin", m); [...lockSeg.children].forEach((c) => { c.classList.remove("on"); c.setAttribute("aria-checked", "false"); }); e.currentTarget.classList.add("on"); e.currentTarget.setAttribute("aria-checked", "true"); } }, `${m} min`)));

  const lockOnHideToggle = h("label", { class: "switch" },
    h("input", {
      type: "checkbox",
      checked: s.lockOnHide ? true : null,
      onchange: (e) => { setSetting("lockOnHide", Boolean(e.target.checked)); }
    }),
    h("span", { class: "track" }),
    "Lock immediately when tab is hidden"
  );

  const rememberDeviceToggle = isTwoLayer
    ? h("label", { class: "switch" },
        h("input", {
          type: "checkbox",
          checked: acct?.rememberDevice ? true : null,
          onchange: async (e) => {
            await vault.setRememberDevice(Boolean(e.target.checked));
          }
        }),
        h("span", { class: "track" }),
        "Remember this device after sign-out"
      )
    : null;

  const themeRow = h("div", { class: "swatches", role: "radiogroup", "aria-label": "Colour theme" },
    THEMES.map((t) => h("button", { type: "button", role: "radio", class: "swatch" + (s.theme === t ? " on" : ""), "aria-checked": String(s.theme === t), "data-swatch": t,
      onclick: (e) => { setSetting("theme", t); applyTheme(t); [...themeRow.children].forEach((c) => { c.classList.remove("on"); c.setAttribute("aria-checked", "false"); }); e.currentTarget.classList.add("on"); e.currentTarget.setAttribute("aria-checked", "true"); } },
      h("i"), t[0].toUpperCase() + t.slice(1))));

  const currentPair = (autofocus = true) => ({
    passkey: pinField({ label: "Enter your Passkey", name: "current-passkey", length: acctPinLen, autofocus }),
    master: masterField("Current Master Password")
  });

  const changePasskey = () => {
    let userPickedLen = false;
    let googleVerified = false;
    const cur = currentPair(!isGoogleAccount);
    const n1 = pinField({ label: "New Passkey", length: 6, placeholder: "6 digits (0–9)" });
    const n2 = pinField({ label: "Repeat new Passkey", length: 6, placeholder: "Repeat 6 digits" });
    const lenPicker = pinLengthSelector({
      initial: 6,
      onChange: (len) => {
        userPickedLen = true;
        n1.setLength(len, true);
        n2.setLength(len, false);
        n2.input.placeholder = `Repeat ${len} digits`;
        n1.input.focus();
      }
    });

    const googleVerifyStatus = h("div");
    const googleVerifyBtn = isGoogleAccount
      ? h("button", {
          class: "btn glass",
          type: "button",
          onclick: async () => {
            setBusy(googleVerifyBtn, true, "Verifying with Google…");
            try {
              await vault.verifyPasskeyResetIdentity({ googleSession: true });
              googleVerified = true;
              cur.passkey.root.hidden = true;
              googleVerifyBtn.hidden = true;
              googleVerifyStatus.replaceChildren(notice("info", `Verified with Google (${acct.email}). Enter your new Passkey below.`));
              n1.input.focus();
            } catch (err) {
              toast(errText(err));
            } finally {
              setBusy(googleVerifyBtn, false);
            }
          }
        }, icon("user", 16), "Verify with Google instead of Passkey")
      : null;

    const nodes = isTwoLayer
      ? [
          ...(isGoogleAccount ? [googleVerifyBtn, googleVerifyStatus] : []),
          cur.passkey.root,
          lenPicker.root,
          n1.root,
          n2.root
        ]
      : [cur.passkey.root, cur.master.root, lenPicker.root, n1.root, n2.root];

    formSheet({
      title: "Change Passkey",
      action: "Save new Passkey",
      text: isGoogleAccount
        ? "Verify with Google or enter your current Passkey, then choose a 4-digit or 6-digit Passkey."
        : "Confirm your current Passkey first. Your passwords stay exactly as they are.",
      nodes,
      run: async (sh) => {
        const targetLen = userPickedLen ? lenPicker.value : (n1.input.value.length === 4 ? 4 : lenPicker.value);
        const c = checkPin(n1.input.value, targetLen);
        if (!c.ok) throw new Error(c.hint);
        if (n1.input.value !== n2.input.value) throw new Error("The new Passkeys don’t match.");
        if (isGoogleAccount && (googleVerified || !cur.passkey.input.value)) {
          if (!vault.passkeyResetVerified) {
            await vault.verifyPasskeyResetIdentity({ googleSession: true });
          }
          await vault.resetPasskeyAfterVerification(n1.input.value);
        } else {
          await vault.changePasskey(cur.passkey.input.value, isTwoLayer ? "" : cur.master.input.value, n1.input.value);
        }
        sh.close();
        toast(vault.syncStatus === "pending" ? "Passkey changed locally — cloud sync pending" : "Passkey changed");
      }
    });
  };

  const changeMaster = () => {
    const cur = currentPair();
    const next = masterPasswordSetup({ label: "New Master Password", name: "new-master-password", autofocus: false, getPin: () => cur.passkey.input.value });
    formSheet({
      title: "Change Master Password", action: "Save new Master Password",
      text: "Confirm who you are first. Your passwords stay exactly as they are; other devices will need to sign in again.",
      nodes: [cur.passkey.root, cur.master.root, next.root],
      run: async (sh) => {
        const c = next.validate();
        if (!c.ok) throw new Error(c.hint);
        await vault.changeMasterPassword(cur.passkey.input.value, cur.master.input.value, next.value);
        sh.close(); onChange(); toast("Master Password changed");
      }
    });
  };

  // PART 4: Change Account Password (shown ONLY for manual Email/Password accounts, never for Google accounts)
  const changeAccountPassword = () => {
    const curPasskey = pinField({
      label: "Enter your Passkey",
      name: "current-passkey",
      length: acctPinLen,
      autofocus: true
    });
    const next = masterPasswordSetup({
      label: "New Account Password",
      name: "new-account-password",
      autofocus: false,
      getPin: () => curPasskey.input.value
    });
    formSheet({
      title: "Change Account Password",
      action: "Save Password",
      text: "Enter your current Passkey and choose a new account password.",
      nodes: [curPasskey.root, next.root],
      run: async (sh) => {
        if (!curPasskey.input.value) throw new Error("Enter your current Passkey to continue.");
        const c = next.validate();
        if (!c.ok) throw new Error(c.hint);
        await vault.setAccountPassword(curPasskey.input.value, next.value);
        sh.close();
        toast("Account password saved");
      }
    });
  };

  // Device & Session Management / Revoke Other Sessions
  const manageSessions = () => {
    const cur = currentPair();
    const sessionSummary = h("div", { class: "session-card glass" },
      h("strong", null, "Active device & session status"),
      h("span", { class: "muted small" }, "Checking active sessions…")
    );
    vault.listSessions?.().then((info) => {
      sessionSummary.replaceChildren(
        h("strong", null, `${info.activeSessions || 1} active session${(info.activeSessions || 1) === 1 ? "" : "s"}`),
        h("span", { class: "muted small" }, `Current device: ${info.email || "Local Vault"} · Session revision v${info.sessionRev || 1}`)
      );
    }).catch(() => {});

    const nodes = isTwoLayer
      ? [sessionSummary, cur.passkey.root]
      : [sessionSummary, cur.passkey.root, cur.master.root];

    formSheet({
      title: "Devices & Sessions",
      action: "Revoke Other Sessions",
      danger: true,
      text: "Sign out all other browsers and devices signed into this account while keeping this device active.",
      nodes,
      run: async (sh) => {
        if (!cur.passkey.input.value) throw new Error("Enter your current Passkey to revoke other sessions.");
        await vault.revokeOtherSessions(cur.passkey.input.value, isTwoLayer ? "" : cur.master.input.value);
        sh.close();
        toast("All other sessions have been revoked");
      }
    });
  };

  // PART 4, F5, B13: App-level lock (UI only) with Passkey step-up, auto-clearing copySecret, local QR code, and 8 backup codes
  const manageTotp = () => {
    if (acct?.totpEnabled) {
      const curPasskey = pinField({
        label: "Enter your Passkey",
        name: "disable-totp-passkey",
        length: acctPinLen,
        autofocus: true
      });
      formSheet({
        title: "Disable App-level lock (UI only)?",
        action: "Disable Authenticator",
        danger: true,
        text: "Confirm your current Passkey to disable the app-level Authenticator prompt.",
        nodes: [curPasskey.root],
        run: async (sh) => {
          if (!curPasskey.input.value) throw new Error("Enter your Passkey to continue.");
          await vault.disableTotp(curPasskey.input.value);
          sh.close();
          closeAllSheets();
          toast("App-level lock (UI only) disabled");
        }
      });
      return;
    }

    const secret = generateTotpSecret(20);
    const otpUri = getTotpUri(acct?.email || "user@keyvex", secret, "KeyVEX");
    const qrSvgMarkup = generateQrSvg(otpUri);
    const qrWrap = h("div", {
      class: "qr-box glass",
      style: { width: "176px", height: "176px", padding: "10px", borderRadius: "18px", margin: "4px auto", background: "#fff" },
      html: qrSvgMarkup
    });

    const curPasskey = pinField({
      label: "Enter your Passkey",
      name: "enable-totp-passkey",
      length: acctPinLen,
      autofocus: true
    });
    const codeIn = pinField({ label: "6-Digit Authenticator Code", name: "totp-verify", length: 6, placeholder: "000000" });
    const copySecretBtn = h("button", {
      class: "btn glass",
      type: "button",
      onclick: () => {
        copySecret(secret, "Secret key copied", 25_000);
      }
    }, icon("copy", 16), " Copy Secret Key");

    formSheet({
      title: "Set up App-level lock (UI only)",
      action: "Verify & Enable Authenticator",
      text: "Scan the QR code or enter the secret key in Google Authenticator, Microsoft Authenticator, or 1Password, then confirm your Passkey and the 6-digit code below.",
      nodes: [
        notice("info", "App-level lock (UI only): prompts for a 6-digit TOTP code after sign-in and syncs inside your encrypted vault metadata."),
        qrWrap,
        h("div", {
          class: "code-block glass",
          style: {
            padding: "12px",
            fontFamily: "monospace",
            fontSize: "1.05rem",
            letterSpacing: "2px",
            textAlign: "center",
            wordBreak: "break-all",
            margin: "4px 0"
          }
        }, secret),
        copySecretBtn,
        curPasskey.root,
        codeIn.root
      ],
      run: async (sh) => {
        if (!curPasskey.input.value) throw new Error("Enter your current Passkey to continue.");
        const valid = await verifyTotpCode(secret, codeIn.input.value, 1, { checkReplay: false });
        if (!valid) throw new Error("Invalid authenticator code. Check the time on your device and try again.");
        const res = await vault.enableTotp(curPasskey.input.value, secret);
        sh.close();
        if (res?.backupCodes?.length) {
          showTotpBackupCodesSheet(res.backupCodes);
        } else {
          toast("App-level lock (UI only) enabled!");
        }
      }
    });
  };

  function showTotpBackupCodesSheet(codes = []) {
    const codesText = codes.join("\n");
    const sheet = openSheet({
      title: "Save your backup codes",
      content: [
        notice("info", "Save these 8 one-time backup codes in a safe place. Each code can be used once if you lose your phone."),
        h("pre", {
          class: "code-block glass mono",
          style: { padding: "14px", borderRadius: "16px", textAlign: "center", fontSize: "15px", lineHeight: "1.6", margin: "8px 0" }
        }, codesText),
        h("div", { class: "row-btns" },
          h("button", {
            class: "btn glass",
            type: "button",
            onclick: () => copySecret(codesText, "Backup codes copied", 25_000)
          }, icon("copy", 16), "Copy codes"),
          h("button", {
            class: "btn primary",
            type: "button",
            onclick: () => {
              sheet.close();
              toast("App-level lock (UI only) enabled!");
            }
          }, "I saved these codes")
        )
      ]
    });
  }

  // PART 4: Export backup requires current Passkey first
  const exportBackup = () => {
    const curPasskey = pinField({
      label: "Enter your Passkey",
      name: "export-backup-passkey",
      length: acctPinLen,
      autofocus: true
    });
    formSheet({
      title: "Export encrypted backup?",
      action: "Export Backup",
      text: "Enter your current Passkey to export an encrypted .json backup file. Keep it somewhere private.",
      nodes: [curPasskey.root],
      run: async (sh) => {
        if (!curPasskey.input.value) throw new Error("Enter your current Passkey to export a backup.");
        const json = await vault.exportBackup(curPasskey.input.value);
        sh.close();
        download(`keyvex-backup-${new Date().toISOString().slice(0, 10)}.json`, json);
        toast("Encrypted backup downloaded");
      }
    });
  };

  /**
   * Simplified Zero-Prompt Restore & Import:
   *   - No "Old KeyVEX" option.
   *   - No Backup Passkey, Backup Master Password, or Confirmation Passkey fields.
   *   - Simply choose a KeyVEX `.json` backup file or `.csv` export file and click "Import Passwords".
   *   - Imported passwords appear directly in the main vault (`All passwords`) with no extra badge or separate section.
   */
  const restoreImport = () => {
    let file = null;
    const warn = notice(
      "info",
      "Choose a KeyVEX backup (.json) or CSV password file to restore directly into your vault. Exact duplicates are automatically skipped."
    );
    const previewWrap = h("div", { class: "import-preview-wrap" });
    const fileBtn = h("button", { class: "btn glass", type: "button", onclick: () => picker.click() });
    const picker = h("input", {
      type: "file",
      accept: "application/json,.json,.csv,text/csv",
      hidden: true,
      onchange: async () => {
        file = picker.files[0] || null;
        previewWrap.replaceChildren();
        if (file && file.size > MAX_IMPORT_FILE_BYTES) {
          toast("File exceeds the 10 MB safety limit.");
          file = null;
          picker.value = "";
        } else if (file) {
          try {
            const text = await file.text();
            const isCsv = file.name.toLowerCase().endsWith(".csv") || !text.trim().startsWith("{");
            if (isCsv) {
              const parsed = csvToEntries(text);
              if (parsed.preview?.length) {
                previewWrap.replaceChildren(
                  h("div", { class: "notice info", style: { display: "grid", gap: "6px" } },
                    h("strong", null, `Ready to import: ${parsed.items.length} passwords found`),
                    ...parsed.preview.map((r) => h("div", { class: "small muted" }, `• ${r.service} (${r.username})`))
                  )
                );
              }
            } else {
              const items = typeof vault.readBackupAuto === "function"
                ? await vault.readBackupAuto(text)
                : await readBackup(text, { autoRestore: true, email: acct?.email || "" });
              if (items?.length) {
                previewWrap.replaceChildren(
                  h("div", { class: "notice info", style: { display: "grid", gap: "6px" } },
                    h("strong", null, `Ready to restore: ${items.length} passwords found`),
                    ...items.slice(0, 5).map((r) => h("div", { class: "small muted" }, `• ${r.service} (${r.username || "no username"})`))
                  )
                );
              }
            }
          } catch { /* preview optional */ }
        }
        paint();
      }
    });

    const paint = () => {
      fileBtn.replaceChildren(icon("upload", 18), file ? file.name : "Choose KeyVEX (.json) or CSV file");
    };

    paint();

    formSheet({
      title: "Restore & Import",
      action: "Import Passwords",
      nodes: [warn, fileBtn, picker, previewWrap],
      run: async (sh) => {
        if (!file) throw new Error("Choose a KeyVEX (.json) or CSV file first.");
        if (file.size > MAX_IMPORT_FILE_BYTES) throw new Error("File exceeds the 10 MB safety limit.");
        const text = await file.text();
        if (text.length > MAX_IMPORT_FILE_BYTES) throw new Error("File exceeds the 10 MB safety limit.");

        const isCsv = file.name.toLowerCase().endsWith(".csv") || !text.trim().startsWith("{");
        let items = [];
        if (isCsv) {
          const parsed = csvToEntries(text);
          if (!parsed.items.length) throw new Error("No usable rows found in that file.");
          items = parsed.items;
        } else {
          items = typeof vault.readBackupAuto === "function"
            ? await vault.readBackupAuto(text)
            : await readBackup(text, { autoRestore: true, email: acct?.email || "" });
          if (!items.length) throw new Error("That backup file has no passwords in it.");
        }

        const added = await vault.importEntries(items, "", {
          skipAuth: true
        });
        const skippedDups = Math.max(0, items.length - added);
        sh.close();
        onChange();
        toast(`Imported ${added} of ${items.length} passwords${skippedDups ? ` (${skippedDups} duplicate${skippedDups === 1 ? "" : "s"} skipped)` : ""}`);
      }
    });
  };

  const erase = () => {
    let googleVerified = false;
    const cur = currentPair(!isGoogleAccount);
    const reauthPw = isTwoLayer && !isGoogleAccount && acct?.hasPassword
      ? passwordField({
          label: "Account Password (for fresh session confirmation)",
          name: "delete-account-password",
          autocomplete: "current-password",
          placeholder: "Optional unless session expired"
        })
      : null;

    const googleVerifyStatus = h("div");
    const googleVerifyBtn = isGoogleAccount
      ? h("button", {
          class: "btn glass",
          type: "button",
          onclick: async () => {
            setBusy(googleVerifyBtn, true, "Verifying with Google…");
            try {
              await vault.verifyPasskeyResetIdentity({ googleSession: true });
              googleVerified = true;
              cur.passkey.root.hidden = true;
              googleVerifyBtn.hidden = true;
              googleVerifyStatus.replaceChildren(notice("info", `Google account (${acct.email}) verified. Click 'Delete everything' below to permanently delete your account.`));
            } catch (err) {
              toast(errText(err));
            } finally {
              setBusy(googleVerifyBtn, false);
            }
          }
        }, icon("user", 16), "Verify with Google")
      : null;

    const progressEl = h("div", { class: "small muted", "aria-live": "polite" });
    const nodes = isTwoLayer
      ? [
          ...(isGoogleAccount ? [googleVerifyBtn, googleVerifyStatus] : []),
          cur.passkey.root,
          ...(reauthPw ? [reauthPw.root] : []),
          progressEl
        ]
      : [cur.passkey.root, cur.master.root, progressEl];

    formSheet({
      title: "Delete account",
      action: "Delete everything",
      danger: true,
      text: isGoogleAccount
        ? "Verify with Google or enter your Passkey to permanently delete your account and all passwords."
        : "Your account and every password in it are deleted for good. Export a backup first if you might need it.",
      nodes,
      run: async () => {
        if (isGoogleAccount && (googleVerified || !cur.passkey.input.value)) {
          if (!vault.passkeyResetVerified) {
            await vault.verifyPasskeyResetIdentity({ googleSession: true });
          }
          googleVerified = true;
        } else if (!cur.passkey.input.value || (!isTwoLayer && !cur.master.input.value)) {
          throw new Error(isTwoLayer ? "Enter your Passkey to continue." : "Enter your Passkey and Master Password to continue.");
        }
        if (!(await confirmSheet({ title: "Delete your account?", text: "This is permanent. Your passwords will be gone from all your devices and can’t be recovered.", yes: "Yes, delete", danger: true }))) return;
        const res = await vault.deleteAccount(
          googleVerified ? "" : cur.passkey.input.value,
          isTwoLayer ? "" : cur.master.input.value,
          {
            googleVerified,
            accountPassword: reauthPw?.input?.value || null,
            onProgress: ({ deletedCount }) => {
              progressEl.textContent = `Deleted ${deletedCount} cloud records…`;
            }
          }
        );
        if (res?.state === "completed") {
          closeAllSheets();
          ctx.go("login", { notice: "Your account was deleted." });
        }
      }
    });
  };

  const deletionBannerWrap = h("div", { class: "deletion-recovery-wrap" });
  if (isTwoLayer && acct?.uid) {
    vault.getDeletionJobStatus(acct.uid).then((job) => {
      if (!job || job.state === "completed") return;
      const retryBtn = h("button", {
        class: "btn danger",
        type: "button",
        onclick: async () => {
          setBusy(retryBtn, true, "Resuming deletion…");
          try {
            const res = await vault.resumeAccountDeletion(acct.uid);
            if (res?.state === "completed") {
              closeAllSheets();
              ctx.go("login", { notice: "Your account deletion has been completed." });
            }
          } catch (err) {
            toast(errText(err));
          } finally {
            setBusy(retryBtn, false);
          }
        }
      }, icon("refresh", 16), "Retry Account Deletion");
      deletionBannerWrap.replaceChildren(
        h("div", { class: "notice err", style: { display: "grid", gap: "8px", marginBottom: "12px" } },
          h("strong", null, `Pending Account Deletion (${job.state})`),
          h("span", null, job.lastError?.message || "A previous account deletion was interrupted before completion."),
          retryBtn
        )
      );
    }).catch(() => {});
  }

  const syncTone = vault.syncStatus === "cloud" ? "info" : "warn";
  const syncLabel = vault.syncStatus === "cloud"
    ? `Synced with Cloud Firestore (${acct?.email})`
    : (vault.syncStatus === "pending"
        ? `Cloud sync pending (${vault.pendingOutboxCount || 1} queued change${vault.pendingOutboxCount === 1 ? "" : "s"}) — will retry when online`
        : "Local mode (changes saved in this browser)");

  openSheet({
    title: "Settings",
    content: [
      deletionBannerWrap,
      acct?.email && h("div", { class: "user-pill glass" },
        icon("user", 18),
        h("span", { class: "user-pill-text" },
          h("strong", null, acct.name || acct.email.split("@")[0]),
          h("small", { class: "muted" }, acct.email)
        )
      ),
      isTwoLayer && h("div", {
        class: "notice " + syncTone,
        style: { margin: "8px 0 16px 0", display: "flex", alignItems: "center", gap: "8px" }
      },
        icon(vault.syncStatus === "cloud" ? "check" : "alert", 16),
        syncLabel
      ),
      h("div", { class: "group-label" }, "General"),
      h("div", { class: "set-block" }, h("span", { class: "set-label" }, "Auto-lock after inactivity"), lockSeg),
      h("div", { class: "set-block" }, lockOnHideToggle),
      rememberDeviceToggle && h("div", { class: "set-block" }, rememberDeviceToggle),
      h("div", { class: "set-block" }, h("span", { class: "set-label" }, "Theme"), themeRow),
      !isInstalled() && row("download", "Install app / Add to Home Screen", "Open KeyVEX like a normal app and keep it available offline", () => { startInstallFlow(); }),
      row("info", "About KeyVEX", "Version 1.0 (Version 1.0.0) · Created by Abdullah Sakib", () => openAbout(ctx)),
      h("div", { class: "group-label" }, "Security"),
      row("key", "Change Passkey", "4-digit or 6-digit PIN for opening your vault", changePasskey),
      isTwoLayer && !isGoogleAccount && row("shield", "Change Account Password", "Update your Email & Password login credential", changeAccountPassword),
      !isTwoLayer && row("shield", "Change Master Password", "Guards every important action · needs both credentials", changeMaster),
      isTwoLayer && row("shield", "App-level lock (UI only)", acct?.totpEnabled ? "Enabled · Prompts for 6-digit Authenticator code after sign-in" : "Disabled · Add an app-level Authenticator code check on sign-in", manageTotp),
      row("lock", "Revoke Other Sessions", "Sign out all other devices and browsers", manageSessions),
      h("div", { class: "group-label" }, "Backup"),
      row("download", "Backup & Export", "Save an encrypted copy of your vault", exportBackup),
      row("upload", "Restore & Import", "Restore a KeyVEX backup (.json) or CSV into your vault", restoreImport),
      h("div", { class: "group-label" }, "Danger zone"),
      row("trash", "Delete account", "Erases your account and all passwords", erase, true),
      h("div", { class: "row-btns" },
        h("button", { class: "btn glass", type: "button", onclick: () => { closeAllSheets(); ctx.lockNow(); } }, icon("lock", 18), "Lock vault"),
        isTwoLayer && h("button", {
          class: "btn danger",
          type: "button",
          onclick: async () => {
            const ok = await confirmSheet({
              title: "Sign out of KeyVEX?",
              text: "Your vault will be locked and your active session on this browser will be closed.",
              yes: "Sign out",
              danger: true
            });
            if (!ok) return;
            closeAllSheets();
            await ctx.logoutAccount("Signed out of your account.");
          }
        }, icon("user", 18), "Log out")
      )
    ]
  });
}
