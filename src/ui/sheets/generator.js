import { h } from "../dom.js";
import { icon } from "../icons.js";
import { openSheet, confirmSheet } from "../components/sheet.js";
import { copySecret, flash, strengthMeter, toast } from "../components/feedback.js";
import { generatePassword } from "../../core/generator.js";
import { strength } from "../../core/strength.js";

function formatTimestamp(ms) {
  const d = new Date(Number(ms) || Date.now());
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

/**
 * Opens the dedicated Password Generator History popup modal (`openGeneratorHistorySheet`)
 * showing the total number of generated passwords, date & time for each entry, copy, individual delete,
 * and Clear All confirmation.
 */
export function openGeneratorHistorySheet(vault, onHistoryChange) {
  const countBadge = h("div", { class: "notice info", style: { display: "flex", justifyContent: "space-between", alignItems: "center" } });
  const historyListEl = h("div", { class: "gen-history-list", role: "list", "aria-label": "Generated password history" });

  const clearHistoryBtn = h("button", {
    class: "btn danger slim",
    type: "button",
    onclick: async () => {
      if (!vault?.unlocked) return;
      const items = vault.listGeneratorHistory();
      if (!items.length) return;
      const confirmed = await confirmSheet({
        title: "Clear generator history?",
        text: "All saved passwords in your encrypted generator history will be permanently removed.",
        yes: "Clear history",
        danger: true
      });
      if (!confirmed) return;
      await vault.clearGeneratorHistory();
      renderHistoryPopup();
      onHistoryChange?.();
      toast("Generator history cleared");
    }
  }, icon("trash", 15), "Clear History");

  function renderHistoryPopup() {
    if (!vault?.unlocked || typeof vault.listGeneratorHistory !== "function") {
      countBadge.replaceChildren(
        h("strong", null, "Encrypted History Locked"),
        h("span", { class: "small muted" }, "Unlock your vault to view generated passwords.")
      );
      historyListEl.replaceChildren(h("p", { class: "muted small" }, "Unlock your vault to save and view encrypted generator history."));
      clearHistoryBtn.hidden = true;
      return;
    }

    const items = vault.listGeneratorHistory();
    countBadge.replaceChildren(
      h("strong", null, `Total Passwords Generated: ${items.length}`),
      h("span", { class: "small muted" }, "AES-256-GCM Encrypted")
    );
    clearHistoryBtn.hidden = items.length === 0;

    if (!items.length) {
      historyListEl.replaceChildren(h("p", { class: "muted small" }, "No generated passwords in history yet."));
      return;
    }

    historyListEl.replaceChildren(
      ...items.map((item, idx) =>
        h("div", { class: "gen-history-item glass", role: "listitem", "data-history-id": item.id },
          h("div", { class: "gen-history-meta" },
            h("span", { class: "gen-history-pw mono" }, item.password),
            h("span", { class: "gen-history-time" }, `#${items.length - idx} · ${formatTimestamp(item.createdAt)} · ${item.length || item.password.length} chars`)
          ),
          h("div", { class: "gen-history-actions" },
            h("button", {
              class: "icon-btn",
              type: "button",
              "aria-label": "Copy historical password",
              title: "Copy password",
              onclick: (e) => {
                flash(e.currentTarget);
                copySecret(item.password, "Password copied");
              }
            }, icon("copy", 16)),
            h("button", {
              class: "icon-btn",
              type: "button",
              "aria-label": "Delete history item",
              title: "Delete from history",
              onclick: async () => {
                await vault.removeGeneratorHistoryItem(item.id);
                renderHistoryPopup();
                onHistoryChange?.();
                toast("Removed from generator history");
              }
            }, icon("trash", 16))
          )
        )
      )
    );
  }

  renderHistoryPopup();

  return openSheet({
    title: "Generated Password History",
    content: [
      countBadge,
      h("div", { class: "gen-history-head", style: { display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "4px" } },
        h("span", { class: "group-label" }, "Recent Passwords (with Date & Time)"),
        clearHistoryBtn
      ),
      historyListEl
    ]
  });
}

/**
 * Password generator sheet with a dedicated "View History" button that opens the
 * Encrypted Password Generator History popup (`src/ui/sheets/generator.js`).
 * Never logs or stores generated passwords in plaintext.
 */
export function openGenerator(arg = {}) {
  const vault = arg?.vault || null;
  const onUse = typeof arg?.onUse === "function" ? arg.onUse : null;
  const opts = { length: 18, lower: true, upper: true, digits: true, symbols: true };
  let current = "";
  const out = h("output", { class: "gen-out mono", "aria-live": "polite" });
  const meter = strengthMeter();
  const lenLabel = h("strong", null, String(opts.length));

  const historyBtnLabel = h("span", null, "View Encrypted History (0)");
  const historyBtn = h("button", {
    class: "btn glass",
    type: "button",
    "data-action": "open-generator-history",
    onclick: () => openGeneratorHistorySheet(vault, updateHistoryButton)
  }, icon("clock", 18), historyBtnLabel);

  function updateHistoryButton() {
    if (!vault?.unlocked || typeof vault.listGeneratorHistory !== "function") {
      historyBtnLabel.textContent = "View Encrypted History";
      return;
    }
    const count = vault.listGeneratorHistory().length;
    historyBtnLabel.textContent = `View Encrypted History (${count} generated)`;
  }

  const recordToHistory = async (pw) => {
    if (vault?.unlocked && typeof vault.addGeneratorHistory === "function" && pw) {
      try {
        await vault.addGeneratorHistory(pw);
        updateHistoryButton();
      } catch {
        /* ignore if vault locked */
      }
    }
  };

  const make = (record = true) => {
    try { current = generatePassword(opts); } catch { return; }
    out.textContent = current;
    meter.update(strength(current));
    out.classList.remove("pop"); void out.offsetWidth; out.classList.add("pop");
    if (record) {
      recordToHistory(current);
    }
  };

  const slider = h("input", {
    type: "range",
    min: 8,
    max: 64,
    value: opts.length,
    "aria-label": "Password length",
    oninput: (e) => {
      opts.length = +e.target.value;
      lenLabel.textContent = e.target.value;
      make(true);
    }
  });

  const toggle = (key, label) => {
    const b = h("button", { type: "button", class: "chip-toggle on", "aria-pressed": "true" }, label);
    b.addEventListener("click", () => {
      const on = [opts.lower, opts.upper, opts.digits, opts.symbols].filter(Boolean).length;
      if (opts[key] && on === 1) return; // keep at least one set
      opts[key] = !opts[key];
      b.classList.toggle("on", opts[key]);
      b.setAttribute("aria-pressed", String(opts[key]));
      make(true);
    });
    return b;
  };

  const copyBtn = h("button", {
    class: "icon-btn",
    type: "button",
    "aria-label": "Copy password",
    onclick: (e) => {
      flash(e.currentTarget);
      copySecret(current, "Password copied");
      recordToHistory(current);
    }
  }, icon("copy", 18));

  const regen = h("button", {
    class: "icon-btn",
    type: "button",
    "aria-label": "Generate another",
    onclick: () => make(true)
  }, icon("refresh", 18));

  const sheet = openSheet({
    title: "Password generator",
    content: [
      h("div", { class: "gen-box glass" }, out, h("div", { class: "gen-actions" }, regen, copyBtn)),
      meter,
      h("div", { class: "range-row" }, h("span", null, "Length"), lenLabel),
      slider,
      h("div", { class: "chips-wrap" }, toggle("lower", "a–z"), toggle("upper", "A–Z"), toggle("digits", "0–9"), toggle("symbols", "!@#")),
      h("button", {
        class: "btn primary",
        type: "button",
        onclick: async () => {
          await recordToHistory(current);
          if (onUse) {
            onUse(current);
            sheet.close();
          } else {
            copySecret(current, "Password copied");
          }
        }
      }, onUse ? "Use this password" : "Copy password"),
      historyBtn
    ]
  });

  make(true);
  updateHistoryButton();
  return sheet;
}
