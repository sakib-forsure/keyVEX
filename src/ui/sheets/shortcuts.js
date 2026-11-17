import { h } from "../dom.js";
import { openSheet } from "../components/sheet.js";

const KEYS = [["/", "Search"], ["N", "New password"], ["G", "Password generator"], ["S", "Security check"], [",", "Settings"], ["L", "Sign out"], ["?", "Show this list"], ["Esc", "Close a window"]];

export function openShortcuts() {
  return openSheet({ title: "Keyboard shortcuts", content: [
    h("div", { class: "shortcuts" }, KEYS.map(([k, label]) => h("div", { class: "sc-row" }, h("span", null, label), h("kbd", { class: "kbd" }, k)))),
    h("p", { class: "tiny muted" }, "Shortcuts work when you’re not typing in a field.")
  ] });
}
