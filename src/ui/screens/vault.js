import { h } from "../dom.js";
import { icon } from "../icons.js";
import { brand } from "../components/brand.js";
import { avatar } from "../components/avatar.js";
import { copySecret, flash, toast } from "../components/feedback.js";
import { pinField, notice } from "../components/fields.js";
import { openSheet, setBusy } from "../components/sheet.js";
import { openDetail } from "../sheets/detail.js";
import { openPicker } from "../sheets/entryForm.js";
import { openGenerator } from "../sheets/generator.js";
import { openSecurityCheck } from "../sheets/audit.js";
import { openSettings, openAbout } from "../sheets/settings.js";
import { openShortcuts } from "../sheets/shortcuts.js";
import { getSettings, setSetting } from "../settings.js";
import { auditEntries } from "../../core/audit.js";
import { errText, logAuthError } from "../errors.js";

const CAT_ICON = { Social: "users", Email: "mail", Banking: "bank", Shopping: "bag", Work: "briefcase", Entertainment: "play", Other: "grid" };
const VIRTUAL_CHUNK_SIZE = 200;

/**
 * Responsive vault home (`src/ui/screens/vault.js`).
 *   - B10: Debounces vault search (120 ms) and virtualizes/chunks lists > 500 entries.
 *   - B25: Uses an `AbortController` registered via `ctx.registerScreenCleanup` so `document` keydown
 *     listeners are deterministically removed on lock/navigation without leaking.
 *   - B26: Entry rows are `<article class="entry glass">` with one primary `<button class="entry-main">`
 *     and separate sibling `.row-actions` buttons (zero interactive-in-interactive nesting).
 */
export function vaultScreen(ctx, props = {}) {
  const { vault } = ctx;
  const prefs = getSettings();
  const st = {
    q: "",
    cat: "All",
    first: true,
    sort: prefs.sort === "az" ? "az" : "recent",
    view: prefs.view === "list" ? "list" : "grid",
    renderLimit: VIRTUAL_CHUNK_SIZE,
    bulkMode: false,
    selectedIds: new Set()
  };

  let searchDebounceTimer = null;
  const keyAbort = new AbortController();

  ctx.registerScreenCleanup?.(() => {
    keyAbort.abort();
    if (searchDebounceTimer) {
      clearTimeout(searchDebounceTimer);
      searchDebounceTimer = null;
    }
  });

  const sideNav = h("nav", { class: "side-nav", "aria-label": "Library" });
  const stats = h("section", { class: "stats", "aria-label": "Overview" });
  const cats = h("div", { class: "cats", role: "tablist", "aria-label": "Categories" });
  const title = h("h2", { class: "section-title" });
  const count = h("span", { class: "muted small" });
  const bulkBarWrap = h("div", { hidden: true });
  const setPref = (k, v) => { st[k] = v; setSetting(k, v); render(); };
  const tools = h("div", { class: "view-tools" });

  const openBulkDeleteSheet = () => {
    const ids = [...st.selectedIds];
    if (!ids.length) return toast("Select at least one password first.");
    const acctPinLen = vault.account?.pinLength || vault.account?.meta?.pinLength || 6;
    const pk = pinField({
      label: "Enter your Passkey",
      name: "bulk-delete-passkey",
      length: acctPinLen,
      autofocus: true
    });
    const msg = h("div", { class: "flow-msg", "aria-live": "polite" });
    const delBtn = h("button", { class: "btn danger", type: "submit" }, `Delete ${ids.length} password${ids.length === 1 ? "" : "s"}`);
    const form = h("form", {
      novalidate: true,
      onsubmit: async (ev) => {
        ev.preventDefault();
        msg.replaceChildren();
        if (!pk.input.value) {
          msg.replaceChildren(notice("err", "Enter your current Passkey to delete selected items."));
          pk.input.focus();
          return;
        }
        setBusy(delBtn, true, "Deleting…");
        try {
          const res = await vault.removeMany(pk.input.value, ids);
          st.selectedIds.clear();
          st.bulkMode = false;
          sheet.close();
          render();
          toast(`Deleted ${res.removedCount} password${res.removedCount === 1 ? "" : "s"}`);
        } catch (err) {
          logAuthError("bulkDelete", err);
          msg.replaceChildren(notice("err", errText(err)));
        } finally {
          setBusy(delBtn, false);
        }
      }
    },
      h("p", { class: "muted" }, `Confirm your Passkey to permanently delete ${ids.length} selected password${ids.length === 1 ? "" : "s"}.`),
      pk.root,
      msg,
      delBtn
    );
    const sheet = openSheet({ title: "Delete selected passwords?", content: form });
  };

  const drawTools = () => tools.replaceChildren(
    h("button", {
      type: "button",
      class: "btn glass slim" + (st.bulkMode ? " on" : ""),
      onclick: () => {
        st.bulkMode = !st.bulkMode;
        if (!st.bulkMode) st.selectedIds.clear();
        render();
      }
    }, st.bulkMode ? "Done" : "Select"),
    h("div", { class: "seg mini", role: "radiogroup", "aria-label": "Sort" }, [["recent", "Recent"], ["az", "A–Z"]].map(([k, l]) =>
      h("button", { type: "button", role: "radio", class: st.sort === k ? "on" : "", "aria-checked": String(st.sort === k), onclick: () => setPref("sort", k) }, l))),
    h("div", { class: "seg mini icons", role: "radiogroup", "aria-label": "Layout" }, [["grid", "Grid view", "grid"], ["list", "List view", "list"]].map(([k, l, i]) =>
      h("button", { type: "button", role: "radio", class: st.view === k ? "on" : "", "aria-checked": String(st.view === k), "aria-label": l, title: l, onclick: () => setPref("view", k) }, icon(i, 16)))));

  const list = h("div", { class: "entries" });
  const empty = h("div", { class: "empty-wrap" });

  const refresh = () => render();
  const open = (id) => openDetail(ctx, id, refresh);
  const add = () => openPicker(ctx, refresh);
  const security = () => openSecurityCheck(ctx, refresh);
  const settings = () => openSettings(ctx, refresh);
  const about = () => openAbout(ctx);
  const generator = () => openGenerator({ vault });
  const syncNow = async () => {
    try {
      await vault.sync();
      render();
      toast("Vault synchronized");
    } catch (err) {
      if (err?.code === "PASSKEY_CHANGED_REMOTELY") {
        ctx.lockNow(err.message);
        return;
      }
      toast("Offline — changes saved locally");
    }
  };

  const copyBtn = (iconName, label, text, msg, secret) => h("button", { class: "icon-btn", type: "button", "aria-label": label, title: label,
    onclick: (ev) => { ev.stopPropagation(); if (!text) return toast("Nothing to copy"); flash(ev.currentTarget); copySecret(text, msg, secret ? 25_000 : 0); } }, icon(iconName, 18));

  // B26: <article class="entry glass"> with one primary <button class="entry-main"> and separate sibling action buttons
  const row = (e, i) => {
    const isSelected = st.selectedIds.has(e.id);
    return h("article", { class: "entry glass", style: { "--i": i } },
      st.bulkMode && h("label", { class: "entry-select-box", "aria-label": `Select ${e.service}` },
        h("input", {
          type: "checkbox",
          checked: isSelected ? true : null,
          onchange: (ev) => {
            if (ev.target.checked) st.selectedIds.add(e.id);
            else st.selectedIds.delete(e.id);
            render();
          }
        })
      ),
      h("button", {
        class: "entry-main",
        type: "button",
        "aria-label": `Open ${e.service || "Saved Password"}`,
        onclick: () => {
          if (st.bulkMode) {
            if (st.selectedIds.has(e.id)) st.selectedIds.delete(e.id);
            else st.selectedIds.add(e.id);
            render();
            return;
          }
          open(e.id);
        }
      },
        avatar(e.service),
        h("span", { class: "meta" },
          h("span", { class: "name" },
            e.service || "Saved Password",
            e.favorite && h("span", { class: "fav", title: "Favorite" }, icon("star", 13))
          ),
          h("span", { class: "sub" }, e.username || e.website || "No username"))
      ),
      h("span", { class: "row-actions" },
        h("button", { class: "icon-btn fav-btn" + (e.favorite ? " on" : ""), type: "button", "aria-label": e.favorite ? `Remove ${e.service} from favorites` : `Add ${e.service} to favorites`, "aria-pressed": String(!!e.favorite), title: "Favorite",
          onclick: async (ev) => { ev.stopPropagation(); await vault.save({ ...e, favorite: !e.favorite }); render(); } }, icon(e.favorite ? "star" : "starOutline", 18)),
        copyBtn("user", `Copy username for ${e.service}`, e.username, "Username copied"),
        copyBtn("key", `Copy password for ${e.service}`, e.password, "Password copied", true)
      )
    );
  };

  const navItem = (key, label, iconName, n) => h("button", { class: "nav-item" + (st.cat === key ? " on" : ""), type: "button", "aria-current": st.cat === key ? "page" : null,
    onclick: () => { st.cat = key; st.renderLimit = VIRTUAL_CHUNK_SIZE; render(); } }, icon(iconName, 20), h("span", { class: "grow label" }, label), n != null && h("span", { class: "n" }, String(n)));

  const tile = (iconName, value, label, tone, onclick) => h(onclick ? "button" : "div", { class: `tile glass ${tone || ""}`, type: onclick ? "button" : null, onclick },
    h("span", { class: "tile-ico" }, icon(iconName, 20)), h("span", { class: "tile-val" }, value), h("span", { class: "tile-label" }, label));

  function render() {
    const all = vault.list();
    const term = st.q.trim().toLowerCase();
    const byCat = (c) => all.filter((e) => (e.category === "Imported" ? "Other" : e.category) === c).length;
    const favs = all.filter((e) => e.favorite).length;

    sideNav.replaceChildren(
      h("div", { class: "group-label" }, "Library"),
      navItem("All", "All passwords", "layers", all.length),
      navItem("Favorites", "Favorites", "star", favs),
      h("div", { class: "group-label" }, "Categories"),
      ...vault.categories.map((c) => navItem(c, c, CAT_ICON[c], byCat(c))));
    const tabList = ["All", "Favorites", ...vault.categories];
    cats.replaceChildren(...tabList.map((c) => h("button", { class: "cat" + (st.cat === c ? " on" : ""), type: "button", role: "tab", "aria-selected": String(st.cat === c),
      onclick: () => { st.cat = c; st.renderLimit = VIRTUAL_CHUNK_SIZE; render(); } }, c)));

    const a = auditEntries(all);
    const flagged = new Set([...a.weak, ...a.reused, ...a.old].map((e) => e.id)).size;
    const score = all.length ? Math.round(100 * (1 - flagged / all.length)) : 100;
    stats.replaceChildren(
      tile("key", all.length, "Passwords", "", () => { st.cat = "All"; st.renderLimit = VIRTUAL_CHUNK_SIZE; render(); }),
      tile("star", favs, "Favorites", "", () => { st.cat = "Favorites"; st.renderLimit = VIRTUAL_CHUNK_SIZE; render(); }),
      tile("shield", all.length ? score + "%" : "—", "Security score", score >= 80 || !all.length ? "good" : "warn", security),
      tile("alert", flagged, "Need attention", flagged ? "warn" : "good", security));

    const items = all.filter((e) => {
      const cat = e.category === "Imported" ? "Other" : e.category;
      return (st.cat === "All" || (st.cat === "Favorites" ? e.favorite : cat === st.cat)) &&
        (!term || [e.service, e.username, e.website].some((v) => String(v || "").toLowerCase().includes(term)));
    });
    title.textContent = term ? "Results" : st.cat === "All" ? "All passwords" : st.cat;
    count.textContent = `${items.length} ${items.length === 1 ? "item" : "items"}`;
    if (st.sort === "az") items.sort((a, b) => String(a.service || "").localeCompare(String(b.service || ""), undefined, { sensitivity: "base" }));
    list.classList.toggle("list", st.view === "list");
    drawTools();

    bulkBarWrap.replaceChildren();
    bulkBarWrap.hidden = !st.bulkMode;
    if (st.bulkMode) {
      bulkBarWrap.append(
        h("div", { class: "bulk-bar glass" },
          h("span", { class: "small" }, `${st.selectedIds.size} selected`),
          h("div", { class: "bulk-bar-actions" },
            h("button", {
              class: "btn glass slim",
              type: "button",
              onclick: () => {
                items.forEach((it) => st.selectedIds.add(it.id));
                render();
              }
            }, "Select all"),
            h("button", {
              class: "btn danger slim",
              type: "button",
              disabled: st.selectedIds.size === 0 ? true : null,
              onclick: openBulkDeleteSheet
            }, icon("trash", 16), `Delete selected (${st.selectedIds.size})`)
          )
        )
      );
    }

    // B10: Virtualize / window lists > 500 entries so large vaults never freeze the DOM
    const shouldWindow = items.length > 500 && items.length > st.renderLimit;
    const visibleItems = shouldWindow ? items.slice(0, st.renderLimit) : items;
    const nodes = visibleItems.map(row);
    if (shouldWindow) {
      nodes.push(
        h("button", {
          class: "btn glass",
          type: "button",
          onclick: () => {
            st.renderLimit += VIRTUAL_CHUNK_SIZE;
            render();
          }
        }, `Show more (${items.length - visibleItems.length} remaining)`)
      );
    }
    list.replaceChildren(...nodes);
    list.hidden = nodes.length === 0;
    if (st.first) { list.classList.add("enter"); st.first = false; setTimeout(() => list.classList.remove("enter"), 1200); }

    empty.replaceChildren();
    empty.hidden = items.length > 0;
    if (!all.length) {
      empty.append(h("div", { class: "empty glass" }, h("div", { class: "empty-ico" }, icon("lock", 28)), h("h3", null, "Your vault is empty"), h("p", { class: "muted" }, "Add your first login. It’s encrypted on your device before it’s saved."), h("button", { class: "btn primary", type: "button", onclick: add }, icon("plus", 18), "Add a password")));
    } else if (!items.length) {
      empty.append(h("div", { class: "empty glass" }, h("div", { class: "empty-ico" }, icon("search", 28)), h("h3", null, "Nothing matches"), h("p", { class: "muted" }, "Try another word, or add it as a new password.")));
    }
  }

  // B10: 120 ms debounced search input
  const search = h("input", {
    type: "search",
    placeholder: "Search passwords",
    "aria-label": "Search passwords",
    autocomplete: "off",
    oninput: (e) => {
      const nextQ = e.target.value;
      st.q = nextQ;
      st.renderLimit = VIRTUAL_CHUNK_SIZE;
      if (searchDebounceTimer) clearTimeout(searchDebounceTimer);
      searchDebounceTimer = setTimeout(() => {
        searchDebounceTimer = null;
        render();
      }, 120);
    }
  });
  const dock = (name, label, fn, on) => h("button", { class: "dock-btn" + (on ? " on" : ""), type: "button", "aria-label": label, title: label, onclick: fn }, icon(name, 22));
  const sideLink = (name, label, fn) => h("button", { class: "nav-item", type: "button", onclick: fn }, icon(name, 20), h("span", { class: "grow label" }, label));

  const root = h("main", { class: "screen vault shell" },
    h("aside", { class: "sidebar glass" },
      brand({ size: "sm", slogan: false }),
      h("button", { class: "btn primary add-btn", type: "button", onclick: add }, icon("plus", 18), "Add password"),
      sideNav,
      h("div", { class: "side-foot" },
        sideLink("refresh", "Sync vault", syncNow),
        sideLink("shield", "Security check", security),
        sideLink("wand", "Password generator", generator),
        sideLink("keyboard", "Keyboard shortcuts", openShortcuts),
        sideLink("info", "About KeyVEX", about),
        sideLink("gear", "Settings", settings))),
    h("div", { class: "content" },
      h("header", { class: "topbar" },
        h("div", { class: "mobile-brand" }, brand({ size: "sm", slogan: false })),
        h("div", { class: "search-pill glass" }, icon("search", 20), search, h("kbd", { class: "kbd", "aria-hidden": "true" }, "/")),
        h("button", { class: "btn glass slim top-gen", type: "button", onclick: generator }, icon("wand", 18), "Generator"),
        h("button", { class: "btn primary slim top-add", type: "button", onclick: add }, icon("plus", 18), "Add"),
        h("button", { class: "round glass m-only", type: "button", "aria-label": "Sync vault", title: "Sync vault", onclick: syncNow }, icon("refresh", 20)),
        h("button", { class: "round glass m-only", type: "button", "aria-label": "Settings", onclick: settings }, icon("gear", 20)),
        h("button", { class: "round glass m-only", type: "button", "aria-label": "Lock vault", title: "Lock vault", onclick: () => ctx.lockNow() }, icon("lock", 20))),
      stats,
      h("button", { class: "promo m-only", type: "button", onclick: generator },
        h("span", { class: "promo-ico" }, icon("wand", 20)),
        h("span", { class: "meta" }, h("span", { class: "name" }, "Make a strong password"), h("span", { class: "sub" }, "Random, unbiased, one tap")), icon("chevron", 18)),
      cats,
      h("div", { class: "section-head" }, h("div", { class: "head-l" }, title, count), tools),
      bulkBarWrap,
      list, empty),
    h("nav", { class: "dock glass", "aria-label": "Main" },
      dock("home", "Top", () => scrollTo({ top: 0, behavior: "smooth" }), true),
      dock("shield", "Security check", security),
      h("button", { class: "dock-add", type: "button", "aria-label": "Add password", onclick: add }, icon("plus", 24)),
      dock("wand", "Password generator", generator),
      dock("gear", "Settings", settings)));

  const onKey = (e) => {
    if (keyAbort.signal.aborted || !root.isConnected) {
      document.removeEventListener("keydown", onKey);
      return;
    }
    if (!e.key || e.ctrlKey || e.metaKey || e.altKey || /^(INPUT|TEXTAREA|SELECT)$/.test(e.target?.tagName || "") || document.querySelector(".sheet-wrap")) return;
    const k = e.key.toLowerCase();
    const run = { "/": () => search.focus(), n: add, g: generator, s: security, ",": settings, l: () => ctx.lockNow(), "?": openShortcuts }[k];
    if (run) { e.preventDefault(); run(); }
  };
  document.addEventListener("keydown", onKey);
  keyAbort.signal.addEventListener("abort", () => {
    document.removeEventListener("keydown", onKey);
  });

  render();
  if (props.skipped) setTimeout(() => toast(`${props.skipped} item(s) couldn’t be decrypted and were skipped.`), 600);
  return root;
}
