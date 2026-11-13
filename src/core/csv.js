/**
 * Import from the CSV files other password managers export (Chrome, Edge, Firefox, Bitwarden, 1Password, LastPass…).
 * Pure functions, no DOM. Supports automatic delimiter detection (`,`, `;`, `\t`) and 10 MB size cap (B17).
 */
import { MAX_IMPORT_FILE_BYTES } from "./backup.js";

export function detectCsvDelimiter(text) {
  const src = String(text || "").replace(/^\uFEFF/, "");
  let firstLine = "";
  let inQuotes = false;
  for (let i = 0; i < src.length && i < 4096; i++) {
    const c = src[i];
    if (c === '"') {
      if (src[i + 1] === '"') i++;
      else inQuotes = !inQuotes;
    } else if (!inQuotes && (c === "\n" || c === "\r")) {
      break;
    }
    firstLine += c;
  }
  const counts = { ",": 0, ";": 0, "\t": 0 };
  inQuotes = false;
  for (let i = 0; i < firstLine.length; i++) {
    const c = firstLine[i];
    if (c === '"') {
      if (firstLine[i + 1] === '"') i++;
      else inQuotes = !inQuotes;
    } else if (!inQuotes && c in counts) {
      counts[c]++;
    }
  }
  if (counts[";"] > counts[","] && counts[";"] >= counts["\t"]) return ";";
  if (counts["\t"] > counts[","] && counts["\t"] > counts[";"]) return "\t";
  return ",";
}

/** RFC 4180-style parser: quoted fields, escaped quotes, newlines inside quotes, CRLF, BOM, auto-detected delimiter. */
export function parseCSV(text, delimiter = null) {
  const raw = String(text ?? "");
  if (raw.length > MAX_IMPORT_FILE_BYTES) {
    const err = new Error("CSV file exceeds the 10 MB safety limit.");
    err.code = "FILE_TOO_LARGE";
    throw err;
  }
  const src = raw.replace(/^\uFEFF/, "");
  const sep = delimiter || detectCsvDelimiter(src);
  const rows = [];
  let row = [], field = "", quoted = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (quoted) {
      if (c === '"') { if (src[i + 1] === '"') { field += '"'; i++; } else quoted = false; }
      else field += c;
    } else if (c === '"' && field === "") quoted = true;
    else if (c === sep) { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && src[i + 1] === "\n") i++;
      row.push(field); field = "";
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
    } else field += c;
  }
  row.push(field);
  if (row.some((v) => v !== "")) rows.push(row);
  return rows;
}

const ALIASES = {
  service: ["name", "title", "service", "site", "account", "login_name"],
  website: ["url", "login_uri", "website", "web site", "origin", "uri", "address"],
  username: ["username", "login_username", "user", "login", "email", "user name"],
  password: ["password", "login_password", "pass", "pwd"],
  notes: ["note", "notes", "extra", "comments"],
  category: ["folder", "grouping", "group", "category", "type"],
  favorite: ["favorite", "fav", "favourite"]
};
const CATS = { social: "Social", email: "Email", mail: "Email", bank: "Banking", banking: "Banking", finance: "Banking", shop: "Shopping", shopping: "Shopping", work: "Work", business: "Work", entertainment: "Entertainment", streaming: "Entertainment" };

const hostOf = (url) => { try { return new URL(/^[a-z][a-z0-9+.-]*:/i.test(url) ? url : "https://" + url).hostname.replace(/^www\./, ""); } catch { return ""; } };

/** @returns {{ items: object[], skipped: number, delimiter: string, preview: object[] }} entries ready for Vault.importEntries */
export function csvToEntries(text) {
  const raw = String(text ?? "");
  if (raw.length > MAX_IMPORT_FILE_BYTES) {
    const err = new Error("CSV file exceeds the 10 MB safety limit.");
    err.code = "FILE_TOO_LARGE";
    throw err;
  }
  const delimiter = detectCsvDelimiter(raw);
  const rows = parseCSV(raw, delimiter);
  if (rows.length < 2) throw new Error("That file has no rows to import.");
  const head = rows[0].map((h) => h.trim().toLowerCase());
  const col = {};
  for (const [key, names] of Object.entries(ALIASES)) col[key] = head.findIndex((h) => names.includes(h));
  if (col.password < 0 || (col.service < 0 && col.website < 0)) throw new Error("Couldn’t find password and name/url columns. Is this a password export?");
  const items = []; let skipped = 0;
  for (const r of rows.slice(1)) {
    const get = (k) => (col[k] >= 0 ? (r[col[k]] ?? "").trim() : "");
    const website = get("website"), password = r[col.password] ?? "";
    const service = get("service") || hostOf(website);
    if (!service || !password) { skipped++; continue; }
    const cat = get("category").toLowerCase();
    items.push({
      service, website, username: get("username"), password, notes: get("notes"),
      category: CATS[cat] || "Other", favorite: ["1", "true", "yes"].includes(get("favorite").toLowerCase())
    });
  }
  // Safe preview of first 5 rows WITHOUT passwords (B17)
  const preview = items.slice(0, 5).map(({ service, username, website, category }) => ({
    service,
    username: username || "—",
    website: website || "—",
    category
  }));
  return { items, skipped, delimiter, preview };
}
