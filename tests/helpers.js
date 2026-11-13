import { createApp } from "../server/app.js";
import { Api } from "../src/core/api.js";
import { Vault } from "../src/core/vault.js";
import { useFastKdfForTests } from "../src/core/crypto.js";

useFastKdfForTests();

export const PIN = "482916";
export const MASTER = "Blue Moon River 42!";
export const sample = { service: "GitHub", website: "github.com", username: "me@x.com", password: "S3cret!pass", category: "Work" };

/** A real server on a random port with an in-memory database. */
export async function startServer(opts = {}) {
  const app = createApp({ ...opts });
  await new Promise((ok) => app.server.listen(0, "127.0.0.1", ok));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  return { ...app, base, newApi: () => new Api(base), newVault: () => new Vault(new Api(base)) };
}
