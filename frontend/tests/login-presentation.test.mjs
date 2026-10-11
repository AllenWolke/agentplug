import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const app = readFileSync(new URL("../src/App.jsx", import.meta.url), "utf8");
const config = readFileSync(new URL("../src/config.js", import.meta.url), "utf8");

test("login page does not publish demo identities or prefill an account", () => {
  assert.doesNotMatch(app, /MVP 演示身份|demo-accounts|DEMO_ACCOUNTS/);
  assert.doesNotMatch(config, /DEMO_ACCOUNTS/);
  assert.match(app, /username: "", password: ""/);
  assert.match(app, /<b>AgentPlug<\/b>/);
});
