import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { isIntegrationAdmin } from "../src/config.js";

const app = await readFile(new URL("../src/App.jsx", import.meta.url), "utf8");
const page = await readFile(new URL("../src/features/identity/MachineCredentialAdmin.jsx", import.meta.url), "utf8");

test("machine credential controls require independent integration management authority", () => {
  assert.match(app, /label: "机器身份凭证"/);
  assert.match(app, /path="\/platform\/machine-credentials" element=\{<Guard when=\{isIntegrationAdmin\(user\)\}>/);
  assert.equal(isIntegrationAdmin({ policy_mode: "v2", capabilities: ["machine.manage"] }), true);
  assert.equal(isIntegrationAdmin({ policy_mode: "v2", capabilities: ["platform.monitor"] }), false);
  assert.equal(isIntegrationAdmin({ policy_mode: "v2", capabilities: ["authorization.change"] }), false);
  assert.equal(isIntegrationAdmin({ policy_mode: "v2", capabilities: [] }), false);
  assert.match(page, /api\.identityMachineCredentials\(/);
  assert.match(page, /api\.createIdentityMachineCredential\(/);
  assert.match(page, /api\.rotateIdentityMachineCredential\(/);
  assert.match(page, /api\.disableIdentityMachineCredential\(/);
});

test("new client secret is displayed only in volatile page state and warned as one-time", () => {
  assert.match(page, /setIssued\(created\)/);
  assert.match(page, /一次性 Secret/);
  assert.match(page, /Secret 不返回列表、不进入 localStorage\/sessionStorage/);
  assert.doesNotMatch(page, /localStorage\.setItem|sessionStorage\.setItem/);
});
