import test from "node:test";
import assert from "node:assert/strict";
import { englishMessages, getLanguage, interpolateUI, setLanguage, subscribeLanguage, translateUI, spaceInterfaceText } from "../src/localization.js";
import { actionLabels, actionName, actionOption, roleName, resourceName } from "../src/presentation.js";
import { agentPresentation } from "../src/features/agent-workspace/catalog-presentation.js";

test("language preference notifies subscribers once and rejects unsupported choices", () => {
  setLanguage("zh-CN");
  let changes = 0;
  const unsubscribe = subscribeLanguage(() => changes++);
  try {
    setLanguage("en"); setLanguage("en");
    assert.equal(getLanguage(), "en"); assert.equal(changes, 1);
    assert.throws(() => setLanguage("xx"));
    assert.equal(getLanguage(), "en");
    unsubscribe(); setLanguage("zh-CN"); assert.equal(changes, 1);
  } finally { unsubscribe(); setLanguage("zh-CN"); }
});

test("complete messages translate while identifiers, JSON and unmatched business text stay intact", () => {
  assert.equal(translateUI("开始处理任务", "en"), "Start task");
  assert.equal(translateUI("  开始处理任务  ", "en"), "  Start task  ");
  for (const data of ['{"message":"开始处理任务"}', "skill.load", "D:/工作/开始处理任务", "客户说：开始处理任务", 42, null]) assert.equal(translateUI(data, "en"), data);
  assert.equal(translateUI("开始处理任务", "zh-CN"), "开始处理任务");
  assert.equal(interpolateUI("{{0}}（编号 {{1}}）", ["业务中文名", "a.$[x]"], "en"), "业务中文名 (ID a.$[x])");
  assert.equal(translateUI("Mapping a.$[x] 已发布。并发修改时服务端会以 revision 拒绝旧页面提交。", "en"), "Mapping a.$[x] published. The server rejects outdated revisions if changes are made concurrently.");
});

test("all built-in permission actions have English labels without changing command codes", () => {
  setLanguage("en");
  try {
    for (const [code, label] of Object.entries(actionLabels)) {
      assert.ok(englishMessages[label], `${code} is untranslated`);
      assert.doesNotMatch(actionName(code), /[\u3400-\u9fff]/, code);
    }
    const action = Object.freeze({ code: "history.export", resource_type: "agent_installation", sensitive: true });
    assert.equal(actionOption(action), "Export conversation history · Agent (sensitive action)");
    assert.equal(action.code, "history.export");
    assert.equal(roleName("operator"), "Business operator");
    assert.equal(resourceName("model", "model-1"), "Model (ID model-1)");
  } finally { setLanguage("zh-CN"); }
});

test("English word spacing keeps form elements at the same child indices", () => {
  const field = Object.freeze({ name: "reason", value: "用户输入" });
  const sequence = ["Total", 5, "records", field, "Try it.", "Examples"];
  const result = spaceInterfaceText(sequence, "en");
  assert.deepEqual(result, ["Total", " 5", " records", field, "Try it.", " Examples"]);
  assert.equal(result.length, sequence.length); assert.equal(result[3], field);
  assert.equal(spaceInterfaceText(sequence, "zh-CN"), sequence);
});

test("new examples follow the chosen language without rewriting an existing draft", () => {
  setLanguage("zh-CN");
  const draft = agentPresentation({ agent_id: "example-python-documents" }).exampleInput;
  setLanguage("en");
  try {
    const english = agentPresentation({ agent_id: "example-python-documents" });
    assert.equal(english.name, "Python document assistant");
    assert.deepEqual(JSON.parse(english.exampleInput), { question: "How can incremental document updates remain consistent?", top_k: 3, cache_mode: "use" });
    assert.equal(JSON.parse(draft).question, "文档增量更新如何保持一致性？");
  } finally { setLanguage("zh-CN"); }
});
