import test from "node:test";
import assert from "node:assert/strict";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AnswerText } from "../src/renderers/AnswerText.js";

test("answers display readable headings, lists and inline code", () => {
  const rendered = renderToStaticMarkup(React.createElement(AnswerText, { text: "## 排查建议\n1. 查看 `runtime.inspect`\n2. 核对 **日志**\n\n来源：知识文档" }));
  assert.match(rendered, /<h4>排查建议<\/h4>/);
  assert.match(rendered, /<ol><li>查看 <code>runtime.inspect<\/code><\/li><li>核对 <strong>日志<\/strong><\/li><\/ol>/);
  assert.match(rendered, /来源：知识文档/);
});

test("untrusted answer HTML, executable URLs and fences never become active markup", () => {
  const rendered = renderToStaticMarkup(React.createElement(AnswerText, { text: '<img src=x onerror=alert(1)>\n[click](javascript:alert(1))\n\n```html\n<script>alert(1)</script>' }));
  assert.doesNotMatch(rendered, /<script|<img|<a /);
  assert.match(rendered, /&lt;img/);
  assert.match(rendered, /&lt;script&gt;/);
  assert.match(rendered, /javascript:alert/);
});
