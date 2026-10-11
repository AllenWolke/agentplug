import React from "react";

const h = React.createElement;
function inline(text) {
  return String(text).split(/(`[^`\n]+`|\*\*[^*\n]+\*\*)/g).filter(Boolean).map((part, index) =>
    part.startsWith("`") && part.endsWith("`") ? h("code", { key: index }, part.slice(1, -1)) :
      part.startsWith("**") && part.endsWith("**") ? h("strong", { key: index }, part.slice(2, -2)) : part);
}

// A small inert Markdown subset for answers. React escapes all text; HTML,
// images, embedded controls and executable URL schemes remain ordinary text.
export function AnswerText({ text }) {
  const blocks = [];
  const lines = String(text || "").replace(/\r\n/g, "\n").split("\n");
  for (let i = 0; i < lines.length;) {
    const line = lines[i];
    if (!line.trim()) { i++; continue; }
    if (/^```/.test(line)) {
      const code = []; i++;
      while (i < lines.length && !/^```/.test(lines[i])) code.push(lines[i++]);
      if (i < lines.length) i++;
      blocks.push(h("pre", { key: blocks.length }, h("code", null, code.join("\n")))); continue;
    }
    const heading = /^(#{1,4})\s+(.+)$/.exec(line);
    if (heading) { blocks.push(h("h" + Math.min(heading[1].length + 2, 6), { key: blocks.length }, inline(heading[2]))); i++; continue; }
    const list = /^\s*(?:[-*]\s+|\d+[.)]\s+)/.exec(line);
    if (list) {
      const ordered = /^\s*\d/.test(line), items = [];
      const pattern = ordered ? /^\s*\d+[.)]\s+(.+)$/ : /^\s*[-*]\s+(.+)$/;
      let match;
      while (i < lines.length && (match = pattern.exec(lines[i]))) { items.push(h("li", { key: items.length }, inline(match[1]))); i++; }
      blocks.push(h(ordered ? "ol" : "ul", { key: blocks.length }, items)); continue;
    }
    const paragraph = [line]; i++;
    while (i < lines.length && lines[i].trim() && !/^(?:#{1,4}\s|```|\s*[-*]\s|\s*\d+[.)]\s)/.test(lines[i])) paragraph.push(lines[i++]);
    blocks.push(h("p", { key: blocks.length }, inline(paragraph.join("\n"))));
  }
  return h("div", { className: "answer-text" }, blocks);
}
AnswerText.i18nOpaque = true;
