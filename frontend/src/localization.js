import english from "./locales/en.js";

export const LANGUAGE_STORAGE_KEY = "agentplug.ui-language";
export const supportedLanguages = Object.freeze(["zh-CN", "en"]);
const subscribers = new Set();
let language = "zh-CN";
try {
  const saved = globalThis.localStorage?.getItem(LANGUAGE_STORAGE_KEY);
  if (supportedLanguages.includes(saved)) language = saved;
} catch { /* Browser storage can be unavailable; the current choice still works. */ }

export const getLanguage = () => language;
export function subscribeLanguage(callback) { subscribers.add(callback); return () => subscribers.delete(callback); }
export function setLanguage(value) {
  if (!supportedLanguages.includes(value)) throw new Error("Unsupported interface language");
  if (language === value) return;
  language = value;
  try { globalThis.localStorage?.setItem(LANGUAGE_STORAGE_KEY, value); } catch {}
  subscribers.forEach(callback => callback());
}
globalThis.addEventListener?.("storage", event => {
  if (event.key === LANGUAGE_STORAGE_KEY && supportedLanguages.includes(event.newValue) && language !== event.newValue) {
    language = event.newValue;
    subscribers.forEach(callback => callback());
  }
});

const escapePattern = value => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const templates = Object.entries(english).filter(([key]) => /\{\{\d+\}\}/.test(key)).map(([key, translation]) => {
  const names = [];
  let pattern = "", start = 0;
  for (const match of key.matchAll(/\{\{(\d+)\}\}/g)) {
    pattern += escapePattern(key.slice(start, match.index)) + "([\\s\\S]*?)";
    names.push(match[1]); start = match.index + match[0].length;
  }
  pattern += escapePattern(key.slice(start));
  return { pattern: new RegExp("^" + pattern + "$"), translation, names, specificity: key.replace(/\{\{\d+\}\}/g, "").length };
}).sort((a, b) => b.specificity - a.specificity);

// Translate complete interface messages only. Never replace arbitrary substrings
// in identifiers, JSON payloads, user inputs, model output, or resource content.
export function translateUI(value, locale = language) {
  if (locale !== "en" || typeof value !== "string" || !/[\u3400-\u9fff]/.test(value)) return value;
  if (Object.hasOwn(english, value)) return english[value];
  const trimmed = value.trim();
  if (Object.hasOwn(english, trimmed)) return value.replace(trimmed, () => english[trimmed]);
  for (const template of templates) {
    const match = template.pattern.exec(value);
    if (match) {
      const parameters = Object.fromEntries(template.names.map((name, index) => [name, match[index + 1]]));
      return template.translation.replace(/\{\{(\d+)\}\}/g, (_, name) => parameters[name] ?? "");
    }
  }
  return value;
}

export function interpolateUI(key, parameters, locale = language) {
  return translateUI(key, locale).replace(/\{\{(\d+)\}\}/g, (_, name) => String(parameters[Number(name)] ?? ""));
}

// Chinese JSX commonly joins labels and counts without spaces. English needs
// word boundaries; change text only, keeping every child at its original index.
export function spaceInterfaceText(children, locale = language) {
  if (locale !== "en") return children;
  const primitive = value => typeof value === "string" || typeof value === "number";
  return children.map((value, index) => primitive(value) && primitive(children[index - 1]) && /[\p{L}\p{N}.!?:;)]$/u.test(String(children[index - 1])) && /^[\p{L}\p{N}]/u.test(String(value)) ? " " + value : value);
}

export const englishMessages = english;
