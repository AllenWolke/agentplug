import React, { createContext, useContext, useEffect, useSyncExternalStore } from "react";
import { getLanguage, setLanguage, subscribeLanguage, translateUI, spaceInterfaceText } from "../localization.js";

const LanguageContext = createContext("zh-CN");
const PreserveContentContext = createContext(false);
export const useLanguage = () => useContext(LanguageContext);
const displayProps = new Set(["title", "placeholder", "aria-label", "aria-description", "alt", "label", "description", "eyebrow", "summary"]);
const opaqueTags = new Set(["pre", "code", "textarea", "script", "style"]);

export function localizeElement(value, language) {
  if (typeof value === "string") return translateUI(value, language);
  if (Array.isArray(value)) return spaceInterfaceText(value.map(item => localizeElement(item, language)), language);
  if (!React.isValidElement(value)) return value;
  const props = value.props;
  if (props["data-i18n-preserve"] || value.type?.i18nOpaque || opaqueTags.has(value.type)) {
    // Placeholders are interface text; field values and content are not.
    const translatedProps = {};
    for (const key of displayProps) if (typeof props[key] === "string") translatedProps[key] = translateUI(props[key], language);
    return <PreserveContentContext.Provider value={true} key={value.key}>{React.cloneElement(value, translatedProps)}</PreserveContentContext.Provider>;
  }
  const translatedProps = {};
  for (const key of displayProps) if (typeof props[key] === "string") translatedProps[key] = translateUI(props[key], language);
  // Never change value/defaultValue/name/id/key/path, event handlers, or data.
  if (Object.hasOwn(props, "children")) translatedProps.children = localizeElement(props.children, language);
  return React.cloneElement(value, translatedProps);
}

export function LanguageProvider({ children }) {
  const language = useSyncExternalStore(subscribeLanguage, getLanguage, () => "zh-CN");
  useEffect(() => {
    document.documentElement.lang = language;
    document.title = language === "en" ? "AgentPlug · Agent Workspace" : "AgentPlug · 智能体中台";
  }, [language]);
  return <LanguageContext.Provider value={language}>{children}</LanguageContext.Provider>;
}

// A presentation boundary updates interface text without remounting forms,
// changing command values, replaying requests, or translating business content.
export function Localized({ children }) {
  const language = useContext(LanguageContext);
  const preserve = useContext(PreserveContentContext);
  return preserve ? children : localizeElement(children, language);
}

export function LanguageSwitcher() {
  const language = useContext(LanguageContext);
  return <div className="language-switcher" role="group" aria-label="界面语言 / Interface language">
    <span>中文 / English</span>
    <div><button type="button" aria-pressed={language === "zh-CN"} lang="zh-CN" onClick={() => setLanguage("zh-CN")}>中文</button><button type="button" aria-pressed={language === "en"} lang="en" onClick={() => setLanguage("en")}>English</button></div>
  </div>;
}
LanguageSwitcher.i18nOpaque = true;
