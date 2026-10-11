import { Localized, useLanguage } from "./Localization.jsx";
import React, { createContext, useContext } from "react";
import { scopeName } from "../presentation.js";

export const DisplayNamesContext = createContext({ user: {}, workspaces: [] });
export function useScopeName(additionalWorkspaces = []) {
  const { user, workspaces } = useContext(DisplayNamesContext);
  return scope => scopeName(scope, [...workspaces, ...additionalWorkspaces], user);
}
export function TechnicalDetails({ values, summary = "查看技术详情" }) {
  useLanguage();
  const items = Object.entries(values || {}).filter(([, value]) => value !== undefined && value !== null && value !== "");
  if (!items.length) return null;
  return <Localized><details className="technical-details"><summary>{summary}</summary><dl>{items.map(([name, value]) => <React.Fragment key={name}><dt>{name}</dt><dd><code>{typeof value === "object" ? JSON.stringify(value) : String(value)}</code></dd></React.Fragment>)}</dl></details></Localized>;
}
