import React from "react";

// Render only inert text/JSON. Unknown artifacts never become executable HTML.
// 仅渲染惰性文本/JSON，未知 Artifact 永远不会执行 HTML/脚本。
export function ArtifactRenderer({ artifact }) {
  if (!artifact) return null;
  const value = typeof artifact === "string" ? artifact : JSON.stringify(artifact, null, 2);
  return <pre className="artifact-preview" translate="no">{value}</pre>;
}
ArtifactRenderer.i18nOpaque = true;
