import { Localized, useLanguage } from "../../components/Localization.jsx";
import React, { useEffect, useRef, useState } from "react";
import { api } from "../../api.js";

export function AuditEventContent({ eventID }) {
  useLanguage();
  const [actions, setActions] = useState({});
  const [body, setBody] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);

  useEffect(() => {
    let mounted = true;
    const refresh = async () => {
      const current = ++generation.current;
      try {
        const value = await api.auditEventPermissions(eventID);
        if (!mounted || current !== generation.current) return;
        if (value.event_id !== eventID) throw new Error("审计权限结果不匹配");
        setActions(value.actions || {});
        if (value.actions?.["audit.content.read"] !== true) setBody(null);
      } catch {
        if (mounted && current === generation.current) { setActions({}); setBody(null); }
      }
    };
    const focus = () => { setBody(null); setActions({}); refresh(); };
    refresh();
    const timer = setInterval(refresh, 15000);
    window.addEventListener("focus", focus);
    return () => { mounted = false; generation.current++; clearInterval(timer); window.removeEventListener("focus", focus); };
  }, [eventID]);

  const execute = async (exporting) => {
    const current = generation.current;
    setBusy(true); setError(""); setBody(null);
    try {
      const result = exporting ? await api.exportAuditEvents([eventID]) : await api.auditEventContent(eventID);
      if (current !== generation.current) return;
      if (exporting) {
        if (result.items?.length !== 1 || result.items[0].id !== eventID) throw new Error("审计导出结果不匹配");
        const url = URL.createObjectURL(new Blob([JSON.stringify(result, null, 2)], { type: "application/json" }));
        const link = document.createElement("a"); link.href = url; link.download = "audit-events.json"; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 0);
      } else {
        if (result.id !== eventID) throw new Error("审计正文结果不匹配");
        setBody(String(result.summary || ""));
      }
    } catch (reason) {
      if (current === generation.current) { setError(reason.message); setActions({}); setBody(null); }
    } finally { setBusy(false); }
  };

  return <Localized><div className="audit-content-controls">
    <button type="button" className="button secondary" disabled={busy || actions["audit.content.read"] !== true} onClick={() => execute(false)}>查看审计正文</button>
    <button type="button" className="button secondary" disabled={busy || actions["audit.export"] !== true} onClick={() => execute(true)}>导出此事件</button>
    {body !== null && <><pre>{body || "此事件无正文"}</pre><button type="button" className="button secondary" onClick={() => setBody(null)}>关闭正文</button></>}
    {error && <p className="form-error">{error}</p>}
  </div></Localized>;
}
