import React from "react";
import { Localized, useLanguage } from "../../components/Localization.jsx";
import { TechnicalDetails } from "../../components/DisplayNames.jsx";
import { actionName, roleName, resourceName, sourceName, dataScopeName } from "../../presentation.js";
import { formatTime } from "../../format.js";
import { groupResourceGrants, toggleGroupAllows } from "./grant-groups.js";

export function AuthorizationRevocations({ roles = [], grants = [], catalog = [], selectedRoles = [], selectedGrants = [], onRolesChange, onGrantsChange, disabled = false }) {
  useLanguage();
  const groups = groupResourceGrants(grants);
  const selected = selectedRoles.length + selectedGrants.length;
  const toggle = (values, id, checked) => checked ? [...new Set([...values, id])] : values.filter(value => value !== id);
  return <Localized><details className="authorization-revocations" aria-label="调整已有授权">
    <summary><span>调整已有授权</span><small>{roles.length} 项岗位 · {groups.length} 组资源</small>{selected > 0 && <span className="badge danger">已选 {selected} 项撤销</span>}</summary>
    <div className="authorization-revocations-content"><p className="form-hint">开通新权限时无需撤销旧权限。仅选择要收回的事项；选择整组只包含允许项，拒绝规则须逐项明确选择。</p>
      {roles.length > 0 && <div className="compact-role-list">{roles.map(role => <div key={role.id}><label><input type="checkbox" checked={selectedRoles.includes(role.id)} disabled={disabled} onChange={event => onRolesChange(toggle(selectedRoles, role.id, event.target.checked))}/><span>{roleName(role)}<small>{sourceName(role.source_id)}</small></span></label><TechnicalDetails values={{ "岗位绑定编号": role.id, "版本": role.role_version }}/></div>)}</div>}
      {groups.map(group => {
        const count = group.grants.filter(grant => selectedGrants.includes(grant.id)).length;
        const allowed = group.grants.filter(grant => grant.effect !== "deny");
        const allAllowedSelected = allowed.length > 0 && allowed.every(grant => selectedGrants.includes(grant.id));
        return <article className="compact-grant-group" key={group.key}><div className="compact-grant-heading"><div><b>{resourceName(group.resourceType, group.resourceID, catalog)}</b><small>{group.grants.length} 项授权{count > 0 && <> · 已选 {count} 项</>}</small></div><button type="button" className="text-button" disabled={disabled || !allowed.length} onClick={() => onGrantsChange(toggleGroupAllows(selectedGrants, group.grants))}>{allAllowedSelected ? "取消本组选择" : "选择本组允许项"}</button></div><p className="compact-grant-actions">{[...new Set(group.grants.map(grant => actionName(grant.action)))].join(" · ")}</p>
          <details className="compact-grant-details"><summary>逐项调整与授权来源</summary><div>{group.grants.map(grant => <div className="compact-grant-row" key={grant.id}><label><input type="checkbox" checked={selectedGrants.includes(grant.id)} disabled={disabled} onChange={event => onGrantsChange(toggle(selectedGrants, grant.id, event.target.checked))}/><span>{grant.effect === "deny" && <strong className="form-error">拒绝规则 · </strong>}{actionName(grant.action)}<small>{dataScopeName(grant.data_scope?.type)} · {sourceName(grant.source_id)} · {grant.expires_at ? formatTime(grant.expires_at) : "长期"}</small></span></label><TechnicalDetails values={{ "授权编号": grant.id, "资源编号": grant.resource_id, "操作代码": grant.action, "授权来源": grant.source_id }}/></div>)}</div></details>
        </article>;
      })}
      {!roles.length && !grants.length && <p>当前范围暂无已有授权。</p>}
    </div>
  </details></Localized>;
}
