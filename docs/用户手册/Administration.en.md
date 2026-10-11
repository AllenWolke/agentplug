# Administration and development

[All guides](README.en.md) · [中文版](管理员与开发者操作指南.md)

The company workspace contains departments. User-facing applications mean Agents; technical applications on installation and policy screens are deployment containers.

To create a department, sign in as `system.admin`, open **Departments**, and enter a name. The company is fixed to the current company; the optional code is generated if omitted. Open **Members and roles**, select a company user, and open their membership editor. Choose **Department member** or **Department administrator**, enter a reason and optional expiry, preview the differences, and confirm. Membership and identity changes are saved in one transaction.

An empty department can receive members before any Agent is installed. Creation and membership do not grant Agent access. The company administrator configures the department's approved Agents and actions. Department administrators can admit company users and assign basic use within that ceiling, but cannot appoint or remove peer administrators, raise the ceiling or grant unapproved sensitive actions. Select several company accounts in the user list to assign department identities or enable Agent access, then preview and inspect each result. See [Access and membership](Access-and-membership.en.md).

Publishing an agent involves distinct steps:

1. Register its definition and immutable version with the actual artifact digest and input/output contract.
2. Complete evaluation and independent approval, publish the version and install it in the target application.
3. Register a desired deployment for that version. Activate the installation after the trusted control plane reports readiness.
4. Configure and publish the application's model, prompt, tool, memory, knowledge and runtime policy snapshot.
5. Grant human and machine access separately, then run a task as the intended user. Check the result, sources, usage records and history.

For models, register a provider using secret references only. Operations must configure symbolic endpoint mappings on the server. Test and approve the provider, register and approve the model version, then configure deployment, pricing periods and access policy. Approved pricing uses micro-units per 1,000 tokens and cannot have overlapping effective periods.

The interface does not provide global budget or threshold notification configuration yet. Observed deployment health is read-only; the browser cannot forge readiness. Evaluation conclusions require a real runner and trusted evidence. Unknown or blocked results are never passes.

For machine access, register an identity, restrict its actual outbound CIDRs and store its one-time secret in your organization's secret manager immediately. Credentials alone do not grant access. Configure minimum resource grants and the relevant installation binding. Rotation invalidates old secrets and tokens immediately.

## Confirm a pending tool operation

1. Open the pending operation in its original task. Select **Review the pending operation** and check the tool, target and parameters. Ask the business owner to clarify any hidden or truncated parameters.
2. The page uses your current sign-in method. Local users enter their current password. Company SSO users verify the current account in an identity provider window; no local password is needed.
3. Authenticate and approve the reviewed operation. Approval applies only to that specific operation. Select **Continue run** to request its execution.
4. Before execution, authenticate again to revoke approval if needed. Revocation prevents further use of that approval. Completed business operations use their own business reversal process.

If you close or cancel authentication, or the preview expires, review the operation again. The page does not automatically submit or fall back to a local password. Use **Retry loading the authentication method** after a read failure. If SSO fresh authentication is unavailable, ask the platform administrator to configure the identity provider.

Authentication does not grant access. Submission still checks the current account and login session, Run, published policy, human and machine resource permissions, and exact pending parameters. Another login session, revoked permissions or changed parameters cannot use the original proof. If the continuation result is uncertain, check the original Run before trying further actions.

For failures, check the original run or change status first. Refresh and preview again after a revision conflict. Record the page, time and trace ID when contacting an administrator; do not post credentials or business content in public feedback.
