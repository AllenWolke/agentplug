# Access and membership

The new company administrator is the protected `tenant_admin` version 2 role. It manages the account's own company without granting personal agent execution or business data access. Published version 1 tenant roles and existing global administrator assignments retain their original permissions. Account names such as `system.admin` do not determine authority.

To appoint a company administrator, a platform-wide administrator opens **User principals**, selects an account and uses **Administrator appointment**. Choose **Company administrator**, review the fixed company scope, expiry and reason, and explicitly select any old administrative roles to revoke. Review the plan and complete fresh authentication. Adding the company role alone does not remove prior authority.

Before replacing a global administrator, keep another active, permanent global administrator with a usable login. The server protects the last recovery identity. Company administrators cannot appoint company/global peers, disable protected administrative accounts, or apply for their own business access.

Deploy matching frontend, platform and database versions before using these features. A database upgrade preserves old grants and does not appoint administrators or enable Agents automatically. Existing companies and departments require explicitly reviewed migration; a new department starts with no approved Agents.

[All guides](README.en.md) · [中文版](权限与成员办理.md)

One account belongs to one company workspace and can join several departments within it. A user-facing application means an agent. The historical `Application` identifier is a technical integration and policy container.

The default administration flow uses company administrators, departmental administrators and ordinary members. Permission administration remains an optional delegated role. Management does not automatically grant agent execution.

To create and staff a department as `system.admin`:

1. Open **Departments** and enter a name. The company is fixed and the code is optional.
2. After creation, select **Add department member**, or **Members and roles** from the list.
3. Find a company account and open **Membership**. The department is preselected.
4. Select **Department member** or **Department administrator**, set expiry and provide a reason. Existing roles are retained by default; an explicit demotion lists the administrator role to be revoked.
5. Preview and submit the combined membership and role change atomically. Then assign approved agents separately.

Departments can be staffed before an agent is installed. Creation also prepares an internal management context; it installs no agents and grants no business access. Departmental administrators can admit ordinary members and assign basic Agent use within the company's approved department ceiling. They cannot appoint other administrators, remove a peer administrator or raise that ceiling.

For a business user:

1. Check the current workspace in **My identity and access**. Review active roles, resources and expiry; expand details only when needed.
2. In your access requests, select a membership scope and the required role or agent actions. Basic use includes discovery, running, cancellation, reading your own history and continuing a conversation.
3. Explain why you need access and specify expiry. Sharing, export and administrative actions are separate capabilities.
4. Submit and track the individual approval results. Unapproved items remain unavailable. Refresh access in the target workspace after approval.

For an authorized administrator enabling a colleague:

1. Check the company and department, then open **User identities**.
2. Check the account and configure its department membership and role.
3. Open **Identity and access**, select the role, permitted agents, scope and expiry, and give a reason.
4. Preview additions and revocations. Complete the required reauthentication before submitting the reviewed change.
5. Expand **Advanced: resources and detailed access** to check model, knowledge, tool and skill grants. Machine identities also need resource grants and installation bindings.
6. Ask the colleague to refresh access and verify an actual task. A role alone does not guarantee all dependencies are ready.

When reviewing a request, select only its permitted items. Unselected items are rejected; selecting none rejects the entire request. Basic-action shortcuts do not add sharing, export or administrator access.

Existing grants are collapsed and grouped by agent or resource. Group selection selects allow records only; deny records require an explicit individual selection. Every underlying grant and source remains available.

Administrators cannot create personal access requests or add their own business authority. The server enforces these restrictions. Historical requests remain readable.

The company administrator configures the department's approved Agents and actions. Reducing that ceiling restricts later protected operations under existing personal grants. Re-enabling an action does not automatically reactivate an expired grant source. Other valid sources, explicit denials and cancellation eligibility remain enforced. Impact counts describe authorization records, not running tasks or the reversal of completed external effects.

To process several people:

1. Select other active company accounts in the user list, across pages if needed, up to 50 per batch. Page selection includes only the displayed page.
2. Choose department identity assignment or basic Agent access. Company administrators may appoint department administrators; department administrators may assign ordinary members within their scope.
3. Select the common department and approved Agent, review conversation and dependency access, expiry and reason. Explicitly select membership addition if permitted; existing memberships and expiry remain unchanged.
4. Preview every person's additions, revocations and blocked items, then confirm. The reviewed Agent release and dependencies are fixed; configuration changes require a new preview.
5. Inspect individual results. Each person's change commits separately. A failed item does not undo successful items. Sharing, export, content changes and other advanced capabilities remain separately configurable.

For multiple requests, select pending entries and review each request's approved items or explicitly reject it. Unselected items are rejected. Process multiple requests from the same applicant in separate batches with a fresh preview.

After an interruption or uncertain response, query the original batch. Explicitly continue pending items or stop them after checking the saved state. Stopping preserves completed changes. Reloading or changing language reads the original result without submitting permissions again. Clear a batch only after no items remain pending and its results have been reviewed.
