"""Public State bindings for independently persisted LangGraph checkpoints.

Verified transport and current execution remain authoritative. This bridge
never treats a checkpoint, user decision, or missing task as permission.
"""
from __future__ import annotations
import copy
import json
import re
from contextlib import aclosing
from .errors import DomainExecutionError
from .execution_lifecycle import ExecutionLifecycle
from .recovery_context import checkpoint_state_key
from .graph_context import bind_graph_context, close_graph_context
from .checkpoint_capacity import reply_limit

SCHEMA='schema://agentplug/langgraph-runtime/v1'
NAMESPACE='graph-runtime'
KEY='workflow'

def deny():return DomainExecutionError('RUN_RESUME_UNCONFIRMED')

def checkpoint_id(snapshot):
    config=getattr(snapshot,'config',None)
    value=config.get('configurable',{}).get('checkpoint_id','') if isinstance(config,dict) else ''
    if not isinstance(value,str) or len(value)>128:raise deny()
    return value

def has_pending_work(snapshot):
    # LangGraph can expose next=() while a persisted task carries an error or
    # interrupt after a lost tool reply. That is not a completed business graph.
    return bool(getattr(snapshot,'next',())) or any(
        getattr(task,'error',None) is not None or bool(getattr(task,'interrupts',()))
        for task in getattr(snapshot,'tasks',()))

def resume_command(interrupts,value):
    from langgraph.types import Command
    identifier=getattr(interrupts[0],'id',None) if len(interrupts)==1 else None
    # Address the persisted task's exact interrupt. A scalar null-resume may
    # survive an errored task and incorrectly fill a later approval slot.
    return Command(resume={identifier:value} if isinstance(identifier,str) and identifier else value)

def business_review(value):
    if not value:return {}
    if not isinstance(value,dict) or set(value)-{'decision','reviewer_id','comment'}:raise deny()
    if value.get('decision') not in ('approve','reject','request_changes'):raise deny()
    if not isinstance(value.get('reviewer_id'),str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',value['reviewer_id']) is None:raise deny()
    if 'comment' in value and (not isinstance(value['comment'],str) or len(value['comment'].encode('utf-8'))>2000):raise deny()
    return copy.deepcopy(value)

class PublicGraphCheckpointBridge:
    async def execute(self, request, client, graph, config, work, *, revalidate=None, revalidation_view=None):
        # Invoke only behind the SDK signed transport verification hook.
        await client.validate_current_execution()
        identity=ExecutionLifecycle._identity(request)
        generation=json.loads(identity.key)
        thread=config.get('configurable',{}).get('thread_id')
        if not isinstance(thread,str) or not thread.startswith('scope-v2:'):raise deny()
        binding,token=bind_graph_context(request,client._context)
        fence = fence_token = None
        runtime_parts = None
        try:
            if (request.resume_input or {}).get('version') in {'runtime-recovery/v1','runtime-recovery/v2'}:
                from .checkpoint_reference_set import runtime_parts as read_parts
                runtime_parts=await read_parts(request,client,identity,generation[1])
                _,refs,_=runtime_parts
                from .graph_state_fence import bind
                fence,fence_token=bind(request.scope,refs)
            if revalidate is not None and not callable(revalidate):raise deny()
            if revalidation_view is not None:
                if not callable(revalidation_view) or revalidate is None:raise deny()
                # A trusted application adapter identifies the data this graph
                # boundary may disclose. It must separately authorize data at
                # each effect/use boundary. Default callers retain full-state
                # validation; no authority decision is cached by this seam.
                original_revalidate = revalidate
                async def selected_revalidate(values):
                    selected = revalidation_view(values)
                    if not isinstance(selected, dict):raise deny()
                    return await original_revalidate(copy.deepcopy(selected))
                revalidate = selected_revalidate
            elif revalidate is not None:
                original_revalidate = revalidate
                async def full_revalidate(values):
                    return await original_revalidate(copy.deepcopy(values))
                revalidate = full_revalidate
            return await self._execute(request,client,graph,config,work,identity,generation[1],thread,runtime_parts,revalidate)
        finally:
            if fence is not None:
                from .graph_state_fence import close
                close(fence,fence_token)
            close_graph_context(binding,token)

    async def _execute(self,request,client,graph,config,work,identity,generation,thread,runtime_parts=None,revalidate=None):
        runtime=runtime_parts is not None
        if runtime:
            ref,refs,group=runtime_parts
            if group is not None:raise deny()
            if 'confirmation_token' in request.resume_input:
                from .tool_workflow import graph_tool_resume_input
                if graph_tool_resume_input(request) is None:raise deny()
            expected=checkpoint_state_key(request.scope,NAMESPACE,KEY)
            matches=[cp for cp in refs if cp['state_key']==expected and cp['schema_id']==SCHEMA]
            if len(matches)!=1:raise deny()
            loaded=await client.load_recovery_checkpoint(matches[0])
            ExecutionLifecycle._verify_recovery_checkpoint_response(matches[0],loaded)
        else:loaded=await client.load_checkpoint(NAMESPACE,KEY,SCHEMA)
        limit=reply_limit(loaded)
        # Admission and exit each commit a marker. Negotiate capacity from
        # this exact public State reply, including after runtime recovery;
        # expanding storage alone must not leave a hidden SDK64 ceiling.
        if limit<2:raise deny()
        cp=loaded.get('checkpoint');revision=0;previous=None
        if cp is not None:
            previous=cp.get('value');revision=cp.get('revision')
            if (not isinstance(previous,dict) or previous.get('version')!='langgraph-runtime/v1'
                or previous.get('business_hash')!=identity.business_hash or previous.get('thread_id')!=thread
                or previous.get('phase') not in ('dispatch','waiting','completed')
                or type(revision) is not int or not 1<=revision<=limit-2):raise deny()
        if runtime and previous is None:raise deny()
        snapshot=await graph.aget_state(config)
        if revalidate is not None and request.operation=='resume':
            values=getattr(snapshot,'values',None)
            if isinstance(values,dict) and values and await revalidate(values) is not True:raise deny()
        if runtime:
            values=getattr(snapshot,'values',None)
            if not isinstance(values,dict) or not values or not checkpoint_id(snapshot):raise deny()
            saved=values.get('context')
            if not isinstance(saved,dict) or saved.get('task_id')!=request.scope.run_id:raise deny()
            for field,scope_field in [('tenant_id','tenant_id'),('department_id','department_id'),
                ('application_id','application_id'),('installation_id','installation_id'),
                ('agent_instance_id','agent_instance_id'),('agent_id','agent_id'),
                ('agent_version_id','agent_version_id'),('actor_id','principal_id'),('session_id','session_id')]:
                if saved.get(field)!=getattr(request.scope,scope_field):raise deny()
            anchor=previous.get('checkpoint_id','')
            if previous['phase']!='dispatch' and checkpoint_id(snapshot)!=anchor:raise deny()
            if previous['phase']=='dispatch' and anchor and checkpoint_id(snapshot)!=anchor:
                found=False
                async with aclosing(graph.aget_state_history(config,limit=limit)) as history:
                    async for historical in history:
                        if checkpoint_id(historical)==anchor:found=True;break
                if not found:raise deny()
            review=business_review(request.resume_input.get('business_review') or previous.get('business_resume',{}))
            stored_review=business_review(previous.get('business_resume',{}))
            # A material request leaves a new independent review step pending.
            # Only the current committed platform decision may finish that step.
            next_review=previous['phase']=='waiting' and stored_review.get('decision')=='request_changes'
            if stored_review and not next_review and any(stored_review.get(k)!=review.get(k) for k in ('decision','reviewer_id')):raise deny()
            if review and review['reviewer_id']==request.scope.principal_id:raise deny()
            if previous['phase']=='completed' and has_pending_work(snapshot):raise deny()
            if not has_pending_work(snapshot):
                # Already completed graph nodes are only read, never executed.
                result=copy.deepcopy(values)
            else:
                # Commit admission before continuing a graph node. A crash may
                # advance LangGraph while the exit marker is still absent; the
                # next stop validates this anchor in actual graph history.
                marker={'version':'langgraph-runtime/v1','business_hash':identity.business_hash,'thread_id':thread,
                    'checkpoint_id':checkpoint_id(snapshot),'phase':'dispatch','business_resume':review}
                receipt=await client.save_checkpoint(NAMESPACE,KEY,SCHEMA,marker,revision,f'graph-{generation}-admit')
                if receipt.get('checkpoint',{}).get('revision')!=revision+1:raise deny()
                revision+=1
                interrupts=[x for task in getattr(snapshot,'tasks',()) for x in getattr(task,'interrupts',())]
                if interrupts:
                    from .tool_workflow import recover_graph_tool_interrupt
                    tool_resume=await recover_graph_tool_interrupt(request,client,interrupts)
                    errored=any(getattr(task,'error',None) is not None for task in getattr(snapshot,'tasks',()))
                    if errored:
                        # Resume values already committed to an errored task
                        # must keep their slot indices. Appending the former
                        # approval again could consume the next tool's slot.
                        result=dict(await graph.ainvoke(None,config))
                    elif tool_resume is not None:
                        if review:raise deny()
                        result=dict(await graph.ainvoke(resume_command(interrupts,tool_resume),config))
                    elif review:
                        result=dict(await graph.ainvoke(resume_command(interrupts,review),config))
                    else:
                        result=copy.deepcopy(values);result['__interrupt__']=tuple(interrupts)
                else:result=dict(await graph.ainvoke(None,config))
        else:
            from .tool_workflow import graph_tool_resume_input
            tool_resume=graph_tool_resume_input(request)
            review=(business_review(previous.get('business_resume',{})) if previous and tool_resume is not None
                    else business_review(request.resume_input or {}) if request.operation=='resume' and tool_resume is None else {})
            if review and review['reviewer_id']==request.scope.principal_id:raise deny()
            marker={'version':'langgraph-runtime/v1','business_hash':identity.business_hash,'thread_id':thread,
                'checkpoint_id':checkpoint_id(snapshot),'phase':'dispatch','business_resume':review}
            receipt=await client.save_checkpoint(NAMESPACE,KEY,SCHEMA,marker,revision,f'graph-{generation}-admit')
            if receipt.get('checkpoint',{}).get('revision')!=revision+1:raise deny()
            revision+=1
            if tool_resume is not None:
                from .tool_workflow import recover_graph_tool_interrupt
                interrupts=[x for task in getattr(snapshot,'tasks',()) for x in getattr(task,'interrupts',())]
                approved=await recover_graph_tool_interrupt(request,client,interrupts)
                if approved is None:raise deny()
                result=dict(await graph.ainvoke(resume_command(interrupts,approved),config))
            else:result=await work()
        snapshot=await graph.aget_state(config)
        if not checkpoint_id(snapshot):raise deny()
        if revalidate is not None and await revalidate(result) is not True:raise deny()
        marker={'version':'langgraph-runtime/v1','business_hash':identity.business_hash,'thread_id':thread,
            'checkpoint_id':checkpoint_id(snapshot),'phase':'waiting' if result.get('__interrupt__') else 'completed',
            'business_resume':review}
        receipt=await client.save_checkpoint(NAMESPACE,KEY,SCHEMA,marker,revision,f'graph-{generation}-exit')
        if receipt.get('checkpoint',{}).get('revision')!=revision+1:raise deny()
        return result
