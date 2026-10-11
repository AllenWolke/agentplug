"""Public State bindings for independently persisted LangGraph checkpoints.

Verified transport and current execution remain authoritative. This bridge
never treats a checkpoint, user decision, or missing task as permission.
"""
from __future__ import annotations
import copy
import json
import re
from .errors import DomainExecutionError
from .execution_lifecycle import ExecutionLifecycle
from .recovery_context import checkpoint_state_key
from .graph_context import bind_graph_context, close_graph_context

SCHEMA='schema://agentplug/langgraph-runtime/v1'
NAMESPACE='graph-runtime'
KEY='workflow'

def deny():return DomainExecutionError('RUN_RESUME_UNCONFIRMED')

def checkpoint_id(snapshot):
    config=getattr(snapshot,'config',None)
    value=config.get('configurable',{}).get('checkpoint_id','') if isinstance(config,dict) else ''
    if not isinstance(value,str) or len(value)>128:raise deny()
    return value

def business_review(value):
    if not value:return {}
    if not isinstance(value,dict) or set(value)-{'decision','reviewer_id','comment'}:raise deny()
    if value.get('decision') not in ('approve','reject'):raise deny()
    if not isinstance(value.get('reviewer_id'),str) or re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',value['reviewer_id']) is None:raise deny()
    if 'comment' in value and (not isinstance(value['comment'],str) or len(value['comment'])>2000):raise deny()
    return copy.deepcopy(value)

class PublicGraphCheckpointBridge:
    async def execute(self, request, client, graph, config, work):
        # Invoke only behind the SDK signed transport verification hook.
        await client.validate_current_execution()
        identity=ExecutionLifecycle._identity(request)
        generation=json.loads(identity.key)
        thread=config.get('configurable',{}).get('thread_id')
        if not isinstance(thread,str) or not thread.startswith('scope-v2:'):raise deny()
        binding,token=bind_graph_context(request,client._context)
        try:
            return await self._execute(request,client,graph,config,work,identity,generation[1],thread)
        finally:close_graph_context(binding,token)

    async def _execute(self,request,client,graph,config,work,identity,generation,thread):
        runtime=(request.resume_input or {}).get('version')=='runtime-recovery/v1'
        if runtime:
            ref,refs,group=ExecutionLifecycle._runtime_recovery_reference(request,identity,generation,request.resume_input)
            # Tool/group recovery is owned by its existing SDK Harness adapters.
            if group is not None or 'confirmation_token' in request.resume_input:raise deny()
            expected=checkpoint_state_key(request.scope,NAMESPACE,KEY)
            matches=[cp for cp in refs if cp['state_key']==expected and cp['schema_id']==SCHEMA]
            if len(matches)!=1:raise deny()
            loaded=await client.load_recovery_checkpoint(matches[0])
            ExecutionLifecycle._verify_recovery_checkpoint_response(matches[0],loaded)
        else:loaded=await client.load_checkpoint(NAMESPACE,KEY,SCHEMA)
        cp=loaded.get('checkpoint');revision=0;previous=None
        if cp is not None:
            previous=cp.get('value');revision=cp.get('revision')
            if (not isinstance(previous,dict) or previous.get('version')!='langgraph-runtime/v1'
                or previous.get('business_hash')!=identity.business_hash or previous.get('thread_id')!=thread
                or previous.get('phase') not in ('dispatch','waiting','completed')
                or type(revision) is not int or not 1<=revision<63):raise deny()
        if runtime and previous is None:raise deny()
        snapshot=await graph.aget_state(config)
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
                async for historical in graph.aget_state_history(config,limit=64):
                    if checkpoint_id(historical)==anchor:found=True;break
                if not found:raise deny()
            review=business_review(request.resume_input.get('business_review') or previous.get('business_resume',{}))
            stored_review=business_review(previous.get('business_resume',{}))
            if stored_review and any(stored_review.get(k)!=review.get(k) for k in ('decision','reviewer_id')):raise deny()
            if review and review['reviewer_id']==request.scope.principal_id:raise deny()
            if previous['phase']=='completed' and getattr(snapshot,'next',()):raise deny()
            if not getattr(snapshot,'next',()):
                # Already completed graph nodes are only read, never executed.
                result=copy.deepcopy(values)
            else:
                interrupts=[x for task in getattr(snapshot,'tasks',()) for x in getattr(task,'interrupts',())]
                if interrupts:
                    if review:
                        from langgraph.types import Command
                        result=dict(await graph.ainvoke(Command(resume=review),config))
                    else:
                        result=copy.deepcopy(values);result['__interrupt__']=tuple(interrupts)
                else:result=dict(await graph.ainvoke(None,config))
        else:
            review=business_review(request.resume_input or {}) if request.operation=='resume' else {}
            if review and review['reviewer_id']==request.scope.principal_id:raise deny()
            marker={'version':'langgraph-runtime/v1','business_hash':identity.business_hash,'thread_id':thread,
                'checkpoint_id':checkpoint_id(snapshot),'phase':'dispatch','business_resume':review}
            receipt=await client.save_checkpoint(NAMESPACE,KEY,SCHEMA,marker,revision,f'graph-{generation}-admit')
            if receipt.get('checkpoint',{}).get('revision')!=revision+1:raise deny()
            revision+=1
            result=await work()
        snapshot=await graph.aget_state(config)
        if not checkpoint_id(snapshot):raise deny()
        marker={'version':'langgraph-runtime/v1','business_hash':identity.business_hash,'thread_id':thread,
            'checkpoint_id':checkpoint_id(snapshot),'phase':'waiting' if result.get('__interrupt__') else 'completed',
            'business_resume':review}
        receipt=await client.save_checkpoint(NAMESPACE,KEY,SCHEMA,marker,revision,f'graph-{generation}-exit')
        if receipt.get('checkpoint',{}).get('revision')!=revision+1:raise deny()
        return result
