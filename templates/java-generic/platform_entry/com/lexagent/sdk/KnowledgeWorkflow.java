package com.lexagent.sdk;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Persistent knowledge boundaries. Unknown dispatches use receipt-only reads. */
public final class KnowledgeWorkflow {
    public static final String SEARCH_SCHEMA="schema://agentplug/knowledge-search/v1";
    public static final String ANSWER_SCHEMA="schema://agentplug/knowledge-harness/v1";
    private KnowledgeWorkflow() {}
    public static Map<String,Object> search(CapabilityClient client,String query,String scope,String key,PublicCapabilities.KnowledgeOptions options)throws CapabilityClient.Failure{
        if(options==null||options.asOf()==null||options.asOf().isEmpty())throw PublicCapabilities.stop("KNOWLEDGE_SEARCH_CONFIG_INVALID");
        var identity=java.util.Arrays.asList(query,scope,options.asOf(),options.topK(),options.cacheMode(),options.sourceIds());
        Map<String,Object> state=new LinkedHashMap<>();state.put("version","knowledge-search/v1");state.put("input_hash",PublicCapabilities.digest(identity));state.put("phase","dispatch");
        return run(client,query,scope,key,options,state,false);
    }
    public static Map<String,Object> answer(CapabilityClient client,String query,String scope,String key,PublicCapabilities.KnowledgeOptions options)throws CapabilityClient.Failure{
        if(options==null||options.topK()>5||options.skillRequests()==null||options.skillRequests().isEmpty()||options.skillRequests().size()>4)throw PublicCapabilities.stop("HARNESS_SKILL_REJECTED");
        Map<String,Object> bindings=new LinkedHashMap<>();
        for(var selection:options.skillRequests()){
            Object id=selection.get("skill_id");if(!(id instanceof String skill)||!HarnessRunner.skillIdentifier(skill)||bindings.containsKey(skill)||!java.util.Set.of("skill_id","sections").containsAll(selection.keySet()))throw PublicCapabilities.stop("HARNESS_SKILL_REJECTED");
            Object raw=client.loadSkill(skill,"").get("skill");if(!(raw instanceof Map<?,?> disclosure)||!"skill-disclosure/v1".equals(disclosure.get("version"))||!skill.equals(disclosure.get("skill_id"))||!"untrusted_data".equals(disclosure.get("instruction_trust"))||!(disclosure.get("version_id") instanceof String version)||!HarnessRunner.skillIdentifier(version)||!(disclosure.get("digest") instanceof String hash)||!hash.matches("[a-f0-9]{64}"))throw PublicCapabilities.stop("HARNESS_SKILL_REJECTED");
            Object sections=selection.getOrDefault("sections",List.of());if(!(sections instanceof List<?> list)||list.size()>4||new java.util.HashSet<>(list).size()!=list.size()||list.stream().anyMatch(v->!(v instanceof String text)||!HarnessRunner.skillIdentifier(text)))throw PublicCapabilities.stop("HARNESS_SKILL_REJECTED");
            bindings.put(skill,Map.of("version_id",version,"digest",hash));
        }
        List<Object> identity=new ArrayList<>(List.of(query,scope,options.topK(),options.cacheMode(),options.skillRequests()));
        if(options.asOf()!=null&&!options.asOf().isEmpty()||options.sourceIds()!=null){Map<String,Object> extra=new LinkedHashMap<>();extra.put("as_of",options.asOf());extra.put("source_ids",options.sourceIds());identity.add(extra);}
        Map<String,Object> state=new LinkedHashMap<>();state.put("version","knowledge-harness/v1");state.put("input_hash",PublicCapabilities.digest(identity));state.put("phase","answer_dispatch");state.put("parent_run_id",client.currentRunId());state.put("skill_bindings",bindings);
        var pinned=new PublicCapabilities.KnowledgeOptions(options.topK(),options.asOf(),options.cacheMode(),options.sourceIds(),options.recoveryOnly(),options.skillRequests(),bindings);
        return run(client,query,scope,key,pinned,state,true);
    }
    @SuppressWarnings("unchecked") private static Map<String,Object> run(CapabilityClient client,String query,String scope,String key,PublicCapabilities.KnowledgeOptions options,Map<String,Object> initial,boolean answer)throws CapabilityClient.Failure{
        if(key==null||!key.matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}"))throw PublicCapabilities.stop("REQUEST_INVALID");
        String namespace=answer?"knowledge-harness":"knowledge-search",schema=answer?ANSWER_SCHEMA:SEARCH_SCHEMA;
        Map<String,Object> loaded=client.loadCheckpoint(namespace,key,schema,0),state=initial;long revision=0;
        if(loaded.get("checkpoint")==null){if(options.recoveryOnly())throw PublicCapabilities.stop("KNOWLEDGE_RECONCILIATION_REQUIRED");client.authorizeRuntimeRecoveryStart(namespace,key,schema,(String)state.get("input_hash"));}
        else{
            if(!(loaded.get("checkpoint") instanceof Map<?,?> cp)||!(cp.get("value") instanceof Map<?,?> raw))throw PublicCapabilities.stop("HARNESS_STATE_REJECTED");
            revision=PublicCapabilities.integer(cp.get("revision"));state=PublicCapabilities.copy((Map<String,Object>)raw);
            if(revision<1||revision>2||!java.util.Objects.equals(state.get("version"),initial.get("version"))||!java.util.Objects.equals(state.get("input_hash"),initial.get("input_hash"))||!java.util.Objects.equals(state.get("parent_run_id"),initial.get("parent_run_id"))||!PublicCapabilities.digest(state.get("skill_bindings")).equals(PublicCapabilities.digest(initial.get("skill_bindings")))||!(revision==1?initial.get("phase"):"completed").equals(state.get("phase")))throw PublicCapabilities.stop("HARNESS_STATE_REJECTED");
        }
        boolean recovery=revision!=0;if(!recovery)revision=save(client,namespace,key,schema,state,revision,answer);
        var actual=recovery?options.recovery():options;
        Map<String,Object> result=answer?client.capabilities().answerKnowledge(query,scope,actual):client.capabilities().searchKnowledge(query,scope,actual);
        if(!(result.get("references") instanceof List<?> refs))throw PublicCapabilities.stop("KNOWLEDGE_RESPONSE_INVALID");
        if(recovery&&(!Boolean.TRUE.equals(result.get("recovery_only"))||PublicCapabilities.integer(result.get("model_requests_sent"))!=0))throw PublicCapabilities.stop("KNOWLEDGE_RECONCILIATION_REQUIRED");
        if(answer&&(!(result.get("text") instanceof String text)||text.isBlank()||text.getBytes(java.nio.charset.StandardCharsets.UTF_8).length>32768||refs.isEmpty()||!(result.get("citation_ids") instanceof List<?> cites)||cites.isEmpty()))throw PublicCapabilities.stop("KNOWLEDGE_RESPONSE_INVALID");
        if(!"completed".equals(state.get("phase"))){state.put("phase","completed");save(client,namespace,key,schema,state,revision,answer);}
        return result;
    }
    private static long save(CapabilityClient client,String namespace,String key,String schema,Map<String,Object> state,long revision,boolean answer)throws CapabilityClient.Failure{
        Map<String,Object> response=client.saveCheckpoint(namespace,key,schema,PublicCapabilities.copy(state),revision,(answer?"knowledge-":"search-")+(revision+1));
        if(!(response.get("checkpoint") instanceof Map<?,?> cp)||PublicCapabilities.integer(cp.get("revision"))!=revision+1||!PublicCapabilities.digest(cp.get("value")).equals(PublicCapabilities.digest(state)))throw PublicCapabilities.stop("HARNESS_STATE_REJECTED");return revision+1;
    }
}
