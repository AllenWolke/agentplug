package com.lexagent.sdk;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Application facade over governed durable model and retrieval workflows. */
public final class DurableStageClient {
    private final CapabilityClient client;
    private final String key;
    private final long deadlineMs;
    private final Map<String,Map<String,Object>> receipts=new java.util.concurrent.ConcurrentHashMap<>();
    public DurableStageClient(CapabilityClient client,String key,long deadlineMs){if(client==null||key==null||key.isBlank()||deadlineMs<1)throw new IllegalArgumentException("invalid durable stage");this.client=client;this.key=key;this.deadlineMs=deadlineMs;}
    public Map<String,Map<String,Object>> receipts(){return Map.copyOf(receipts);}
    private String stageKey(String kind,Object identity)throws CapabilityClient.Failure{return "stage-"+PublicCapabilities.digest(List.of(key,kind,identity));}
    @SuppressWarnings("unchecked") public Map<String,Object> chat(List<Map<String,Object>> messages,PublicCapabilities.ChatOptions options)throws CapabilityClient.Failure{
        String mode=PublicCapabilities.schemaMode(options.responseSchema(),options.responseSchemaMode(),options.requireJson());
        List<Object> identity=new java.util.ArrayList<>(List.of(options.stepName(),messages,options.temperature(),options.maxTokens()));
        if(options.requireJson())identity.add(Map.of("require_json",true));if(options.responseSchema()!=null)identity.add(Map.of("response_schema",options.responseSchema(),"response_schema_mode",mode));
        String operationKey=stageKey("model",identity);Map<String,Object> request=new LinkedHashMap<>();request.put("messages",messages);request.put("function_names",List.of());request.put("idempotency_key",operationKey);request.put("temperature",options.temperature());request.put("max_tokens",options.maxTokens());request.put("usage_step",options.stepName());
        if(options.requireJson())request.put("require_json",true);if(options.responseSchema()!=null){request.put("response_schema",options.responseSchema());request.put("response_schema_mode",mode);}
        var result=client.runHarness(request,new HarnessRunner.Options(operationKey,1,1,"","single-model-stage/v1",deadlineMs,null,null));receipts.put(operationKey,PublicCapabilities.copy(result));
        if(!"completed".equals(result.get("status"))||!(result.get("output") instanceof Map<?,?> output)||!(output.get("text") instanceof String))throw PublicCapabilities.stop("MODEL_STAGE_INCOMPLETE");
        var response=PublicCapabilities.copy((Map<String,Object>)output);response.put("execution",result.get("execution"));return response;
    }
    public Map<String,Object> searchKnowledge(String query,String scope,PublicCapabilities.KnowledgeOptions options)throws CapabilityClient.Failure{
        String operationKey=stageKey("knowledge",java.util.Arrays.asList(query,scope,options.asOf(),options.topK(),options.cacheMode(),options.sourceIds()));
        if(System.currentTimeMillis()>=deadlineMs)options=options.recovery();
        Map<String,Object> result=KnowledgeWorkflow.search(client,query,scope,operationKey,options);receipts.put(operationKey,PublicCapabilities.copy(result));return result;
    }
}
