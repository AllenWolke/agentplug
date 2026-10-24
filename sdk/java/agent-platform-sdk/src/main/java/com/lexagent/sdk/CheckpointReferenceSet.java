package com.lexagent.sdk;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Signed metadata paging; values and execution authority remain separate. */
public final class CheckpointReferenceSet {
    private CheckpointReferenceSet() {}
    @SuppressWarnings("unchecked") static Map<String,Object> expand(CapabilityClient client,Map<String,Object> original)throws CapabilityClient.Failure{
        if(!"runtime-recovery/v2".equals(original.get("version")))return original;
        client.validateCurrentExecution();var normalized=PublicCapabilities.copy(original);
        if(!(normalized.get("reference") instanceof Map<?,?> raw)||!"runtime-recovery-stop/v2".equals(raw.get("version"))||raw.containsKey("checkpoints")||normalized.containsKey("group_resume"))throw denied();
        Map<String,Object> reference=(Map<String,Object>)raw;
        if(!(reference.get("checkpoint_set") instanceof Map<?,?> rawSet)||!rawSet.keySet().equals(Set.of("version","count","digest"))||!"recovery-checkpoint-set/v1".equals(rawSet.get("version"))||!(rawSet.get("digest") instanceof String digest)||!digest.matches("[a-f0-9]{64}"))throw denied();
        Map<String,Object> set=(Map<String,Object>)rawSet;long count=PublicCapabilities.integer(set.get("count"));if(count<=128||count>8192)throw denied();
        List<Object> references=new ArrayList<>(),items=new ArrayList<>();
        List<String> fields=List.of("state_key","revision","schema_id","content_hash","execution_revision","expires_at");
        while(references.size()<count){int offset=references.size();Map<String,Object> page=client.post("/internal/state/checkpoint",Map.of("operation","load","reference_set",set,"offset",offset,"limit",64));
            if(!page.keySet().equals(Set.of("version","set","offset","references"))||!"recovery-checkpoint-page/v1".equals(page.get("version"))||!PublicCapabilities.digest(page.get("set")).equals(PublicCapabilities.digest(set))||PublicCapabilities.integer(page.get("offset"))!=offset||!(page.get("references") instanceof List<?> values)||values.size()!=Math.min(64,count-offset))throw denied();
            for(Object value:values){if(!(value instanceof Map<?,?> item)||!item.keySet().equals(Set.copyOf(fields)))throw denied();references.add(value);List<Object> columns=new ArrayList<>();for(String field:fields)columns.add(item.get(field));items.add(columns);}
        }
        String json=new String(PublicCapabilities.canonical(items),StandardCharsets.UTF_8).replace("&","\\u0026").replace("<","\\u003c").replace(">","\\u003e").replace("\u2028","\\u2028").replace("\u2029","\\u2029");
        if(!PublicCapabilities.sha(json.getBytes(StandardCharsets.UTF_8)).equals(digest))throw denied();
        normalized.put("version","runtime-recovery/v1");reference.put("version","runtime-recovery-stop/v1");reference.remove("checkpoint_set");reference.put("checkpoints",references);return normalized;
    }
    public static String digestReferences(List<Map<String,Object>> references)throws CapabilityClient.Failure{
        List<Object> items=new ArrayList<>();List<String> fields=List.of("state_key","revision","schema_id","content_hash","execution_revision","expires_at");
        for(var reference:references){if(!reference.keySet().equals(Set.copyOf(fields)))throw denied();List<Object> row=new ArrayList<>();for(String field:fields)row.add(reference.get(field));items.add(row);}
        String json=new String(PublicCapabilities.canonical(items),StandardCharsets.UTF_8).replace("&","\\u0026").replace("<","\\u003c").replace(">","\\u003e").replace("\u2028","\\u2028").replace("\u2029","\\u2029");return PublicCapabilities.sha(json.getBytes(StandardCharsets.UTF_8));
    }
    private static CapabilityClient.Failure denied(){return PublicCapabilities.stop("RUN_RESUME_UNCONFIRMED");}
}
