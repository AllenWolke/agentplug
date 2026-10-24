package com.lexagent.sdk;

import java.util.Map;
import java.util.Set;

/** Validates original batch windows without granting execution authority. */
public final class ExecutionPolicy {
    private ExecutionPolicy() {}
    public static void validate(Map<String,Object> value)throws CapabilityClient.Failure{
        try{validateFields(value);}catch(CapabilityClient.Failure|RuntimeException rejected){throw PublicCapabilities.stop("HARNESS_POLICY_REJECTED");}
    }
    private static void validateFields(Map<String,Object> value)throws CapabilityClient.Failure{
        if(!value.keySet().equals(Set.of("version","policy_hash","server_time_ms","limits","execution"))||!"harness-policy/v2".equals(value.get("version"))||!(value.get("policy_hash") instanceof String hash)||!hash.matches("[a-f0-9]{64}"))throw invalid();
        long now=PublicCapabilities.integer(value.get("server_time_ms"));if(now<1||now>9_007_199_254_740_991L||!(value.get("limits") instanceof Map<?,?> limits)||!limits.keySet().equals(Set.of("max_rounds","max_tool_calls","max_repeated_calls","max_elapsed_seconds","limit_behavior")))throw invalid();
        bound(limits.get("max_rounds"),1,8);bound(limits.get("max_tool_calls"),1,16);bound(limits.get("max_repeated_calls"),1,4);bound(limits.get("max_elapsed_seconds"),10,3600);if(!Set.of("error","incomplete").contains(String.valueOf(limits.get("limit_behavior"))))throw invalid();
        if(!(value.get("execution") instanceof Map<?,?> execution)||!(execution.keySet().equals(Set.of("task_timeout_seconds","batch"))||execution.keySet().equals(Set.of("task_timeout_seconds","batch","window"))))throw invalid();
        long task=PublicCapabilities.integer(execution.get("task_timeout_seconds"));if(task<1)throw invalid();
        if(execution.get("batch")==null){if(execution.get("window")!=null)throw invalid();return;}
        if(!(execution.get("batch") instanceof Map<?,?> batch)||!batch.keySet().equals(Set.of("max_items","item_timeout_seconds","elapsed_seconds")))throw invalid();
        bound(batch.get("max_items"),1,10000);long elapsed=PublicCapabilities.integer(batch.get("elapsed_seconds"));bound(batch.get("item_timeout_seconds"),1,elapsed);if(elapsed>3600||elapsed!=task)throw invalid();
        if(!(execution.get("window") instanceof Map<?,?> window)||!window.keySet().equals(Set.of("started_ms","deadline_ms")))throw invalid();
        long start=PublicCapabilities.integer(window.get("started_ms")),deadline=PublicCapabilities.integer(window.get("deadline_ms"));if(start<1||start>now||deadline<1||deadline>9_007_199_254_740_991L||deadline!=Math.addExact(start,elapsed*1000))throw invalid();
    }
    private static void bound(Object value,long min,long max)throws CapabilityClient.Failure{long number=PublicCapabilities.integer(value);if(number<min||number>max)throw invalid();}
    private static CapabilityClient.Failure invalid(){return PublicCapabilities.stop("HARNESS_POLICY_REJECTED");}
}
