package com.lexagent.sdk;

import java.util.Map;

/** Governed operations needed by durable SDK workflows. */
public interface CapabilityPort extends CapabilityPoster {
    Map<String, Object> post(String path, Map<String, Object> input) throws CapabilityClient.Failure;
    Map<String, Object> loadCheckpoint(String namespace, String key, String schema, long revision) throws CapabilityClient.Failure;
    Map<String, Object> saveCheckpoint(String namespace, String key, String schema, Map<String, Object> value,
            long expectedRevision, String operationKey) throws CapabilityClient.Failure;
    void validateCurrentExecution() throws CapabilityClient.Failure;
}
