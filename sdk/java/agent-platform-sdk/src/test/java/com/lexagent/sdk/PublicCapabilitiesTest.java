package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.core.type.TypeReference;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class PublicCapabilitiesTest {
    @SuppressWarnings("unchecked") @Test void sharedCapacityAndUnknownMetadata() throws Exception {
        var fixture=PublicCapabilities.JSON.readValue(Files.readAllBytes(Path.of("../../../contracts/fixtures/public-capabilities-v1.json")),new TypeReference<Map<String,Object>>(){});
        for(Object raw:(List<?>)fixture.get("capacity")){
            Map<String,Object> item=(Map<String,Object>)raw,reply=(Map<String,Object>)item.get("reply");
            if(item.containsKey("error")){var error=assertThrows(CapabilityClient.Failure.class,()->CheckpointCapacity.replyLimit(reply));assertEquals(item.get("error"),error.code());}
            else assertEquals(PublicCapabilities.integer(item.get("limit")),CheckpointCapacity.replyLimit(reply));
        }
        var metadata=(Map<String,Object>)fixture.get("preserved_model_metadata");assertEquals(metadata,PublicCapabilities.modelResultMetadata(metadata));
    }
    private static final class StatePort implements CapabilityPort {
        Map<String,Object> checkpoint;
        boolean negotiated,lost,denied;
        int saves,validations;
        public Map<String,Object> post(String path,Map<String,Object> input)throws CapabilityClient.Failure{
            if(!path.equals("/internal/runtime/harness-policy"))throw PublicCapabilities.stop("UNEXPECTED_TEST_CALL");
            return Map.of("version","harness-policy/v1","policy_hash","a".repeat(64),"server_time_ms",System.currentTimeMillis(),"limits",Map.of("max_rounds",8,"max_tool_calls",16,"max_repeated_calls",4,"max_elapsed_seconds",300,"limit_behavior","error"));
        }
        public Map<String,Object> loadCheckpoint(String namespace,String key,String schema,long revision)throws CapabilityClient.Failure{
            Map<String,Object> result=new java.util.LinkedHashMap<>();result.put("checkpoint",checkpoint==null?null:PublicCapabilities.copy(checkpoint));
            if(negotiated)result.put("checkpoint_history",Map.of("version","checkpoint-history/v1","max_revisions",4096));return result;
        }
        public Map<String,Object> saveCheckpoint(String namespace,String key,String schema,Map<String,Object> state,long expected,String operation)throws CapabilityClient.Failure{
            saves++;long actual=checkpoint==null?0:PublicCapabilities.integer(checkpoint.get("revision"));if(expected!=actual)throw PublicCapabilities.stop("STATE_REVISION_CONFLICT");
            checkpoint=PublicCapabilities.copy(Map.of("revision",actual+1,"value",state,"schema_id",schema));
            if(lost&&expected>0&&!"pending".equals(state.get("phase"))){lost=false;throw PublicCapabilities.stop("STATE_RESULT_UNKNOWN");}
            return Map.of("checkpoint",PublicCapabilities.copy(checkpoint));
        }
        public void validateCurrentExecution()throws CapabilityClient.Failure{validations++;if(denied)throw PublicCapabilities.stop("CAPABILITY_DENIED");}
    }
    @Test void cursorChecksCapacityAndRestoresCommittedUnknownAck()throws Exception{
        var port=new StatePort();assertThrows(CapabilityClient.Failure.class,()->CheckpointCursor.open(port,"batch","a".repeat(64),32));assertEquals(0,port.saves);
        port.negotiated=true;var cursor=CheckpointCursor.open(port,"batch","a".repeat(64),2);assertFalse(cursor.begin());port.lost=true;
        assertThrows(CapabilityClient.Failure.class,()->cursor.confirm("b".repeat(64)));assertEquals(0,cursor.index());
        var restored=CheckpointCursor.open(port,"batch","a".repeat(64),2);assertEquals(1,restored.index());assertFalse(restored.begin());port.denied=true;
        assertThrows(CapabilityClient.Failure.class,restored::begin);assertEquals(1,port.validations);
    }
    @Test void workflowRecoversOriginalDispatchAndRejectsChangedPlan()throws Exception{
        var port=new StatePort();int[] calls={0,0};
        StepWorkflow.Executor executor=new StepWorkflow.Executor(){
            public Map<String,Object> execute(StepWorkflow.Step step,StepWorkflow.Runtime runtime,Map<String,Object> results)throws Exception{calls[0]++;throw PublicCapabilities.stop("UPSTREAM_TIMEOUT");}
            public Map<String,Object> recover(StepWorkflow.Step step,StepWorkflow.Runtime runtime,Map<String,Object> results){calls[1]++;return Map.of("status","completed","output",Map.of("receipt","original"),"covered_slots",List.of("answer"));}
        };
        var steps=List.of(new StepWorkflow.Step("answer",Map.of("question","same"),List.of(),List.of("answer")));var options=StepWorkflow.Options.defaults("workflow",List.of("answer"));
        assertThrows(CapabilityClient.Failure.class,()->StepWorkflow.run(port,steps,executor,options));
        Object deadline=((Map<?,?>)port.checkpoint.get("value")).get("deadline_ms");
        assertEquals("completed",StepWorkflow.run(port,steps,executor,options).get("status"));assertArrayEquals(new int[]{1,1},calls);assertEquals(deadline,((Map<?,?>)port.checkpoint.get("value")).get("deadline_ms"));
        var changed=List.of(new StepWorkflow.Step("answer",Map.of("question","different"),List.of(),List.of("answer")));
        assertThrows(CapabilityClient.Failure.class,()->StepWorkflow.run(port,changed,executor,options));assertEquals(1,calls[0]);
    }
    @SuppressWarnings("unchecked") @Test void sharedPagedReferenceDigest()throws Exception{
        var fixture=PublicCapabilities.JSON.readValue(Files.readAllBytes(Path.of("../../../contracts/fixtures/recovery-checkpoint-set-v1.json")),new TypeReference<Map<String,Object>>(){});
        assertEquals(((Map<?,?>)fixture.get("set")).get("digest"),CheckpointReferenceSet.digestReferences((List<Map<String,Object>>)fixture.get("references")));
    }
    @SuppressWarnings("unchecked") @Test void sharedWorkflowRecoveryScenarios() throws Exception {
        var fixture = PublicCapabilities.JSON.readValue(Files.readAllBytes(Path.of("../../../contracts/fixtures/workflow-recovery-public-v1.json")), new TypeReference<Map<String,Object>>(){});
        for (Object raw : (List<?>)fixture.get("cases")) {
            var test = (Map<String,Object>)raw;
            String name = (String)test.get("name");
            var step = PublicCapabilities.JSON.convertValue(fixture.get("step"), StepWorkflow.Step.class);
            var port = new StatePort();
            port.denied = name.equals("revoked");
            int[] counts = {0, 0};
            var executor = new StepWorkflow.Executor() {
                private Map<String,Object> receipt() {
                    return Map.of("status", "completed", "covered_slots", List.of("answer"), "output", Map.of("receipt", "original"));
                }
                public Map<String,Object> execute(StepWorkflow.Step step, StepWorkflow.Runtime runtime, Map<String,Object> results) throws Exception {
                    if (name.equals("budget_exhausted")) runtime.admitCalls(List.of(new StepWorkflow.Call("tool", "left"), new StepWorkflow.Call("tool", "right")));
                    runtime.admitCall("tool", runtime.operationKey());
                    counts[0]++;
                    if (name.equals("lost_tool_reply") || name.equals("readonly_pending")) throw PublicCapabilities.stop("UPSTREAM_TIMEOUT");
                    return receipt();
                }
                public Map<String,Object> recover(StepWorkflow.Step step, StepWorkflow.Runtime runtime, Map<String,Object> results) {
                    assertTrue(runtime.recovering());
                    counts[1]++;
                    return receipt();
                }
            };
            var options = new StepWorkflow.Options("shared", List.of("answer"), 6,
                Map.of("tool", name.equals("budget_exhausted") ? 1 : 8), java.time.Duration.ofMinutes(1),
                name.equals("timeout") ? 1L : null, null, 1, false, false);
            Map<String,Object> result = null;
            String error = null;
            try {
                if (name.equals("cancelled_before_dispatch")) Thread.currentThread().interrupt();
                if (name.equals("lost_tool_reply") || name.equals("readonly_pending")) {
                    try { StepWorkflow.run(port, List.of(step), executor, options); fail("lost reply completed: " + name); }
                    catch (CapabilityClient.Failure unknown) { assertEquals("UPSTREAM_TIMEOUT", unknown.code(), name); }
                    options = new StepWorkflow.Options(options.key(), options.requiredSlots(), options.maxSteps(), options.maxCalls(),
                        options.timeout(), options.deadlineMs(), null, options.maxExtensions(), false, name.equals("readonly_pending"));
                }
                result = StepWorkflow.run(port, List.of(step), executor, options);
                if (name.equals("duplicate") || name.equals("parameter_conflict")) {
                    if (name.equals("parameter_conflict")) step = new StepWorkflow.Step(step.id(), Map.of("query", "different"), step.dependsOn(), step.requiredSlots());
                    result = StepWorkflow.run(port, List.of(step), executor, options);
                }
            } catch (InterruptedException cancelled) { error = "CANCELLED"; }
              catch (CapabilityClient.Failure failure) { error = failure.code(); }
            finally { Thread.interrupted(); }
            assertEquals(test.get("error"), error, name);
            if (error == null) {
                assertEquals(test.get("status"), result.get("status"), name);
                if (test.containsKey("finish_reason")) assertEquals(test.get("finish_reason"), result.get("finish_reason"), name);
            }
            assertEquals(PublicCapabilities.integer(test.get("sends")), counts[0], name);
            assertEquals(PublicCapabilities.integer(test.get("recoveries")), counts[1], name);
        }
    }
}
