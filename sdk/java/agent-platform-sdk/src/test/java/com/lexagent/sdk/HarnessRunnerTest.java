package com.lexagent.sdk;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class HarnessRunnerTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static Map<String, Object> input() { return Map.of("messages", List.of(Map.of("role", "user", "content", "resolve")), "idempotency_key", "operation", "function_names", List.of("update")); }
    private static HarnessRunner.Options options() { return new HarnessRunner.Options("loop", 3, 4); }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> savedState(Fixture fixture) { return (Map<String, Object>) fixture.checkpoint.get("value"); }
    private static Map<String, Object> legacyState(String phase, int toolCount) throws Exception {
        var state = new java.util.LinkedHashMap<String, Object>();
        state.put("version", "harness-loop/v1"); state.put("input_hash", HarnessRunner.inputFingerprint(input(), options()));
        state.put("phase", phase); state.put("round", 0); state.put("tool_count", toolCount);
        state.put("messages", input().get("messages"));
        state.put("pending", List.of(Map.of("name", "ticket.update", "call_id", "legacy-call", "model_call_id", "model-call",
                "payload", Map.of("sequence", 9007199254740993L))));
        state.put("output", Map.of("completion_status", "incomplete", "finish_reason", "tools_pending"));
        state.put("prompt_hash", "approved-hash"); state.put("context_source_hash", "source-hash");
        return state;
    }
    private static final class Fixture implements HarnessRunner.Port {
        Map<String, Object> checkpoint;
        int models, effects, contexts;
        int policyQueries;
        long revision;
        boolean unknown, denied;
        boolean repeatSecondCall;
        boolean failReceiptSave, failModelSave;
        int modelQueries;
        String modelStatus = "completed";
        String policyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        long policyTimeMs = 1_700_000_000_000L;
        int maxRounds = 8, maxToolCalls = 16, maxRepeatedCalls = 1, maxElapsedSeconds = 300;
        String limitBehavior = "incomplete";
        Map<String,Object> modelReceipt;
        int queries;
        Map<String, Object> receipt;
        @SuppressWarnings("unchecked")
        public Map<String, Object> post(String path, Map<String, Object> command) throws CapabilityClient.Failure {
            if (path.endsWith("runtime/harness-policy")) {
                policyQueries++;
                return Map.of("version", "harness-policy/v1", "policy_hash", policyHash, "server_time_ms", policyTimeMs,
                        "limits", Map.of("max_rounds", maxRounds, "max_tool_calls", maxToolCalls,
                                "max_repeated_calls", maxRepeatedCalls, "max_elapsed_seconds", maxElapsedSeconds,
                                "limit_behavior", limitBehavior));
            }
            if (path.endsWith("state/checkpoint")) {
                if (command.get("operation").equals("save")) {
                    var value = (Map<?, ?>) command.get("value");
                    if (failModelSave && value.get("phase").equals("tool")) { failModelSave = false; throw new CapabilityClient.Failure("STATE_UNAVAILABLE", 503, false); }
                    if (failReceiptSave && value.get("phase").equals("model") && ((Number) value.get("tool_count")).intValue() == 1) {
                        failReceiptSave = false; throw new CapabilityClient.Failure("STATE_UNAVAILABLE", 503, false);
                    }
                    assertEquals(revision, ((Number) command.get("expected_revision")).longValue());
                    revision++;
                    checkpoint = Map.of("revision", revision, "value", JSON.convertValue(command.get("value"), Map.class));
                }
                var response = new java.util.LinkedHashMap<String, Object>();
                response.put("state_key", "a".repeat(64)); response.put("checkpoint", checkpoint);
                return response;
            }
            if (path.endsWith("model/receipt")) {
                modelQueries++;
                return Map.of("version","model-receipt/v1", "idempotency_key",command.get("idempotency_key"), "status",modelStatus, "receipt",modelReceipt);
            }
            if (path.endsWith("tool/receipt")) {
                queries++;
                if (!"opaque".equals(command.get("confirmation_token"))) throw new CapabilityClient.Failure("TOOL_CONFIRMATION_REQUIRED", 403, false);
                Map<String, Object> result = new java.util.LinkedHashMap<>();
                result.put("version", "tool-receipt/v1"); result.put("tool_name", command.get("name")); result.put("call_id", command.get("call_id"));
                result.put("status", unknown ? "unknown" : "completed"); result.put("receipt", receipt); return result;
            }
            if (path.endsWith("context/prepare")) {
                contexts++;
                if (denied) throw new CapabilityClient.Failure("CAPABILITY_DENIED", 403, false);
                assertEquals(List.of("update"), command.get("function_names"));
                var messages = new java.util.ArrayList<Object>(); messages.add(Map.of("role", "system", "content", "approved")); messages.addAll((List<?>) command.get("messages"));
                return Map.of("messages", messages, "prompt_template_hash", "approved-hash", "source_hash", "source-hash");
            }
            if (path.endsWith("model/generate")) {
                assertEquals("approved", ((Map<?, ?>) ((List<?>) command.get("messages")).get(0)).get("content"));
                assertEquals("approved-hash", command.get("prompt_template_hash"));
                assertEquals(List.of("update"), command.get("function_names"));
                models++;
                if (models == 1 || repeatSecondCall && models == 2) {
                    String modelCallID = models == 1 ? "call-1" : "call-2";
                    String arguments = repeatSecondCall
                            ? (models == 1
                                    ? "{\"sequence\":9007199254740993,\"nested\":{\"b\":\"<\",\"a\":\"&\"},\"text\":\"<&>\\u2028\\u2029\"}"
                                    : "{\"text\":\"<&>\\u2028\\u2029\",\"nested\":{\"a\":\"&\",\"b\":\"<\"},\"sequence\":9007199254740993}")
                            : "{\"sequence\":9007199254740993}";
                    modelReceipt = Map.of("text", "partial", "completion_status", "tool_calls", "function_bindings", Map.of("update", "ticket.update"),
                        "tool_calls", List.of(Map.of("id", modelCallID, "function", Map.of("name", "update", "arguments", arguments))));
                    return modelReceipt; }
                return Map.of("text", "complete");
            }
            assertEquals(9007199254740993L, ((Number) ((Map<?, ?>) command.get("payload")).get("sequence")).longValue());
            if (!"opaque".equals(command.get("confirmation_token"))) throw new CapabilityClient.Failure("TOOL_CONFIRMATION_REQUIRED", 403, false);
            effects++;
            if (unknown) throw new CapabilityClient.Failure("TOOL_RESULT_UNKNOWN", 409, false);
            receipt = Map.of("observation", Map.of("version", "runtime-observation/v1", "tool_name", "ticket.update", "call_id", command.get("call_id"),
                    "status", "succeeded", "effect", "completed", "instruction_trust", "untrusted_data", "context_output", Map.of("ok", true)));
            return receipt;
        }

        void seedState(Map<String, Object> value, long savedRevision) {
            revision = savedRevision;
            checkpoint = Map.of("revision", savedRevision, "value", value);
        }
    }
    @Test void approvalPauseResumeAndCompletedReplayPreserveBinding() throws Exception {
        var fixture = new Fixture(); var options = new HarnessRunner.Options("loop", 3, 4);
        var pending = HarnessRunner.run(fixture, "trusted-run", input(), options);
        assertEquals("approval_required", pending.get("status"));
        assertEquals("trusted-run", ((Map<?, ?>) pending.get("pending")).get("run_id"));
        assertEquals(1, ((Map<?, ?>) savedState(fixture).get("tool_repeats")).size());
        assertTrue(((String) savedState(fixture).get("repeat_counted_call_id")).length() > 0);
        assertEquals(pending, HarnessRunner.run(fixture, "trusted-run", input(), options));
        assertEquals(1, ((Map<?, ?>) savedState(fixture).get("tool_repeats")).size());
        assertEquals(1, fixture.models); assertEquals(0, fixture.effects);
        var result = HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4, "opaque"));
        assertEquals("completed", result.get("status")); assertEquals(2, fixture.models); assertEquals(1, fixture.effects); assertEquals(2, fixture.contexts);
        assertEquals(result, HarnessRunner.run(fixture, "trusted-run", input(), options));
        assertEquals(2, fixture.models); assertEquals(1, fixture.effects);
        assertEquals(1, ((Map<?, ?>) savedState(fixture).get("tool_repeats")).size());
        assertEquals("", savedState(fixture).get("repeat_counted_call_id"));
        assertEquals(fixture.policyHash, savedState(fixture).get("loop_policy_hash"));
        assertEquals(8, ((Number) ((Map<?, ?>) savedState(fixture).get("loop_limits")).get("max_rounds")).intValue());
        assertFalse(JSON.writeValueAsString(fixture.checkpoint).contains("opaque"));
        assertEquals("HarnessRunner.Options[redacted]", new HarnessRunner.Options("loop", 3, 4, "opaque").toString());
        assertEquals("HARNESS_STATE_REJECTED", assertThrows(CapabilityClient.Failure.class,
                () -> HarnessRunner.run(fixture, "trusted-run", Map.of("messages", List.of(Map.of("role", "user", "content", "changed")), "idempotency_key", "operation"), options)).code());
    }
    @Test void unknownEffectStopsRecoveryWithoutRedispatch() throws Exception {
        var fixture = new Fixture(); fixture.unknown = true;
        var options = new HarnessRunner.Options("loop", 3, 4, "opaque");
        assertEquals("TOOL_RESULT_UNKNOWN", assertThrows(CapabilityClient.Failure.class, () -> HarnessRunner.run(fixture, "trusted-run", input(), options)).code());
        assertEquals("HARNESS_RECONCILIATION_REQUIRED", assertThrows(CapabilityClient.Failure.class, () -> HarnessRunner.run(fixture, "trusted-run", input(), options)).code());
        assertEquals(1, fixture.effects); assertEquals(1, fixture.models);
    }
    @Test void contextDenialPrecedesProviderAndCheckpointDispatch() {
        var fixture = new Fixture(); fixture.denied = true;
        assertEquals("CAPABILITY_DENIED", assertThrows(CapabilityClient.Failure.class, () -> HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4))).code());
        assertEquals(0, fixture.models); assertEquals(0, fixture.effects); assertEquals(0, fixture.revision);
    }
    @Test void completedReceiptRecoversCheckpointFailureWithoutExecution() throws Exception {
        var fixture = new Fixture(); fixture.failReceiptSave = true;
        var approved = new HarnessRunner.Options("loop", 3, 4, "opaque");
        assertEquals("STATE_UNAVAILABLE", assertThrows(CapabilityClient.Failure.class, () -> HarnessRunner.run(fixture, "trusted-run", input(), approved)).code());
        var paused = HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4));
        assertEquals("approval_required", paused.get("status"));
        assertEquals("tool_dispatch", savedState(fixture).get("phase"));
        var savedPending = (Map<?, ?>) ((List<?>) savedState(fixture).get("pending")).get(0);
        assertEquals(savedPending.get("call_id"), ((Map<?, ?>) paused.get("pending")).get("call_id"));
        assertEquals(1, fixture.queries);
        assertEquals(1, fixture.effects);
        assertEquals("completed", HarnessRunner.run(fixture, "trusted-run", input(), approved).get("status"));
        assertEquals(1, fixture.effects); assertEquals(2, fixture.models); assertEquals(2, fixture.queries);
    }
    @Test void modelReceiptRecoveryNeverRepeatsDispatchOrContext() throws Exception {
        for (String status : List.of("completed", "not_found", "running", "failed", "reconcile")) {
            var fixture = new Fixture(); fixture.failModelSave = true; fixture.modelStatus = status;
            var options = new HarnessRunner.Options("loop", 3, 4, "opaque");
            assertEquals("STATE_UNAVAILABLE", assertThrows(CapabilityClient.Failure.class, () -> HarnessRunner.run(fixture, "trusted-run", input(), options)).code());
            if (status.equals("completed")) {
                assertEquals("completed", HarnessRunner.run(fixture, "trusted-run", input(), options).get("status"));
                assertEquals(2, fixture.models); assertEquals(2, fixture.contexts); assertEquals(1, fixture.effects);
            } else {
                assertEquals("HARNESS_RECONCILIATION_REQUIRED", assertThrows(CapabilityClient.Failure.class, () -> HarnessRunner.run(fixture, "trusted-run", input(), options)).code());
                assertEquals(1, fixture.models); assertEquals(1, fixture.contexts); assertEquals(0, fixture.effects);
            }
            assertEquals(1, fixture.modelQueries);
        }
    }

    @Test void publishedRepeatedCallLimitStopsBeforeSecondEffect() throws Exception {
        var fixture = new Fixture(); fixture.repeatSecondCall = true;
        var approval = HarnessRunner.run(fixture, "trusted-run", input(), options());
        assertEquals("approval_required", approval.get("status"));
        assertEquals(0, fixture.effects);
        var result = HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4, "opaque"));
        assertEquals("incomplete", result.get("status"));
        var output = (Map<?, ?>) result.get("output");
        assertEquals("HARNESS_LIMIT_EXCEEDED", output.get("termination_reason"));
        assertEquals("repeated_tool_limit", output.get("finish_reason"));
        assertEquals(2, fixture.models); assertEquals(1, fixture.effects);
        assertEquals(1, ((Number) savedState(fixture).get("tool_count")).intValue());
        assertEquals(1, ((Number) ((Map<?, ?>) savedState(fixture).get("tool_repeats")).values().iterator().next()).intValue());
    }

    @Test void repeatDigestPreservesLargeIntegersAndCanonicalStringEscaping() throws Exception {
        var payload = JSON.readTree("{\"large\":9007199254740993,\"text\":\"<&>\\u2028\"}");
        assertEquals("8f3c1c20fc247e8d0a658a69ff89672d53d40ecafb9791c8221122d29e96fe9a",
                HarnessRunner.repeatedToolDigest("x", payload));
    }

    @Test void publishedRoundLimitErrorIsPersistedBeforeItIsRaised() {
        var fixture = new Fixture(); fixture.maxRounds = 1; fixture.limitBehavior = "error";
        var failure = assertThrows(CapabilityClient.Failure.class,
                () -> HarnessRunner.run(fixture, "trusted-run", input(), options()));
        assertEquals("HARNESS_LIMIT_EXCEEDED", failure.code());
        assertEquals("done", savedState(fixture).get("phase"));
        assertEquals(Boolean.TRUE, savedState(fixture).get("limit_error"));
        assertEquals("round_limit", ((Map<?, ?>) savedState(fixture).get("output")).get("finish_reason"));
        assertEquals(1, fixture.models); assertEquals(0, fixture.effects);
    }

    @Test void elapsedDeadlineIncludesApprovalDowntime() throws Exception {
        var fixture = new Fixture(); fixture.maxElapsedSeconds = 10;
        assertEquals("approval_required", HarnessRunner.run(fixture, "trusted-run", input(), options()).get("status"));
        fixture.policyTimeMs += 11_000;
        var resumed = HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4, "opaque"));
        assertEquals("incomplete", resumed.get("status"));
        var output = (Map<?, ?>) resumed.get("output");
        assertEquals("elapsed_limit", output.get("finish_reason"));
        assertEquals("HARNESS_LIMIT_EXCEEDED", output.get("termination_reason"));
        assertEquals(0, fixture.effects); assertEquals(1, fixture.models);
        assertFalse(savedState(fixture).containsKey("pending"));
    }

    @Test void policyChangeDuringApprovalRejectsResumeBeforeToolDispatch() throws Exception {
        var fixture = new Fixture();
        assertEquals("approval_required", HarnessRunner.run(fixture, "trusted-run", input(), options()).get("status"));
        fixture.policyHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assertEquals("HARNESS_POLICY_CHANGED", assertThrows(CapabilityClient.Failure.class,
                () -> HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4, "opaque"))).code());
        assertEquals(0, fixture.effects); assertEquals(1, fixture.models);
    }

    @Test void legacyDispatchIsSettledBeforeLegacyHistoryIsRejected() throws Exception {
        var fixture = new Fixture(); fixture.models = 1;
        fixture.receipt = Map.of("observation", Map.of("version", "runtime-observation/v1", "tool_name", "ticket.update",
                "call_id", "legacy-call", "status", "succeeded", "effect", "completed", "instruction_trust", "untrusted_data",
                "context_output", Map.of("ok", true)));
        fixture.seedState(legacyState("tool_dispatch", 1), 1);
        var approval = HarnessRunner.run(fixture, "trusted-run", input(), options());
        assertEquals("approval_required", approval.get("status"));
        assertEquals("tool_dispatch", savedState(fixture).get("phase"));
        assertEquals(1, fixture.queries); assertEquals(0, fixture.effects);
        assertEquals("HARNESS_STATE_REJECTED", assertThrows(CapabilityClient.Failure.class,
                () -> HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4, "opaque"))).code());
        assertEquals(2, fixture.queries); assertEquals(1, fixture.models); assertEquals(0, fixture.effects);
        assertEquals(2, ((Number) savedState(fixture).get("tool_count")).intValue());
        assertFalse(savedState(fixture).containsKey("loop_policy_hash"));
    }

    @Test void legacyDispatchWithNoPriorToolsImportsSettledReceiptBeforeContinuing() throws Exception {
        var fixture = new Fixture(); fixture.models = 1;
        fixture.receipt = Map.of("observation", Map.of("version", "runtime-observation/v1", "tool_name", "ticket.update",
                "call_id", "legacy-call", "status", "succeeded", "effect", "completed", "instruction_trust", "untrusted_data",
                "context_output", Map.of("ok", true)));
        fixture.seedState(legacyState("tool_dispatch", 0), 1);
        var approval = HarnessRunner.run(fixture, "trusted-run", input(), options());
        assertEquals("approval_required", approval.get("status"));
        assertEquals("tool_dispatch", savedState(fixture).get("phase"));
        assertEquals(1, fixture.queries); assertEquals(0, fixture.effects);
        var result = HarnessRunner.run(fixture, "trusted-run", input(), new HarnessRunner.Options("loop", 3, 4, "opaque"));
        assertEquals("completed", result.get("status"));
        assertEquals(2, fixture.queries); assertEquals(0, fixture.effects);
        assertEquals(1, ((Number) savedState(fixture).get("tool_count")).intValue());
        assertEquals(1, ((Number) ((Map<?, ?>) savedState(fixture).get("tool_repeats")).values().iterator().next()).intValue());
    }

    @Test void legacyNonDispatchStateWithConsumedToolsCannotInventRepeatHistory() throws Exception {
        var fixture = new Fixture(); fixture.seedState(legacyState("model", 1), 1);
        assertEquals("HARNESS_STATE_REJECTED", assertThrows(CapabilityClient.Failure.class,
                () -> HarnessRunner.run(fixture, "trusted-run", input(), options())).code());
        assertEquals(0, fixture.models); assertEquals(0, fixture.effects); assertEquals(1, fixture.revision);
        assertFalse(savedState(fixture).containsKey("loop_policy_hash"));
    }
}
