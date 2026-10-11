package com.lexagent.sdk;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class CancellationStateTest {
    @Test void stopRequiresCompletedPlatformEvidence()throws Exception{
        assertFalse(CancellationState.read("cancelled",null).complete());
        ObjectNode value=(ObjectNode)new ObjectMapper().readTree("{\"version\":\"cancellation-state/v1\",\"disposition\":\"verified\",\"progress\":{\"version\":\"cancellation-compensation/v1\",\"cancellation_id\":\""+"a".repeat(64)+"\",\"phase\":\"complete\",\"stop_confirmed\":true,\"total\":2,\"compensated\":1,\"no_effect\":1,\"unresolved\":0,\"needs_attention\":0}}");
        assertTrue(CancellationState.read("cancelled",value).complete());
        ((ObjectNode)value.get("progress")).put("unresolved",1);
        assertThrows(IllegalArgumentException.class,()->CancellationState.read("cancelled",value));
    }
}
