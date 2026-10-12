package generated;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

/** Jackson 3 must initialize alongside the Jackson 2 platform wire codec. */
final class JacksonCompatibilityTest {
    record WirePayload(@JsonProperty("trace_id") String traceId) {}

    @Test
    void bothJacksonGenerationsUseTheSameWireAnnotations() throws Exception {
        ObjectMapper platformMapper = new ObjectMapper();
        JsonMapper springMapper = JsonMapper.builder().build();
        WirePayload payload = new WirePayload("fixture-trace");
        String json = platformMapper.writeValueAsString(payload);
        assertEquals("{\"trace_id\":\"fixture-trace\"}", json);
        assertEquals(json, springMapper.writeValueAsString(payload));
        assertEquals(payload, springMapper.readValue(json, WirePayload.class));
    }
}
