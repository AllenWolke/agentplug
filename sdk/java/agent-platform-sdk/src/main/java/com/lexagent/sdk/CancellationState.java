package com.lexagent.sdk;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/** Validates PLATFORM completion, separately from the Agent stop acknowledgement. */
public final class CancellationState {
    private final String disposition;
    private final ObjectNode progress;
    private final boolean complete;
    private CancellationState(String disposition,ObjectNode progress,boolean complete){this.disposition=disposition;this.progress=progress;this.complete=complete;}
    public String disposition(){return disposition;}
    public ObjectNode progress(){return progress==null?null:progress.deepCopy();}
    public boolean complete(){return complete;}
    private static IllegalArgumentException invalid(){return new IllegalArgumentException("platform cancellation evidence unconfirmed");}
    public static CancellationState read(String status,JsonNode value){
        boolean absent=value==null||value.isNull();
        if(!"cancelling".equals(status)&&!"cancelled".equals(status)){if(!absent)throw invalid();return null;}
        if(absent)return new CancellationState("cancelled".equals(status)?"historical_unverified":"pending_unverified",null,false);
        if(!value.isObject()||!"cancellation-state/v1".equals(value.path("version").asText()))throw invalid();
        String disposition=value.path("disposition").asText();
        if(disposition.equals("historical_unverified")||disposition.equals("pending_unverified")){
            if(!status.equals(disposition.equals("historical_unverified")?"cancelled":"cancelling")||(!value.path("progress").isMissingNode()&&!value.path("progress").isNull()))throw invalid();
            return new CancellationState(disposition,null,false);
        }
        if(!disposition.equals("verified")&&!disposition.equals("in_progress"))throw invalid();
        JsonNode p=value.path("progress");
        if(!p.isObject()||!"cancellation-compensation/v1".equals(p.path("version").asText())||!p.path("stop_confirmed").isBoolean()||!p.path("cancellation_id").isTextual()||!p.path("cancellation_id").asText().matches("[0-9a-f]{64}"))throw invalid();
        String[] counts={"total","compensated","no_effect","unresolved","needs_attention"};
        for(String key:counts){JsonNode n=p.path(key);if(!n.isIntegralNumber()||!n.canConvertToInt()||n.intValue()<0||n.intValue()>16384)throw invalid();}
        String phase=p.path("phase").asText();
        if(!java.util.Set.of("stopping","compensating","needs_attention","complete").contains(phase)||p.path("compensated").intValue()+p.path("no_effect").intValue()+p.path("unresolved").intValue()!=p.path("total").intValue()||p.path("needs_attention").intValue()>p.path("unresolved").intValue())throw invalid();
        if(phase.equals("stopping")==p.path("stop_confirmed").booleanValue()||phase.equals("needs_attention")!=(p.path("needs_attention").intValue()>0))throw invalid();
        boolean complete=disposition.equals("verified");
        if(complete){if(!status.equals("cancelled")||!phase.equals("complete")||p.path("unresolved").intValue()!=0||!p.path("stop_confirmed").booleanValue())throw invalid();}else if(!status.equals("cancelling")||phase.equals("complete"))throw invalid();
        ObjectNode clean=((ObjectNode)p).objectNode();
        for(String key:new String[]{"version","cancellation_id","phase","stop_confirmed","total","compensated","no_effect","unresolved","needs_attention"})clean.set(key,p.get(key).deepCopy());
        return new CancellationState(disposition,clean,complete);
    }
}
