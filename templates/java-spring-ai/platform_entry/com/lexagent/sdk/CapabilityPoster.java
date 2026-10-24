package com.lexagent.sdk;
import java.util.Map;
@FunctionalInterface public interface CapabilityPoster {Map<String,Object> post(String path,Map<String,Object> input)throws CapabilityClient.Failure;}
