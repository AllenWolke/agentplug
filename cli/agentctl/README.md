# agentctl

`agentctl` is the cross-platform productization entry point. It emits the
versioned JSON result contract and never executes a shell string. The control
plane remains the authority for publish and approval. Local commands create,
inspect, validate, run the Conformance Runner, package source or an explicitly
requested Docker image (with digest/provenance), and submit a draft to the
configured PF-02 publish URL; no command bypasses approval.
