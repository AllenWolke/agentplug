# gRPC Mapping Adapter

The adapter accepts only a pre-registered descriptor (`service`, `method`,
mapping hash and revision). The transport process is isolated from Harness and
can later be replaced by a generated gRPC client without changing the v2
contract.
