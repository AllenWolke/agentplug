package agentplatform

import (
	"encoding/json"
	"strings"
)

func validBusinessSchemaReference(reference, agentID, kind string) bool {
	version, found := strings.CutPrefix(reference, "schema://"+agentID+"/"+kind+"/v")
	if !found || version == "" || version[0] < '1' || version[0] > '9' {
		return false
	}
	for _, digit := range version {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func validateManifest(cfg ServerConfig, capabilities map[string]bool) error {
	var manifest struct {
		ManifestVersion string            `json:"manifest_version"`
		AgentID         string            `json:"agent_id"`
		Version         string            `json:"version"`
		Protocols       []string          `json:"execution_protocols"`
		Capabilities    []string          `json:"capabilities"`
		Schemas         map[string]string `json:"schemas"`
		Runtime         map[string]string `json:"runtime"`
	}
	if json.Unmarshal(cfg.Manifest, &manifest) != nil || manifest.ManifestVersion != "agent-manifest/v1" ||
		manifest.AgentID != cfg.AgentID || manifest.Version != cfg.AgentVersion ||
		len(manifest.Protocols) != 1 || manifest.Protocols[0] != ProtocolVersion ||
		manifest.Runtime["transport"] != "http" || manifest.Runtime["isolation"] != "container" ||
		manifest.Runtime["health_path"] != "/health/ready" || manifest.Runtime["run_store"] != storeLabel(cfg.Store) {
		return ErrServerConfig
	}
	seen := map[string]bool{}
	for _, name := range manifest.Capabilities {
		if seen[name] || !capabilities[name] {
			return ErrServerConfig
		}
		seen[name] = true
	}
	if len(seen) != len(capabilities) {
		return ErrServerConfig
	}
	for _, name := range []string{"input", "output"} {
		if !validBusinessSchemaReference(manifest.Schemas[name], cfg.AgentID, name) {
			return ErrServerConfig
		}
	}
	return nil
}
