package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lexagent/platform/internal/notification"
	"github.com/lexagent/platform/internal/sharedkernel"
)

type automaticRecoveryPolicy struct {
	holds     sharedkernel.RecoveryHolds
	toolHolds sharedkernel.RecoveryHolds
	offsets   []notification.KafkaStartOffset
	group     string
}

func readAutomaticRecoveryHolds(path, digest string) (sharedkernel.RecoveryHolds, error) {
	policy, err := readAutomaticRecoveryPolicy(path, digest)
	return policy.holds, err
}

func readAutomaticRecoveryPolicy(path, digest string) (automaticRecoveryPolicy, error) {
	deny := errors.New("automatic recovery hold manifest unavailable or invalid")
	if path == "" && digest == "" {
		return automaticRecoveryPolicy{}, nil
	}
	if !filepath.IsAbs(path) || len(digest) != 64 || strings.ToLower(digest) != digest {
		return automaticRecoveryPolicy{}, deny
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 8<<20 {
		return automaticRecoveryPolicy{}, deny
	}
	f, err := os.Open(path)
	if err != nil {
		return automaticRecoveryPolicy{}, deny
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (8<<20)+1))
	if err != nil || len(raw) > 8<<20 {
		return automaticRecoveryPolicy{}, deny
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != digest {
		return automaticRecoveryPolicy{}, deny
	}
	var manifest struct {
		Version           string                          `json:"version"`
		RunIDs            []string                        `json:"run_ids"`
		ToolScopeHashes   []string                        `json:"tool_scope_hashes,omitempty"`
		KafkaGroupID      string                          `json:"kafka_group_id,omitempty"`
		KafkaStartOffsets []notification.KafkaStartOffset `json:"kafka_start_offsets,omitempty"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&manifest) != nil || d.Decode(new(any)) != io.EOF || manifest.Version != "automatic-recovery-holds/v1" || manifest.RunIDs == nil {
		return automaticRecoveryPolicy{}, deny
	}
	holds, err := sharedkernel.NewRecoveryHolds(manifest.RunIDs)
	if err != nil || notification.ValidateKafkaStartOffsets(manifest.KafkaStartOffsets) != nil || (len(manifest.KafkaStartOffsets) > 0) != (manifest.KafkaGroupID != "") || len(manifest.KafkaGroupID) > 255 || strings.TrimSpace(manifest.KafkaGroupID) != manifest.KafkaGroupID {
		return automaticRecoveryPolicy{}, deny
	}
	for _, hash := range manifest.ToolScopeHashes {
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 32 || strings.ToLower(hash) != hash {
			return automaticRecoveryPolicy{}, deny
		}
	}
	toolHolds, err := sharedkernel.NewRecoveryHolds(manifest.ToolScopeHashes)
	if err != nil {
		return automaticRecoveryPolicy{}, deny
	}
	return automaticRecoveryPolicy{holds: holds, toolHolds: toolHolds, offsets: manifest.KafkaStartOffsets, group: manifest.KafkaGroupID}, nil
}
