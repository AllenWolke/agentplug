package policyasset

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// DraftPublication is explicit configuration, not authorization or health.
type DraftPublication struct {
	InstallationID   string       `json:"installation_id"`
	Scope            Scope        `json:"scope"`
	ExpectedRevision uint64       `json:"expected_revision"`
	Assets           []DraftAsset `json:"assets"`
	Rule             RulePolicy   `json:"rule,omitempty"`
}

// PublicationMatchesSnapshot compares complete immutable policy content and
// all six references. IDs alone cannot acknowledge a resumed publication.
func PublicationMatchesSnapshot(snapshot Snapshot, request PublishSnapshotRequest, assets map[AssetType]Asset) bool {
	if snapshot.Revision != request.ExpectedRevision+1 || snapshot.Hash == "" {
		return false
	}
	expected, err := snapshotFromAssets(request, assets)
	if err != nil {
		return false
	}
	for typ, asset := range assets {
		ref, ok := request.Assets[typ]
		if !ok || ref.ID != asset.ID || ref.Revision != asset.Revision {
			return false
		}
	}
	expected.Revision = snapshot.Revision
	hashInput, err := json.Marshal(struct {
		Snapshot Snapshot               `json:"snapshot"`
		Assets   map[AssetType]AssetRef `json:"assets"`
	}{expected, request.Assets})
	if err != nil {
		return false
	}
	checksum := sha256.Sum256(hashInput)
	expected.Hash = hex.EncodeToString(checksum[:])
	a, err := json.Marshal(expected)
	if err != nil {
		return false
	}
	b, err := json.Marshal(snapshot)
	return err == nil && bytes.Equal(a, b)
}

type DraftAsset struct {
	ID      string          `json:"id"`
	Type    AssetType       `json:"type"`
	Content json.RawMessage `json:"content"`
}

// PreparePublication validates all six components before a maintenance caller
// makes any write. Management uses the same canonical validators as HTTP.
func PreparePublication(d DraftPublication, actorID string) ([]Asset, error) {
	if !validID(d.InstallationID) || !validID(actorID) || d.Scope.validate() != nil || d.ExpectedRevision > 1_000_000_000 || len(d.Assets) != 6 {
		return nil, ErrInvalidSnapshot
	}
	assets := make([]Asset, 0, 6)
	seen := map[AssetType]bool{}
	byType := map[AssetType]Asset{}
	refs := map[AssetType]AssetRef{}
	for _, a := range d.Assets {
		if !validID(a.ID) || seen[a.Type] {
			return nil, ErrInvalidAsset
		}
		seen[a.Type] = true
		content, hash, err := canonicalContent(a.Type, a.Content)
		if err != nil {
			return nil, err
		}
		asset := Asset{ID: a.ID, Type: a.Type, Scope: d.Scope, Revision: 1, Status: AssetDraft, Content: content, Hash: hash, CreatedBy: actorID}
		assets = append(assets, asset)
		published := asset
		published.Revision = 2
		published.Status = AssetPublished
		byType[a.Type] = published
		refs[a.Type] = AssetRef{ID: a.ID, Revision: 2}
	}
	prospective, err := snapshotFromAssets(PublishSnapshotRequest{Scope: d.Scope, ExpectedRevision: d.ExpectedRevision, Assets: refs, Rule: d.Rule}, byType)
	if err != nil || prospective.ValidateDetails() != nil {
		return nil, ErrInvalidSnapshot
	}
	return assets, nil
}
