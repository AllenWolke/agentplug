package execution

import "errors"

// ReviewPreview is the explicit, versioned subset a business Agent offers to an
// independently authorized reviewer. Owner input, tokens and arbitrary output
// fields never become review content merely because a run is waiting.
type ReviewPreview struct {
	SchemaVersion string            `json:"schema_version"`
	Title         string            `json:"title"`
	Summary       string            `json:"summary"`
	References    []ReviewReference `json:"references,omitempty"`
}

type ReviewReference struct {
	DocID   string `json:"doc_id"`
	Title   string `json:"title"`
	Source  string `json:"source,omitempty"`
	Clause  string `json:"clause,omitempty"`
	ChunkID string `json:"chunk_id,omitempty"`
}

func (p ReviewPreview) Validate() error {
	if p.SchemaVersion != "agent-review/v1" || p.Title == "" || len(p.Title) > 256 || p.Summary == "" || len(p.Summary) > 10000 || len(p.References) > 20 {
		return errors.New("invalid review preview")
	}
	for _, r := range p.References {
		if len(r.DocID) > 256 || len(r.Title) > 512 || len(r.Source) > 128 || len(r.Clause) > 512 || len(r.ChunkID) > 256 {
			return errors.New("invalid review reference")
		}
	}
	return nil
}
