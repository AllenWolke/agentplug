package knowledge

import (
	"encoding/json"
	"testing"
)

type sourceDecodeRow struct {
	indexed SourceDocument
	raw     []byte
}

func (row sourceDecodeRow) Scan(dest ...any) error {
	*dest[0].(*string) = row.indexed.ID
	*dest[1].(*int64) = row.indexed.Version
	*dest[2].(*int64) = row.indexed.SourceRevision
	*dest[3].(*int64) = row.indexed.ACLRevision
	*dest[4].(*bool) = row.indexed.Deleted
	*dest[5].(*string) = row.indexed.ContentDigest
	*dest[6].(*[]byte) = row.raw
	return nil
}
func sourceDecodeFixture(t *testing.T) sourceDecodeRow {
	t.Helper()
	document := SourceDocument{ID: "decode-document", Version: 1, SourceRevision: 1, ACLRevision: 1, Body: "original body", Metadata: map[string]string{"valid_from": "2026-01-01"}, ACL: DocumentACL{OwnerPrincipalID: "owner", Readers: []string{"reader"}}}
	digest, err := sourceDigest(struct {
		Body     string
		Metadata map[string]string `json:"metadata,omitempty"`
	}{document.Body, document.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	document.ContentDigest = digest
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return sourceDecodeRow{document, raw}
}
func TestSourceDecodeReusePreservesCurrentColumnsAndOwnedValues(t *testing.T) {
	row := sourceDecodeFixture(t)
	first, err := scanSourceDocument(row)
	if err != nil {
		t.Fatal(err)
	}
	first.Metadata["valid_from"] = "mutated"
	first.ACL.Readers[0] = "foreign"
	again, err := scanSourceDocument(row)
	if err != nil || again.Metadata["valid_from"] != "2026-01-01" || again.ACL.Readers[0] != "reader" {
		t.Fatal("mutable result poisoned decode cache", err)
	}
	for _, field := range []string{"id", "version", "source", "acl", "deleted", "digest"} {
		t.Run(field, func(t *testing.T) {
			changed := row
			switch field {
			case "id":
				changed.indexed.ID = "other"
			case "version":
				changed.indexed.Version++
			case "source":
				changed.indexed.SourceRevision++
			case "acl":
				changed.indexed.ACLRevision++
			case "deleted":
				changed.indexed.Deleted = true
			case "digest":
				changed.indexed.ContentDigest = "other"
			}
			if _, err := scanSourceDocument(changed); err != ErrSourceCorrupt {
				t.Fatal("cached payload bypassed fresh columns", err)
			}
		})
	}
}
func TestSourceDecodeChangedAndCorruptBytesCannotReuseEarlierResult(t *testing.T) {
	row := sourceDecodeFixture(t)
	if _, err := scanSourceDocument(row); err != nil {
		t.Fatal(err)
	}
	changed := row.indexed
	changed.Body = "changed without matching digest"
	raw, _ := json.Marshal(changed)
	for range 2 {
		if _, err := scanSourceDocument(sourceDecodeRow{changed, raw}); err != ErrSourceCorrupt {
			t.Fatal("corrupt bytes accepted", err)
		}
	}
	changed = row.indexed
	changed.ACLRevision++
	changed.ACL.Readers = []string{"replacement"}
	raw, _ = json.Marshal(changed)
	got, err := scanSourceDocument(sourceDecodeRow{changed, raw})
	if err != nil || got.ACLRevision != 2 || got.ACL.Readers[0] != "replacement" {
		t.Fatal("new source authority bytes reused old ACL", err)
	}
	if _, err := scanSourceDocument(sourceDecodeRow{changed, []byte("{")}); err != ErrSourceCorrupt {
		t.Fatal("malformed source accepted", err)
	}
}
