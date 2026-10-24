package execution

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/lexagent/platform/internal/contract"
)

func TestCommandAuthorityDecodePreservesCompleteContractTypeValidation(t *testing.T) {
	for _, raw := range []string{
		`{"operation":"invoke","input_schema":"schema://fixture","context_token":"secret","input":{"items":[1,2]}}`,
		`{"operation":"run","scope":{"authorization_epoch":9007199254740991},"resume_input":{"decision":"approve"}}`,
		`null`, `{}`, `{"input":null}`, `{"input":[]}`, `{"input":"bad"}`,
		`{"resume_input":1}`, `{"scope":[]}`, `{"context_token":1}`,
		`{"operation":true}`, `{"scope":{"authorization_epoch":"bad"}}`,
		`{"input":`, `{} {}`, `[{}]`,
	} {
		t.Run(raw, func(t *testing.T) {
			var full contract.ExecuteRequest
			original := json.Unmarshal([]byte(raw), &full)
			for i := 0; i < 2; i++ {
				got, err := commandAuthorityHeaders.Decode([]byte(raw))
				if (original == nil) != (err == nil) {
					t.Fatalf("decode acceptance changed: original=%v cached=%v", original, err)
				}
				if original == nil && got != (commandAuthorityHeader{full.Operation, full.InputSchema, full.ContextToken == ""}) {
					t.Fatal("cached metadata differs from original command")
				}
			}
		})
	}
}

func TestCommandAuthorityDecodeTracksChangedBytesAndRetainsNoPayload(t *testing.T) {
	first, err := commandAuthorityHeaders.Decode([]byte(`{"operation":"invoke","input_schema":"schema://fixture","input":{"private":"not-retained"}}`))
	if err != nil || !first.ContextTokenEmpty {
		t.Fatal(first, err)
	}
	changed, err := commandAuthorityHeaders.Decode([]byte(`{"operation":"resume","input_schema":"schema://other","context_token":"secret"}`))
	if err != nil || changed.Operation != "resume" || changed.InputSchema != "schema://other" || changed.ContextTokenEmpty {
		t.Fatal(changed, err)
	}
	// The cached value must remain an explicit scalar projection. A future
	// refactor cannot silently retain bearer tokens or the business request.
	typ := reflect.TypeOf(first)
	if typ.NumField() != 3 || typ.Field(0).Name != "Operation" || typ.Field(1).Name != "InputSchema" || typ.Field(2).Name != "ContextTokenEmpty" {
		t.Fatal("command decode cache retained unexpected data")
	}
}

// Pure local parsing measurement; it is not a service latency percentile.
func BenchmarkCommandAuthorityDecode(b *testing.B) {
	command := contract.ExecuteRequest{Operation: "invoke", InputSchema: "schema://fixture", Input: map[string]any{
		"items": strings.Repeat("representative-immutable-command-", 4096),
	}}
	raw, err := json.Marshal(command)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("original_complete_decode", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(raw)))
		for i := 0; i < b.N; i++ {
			var value contract.ExecuteRequest
			if err := json.Unmarshal(raw, &value); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("warm_scalar_projection", func(b *testing.B) {
		if _, err := commandAuthorityHeaders.Decode(raw); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.SetBytes(int64(len(raw)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := commandAuthorityHeaders.Decode(raw); err != nil {
				b.Fatal(err)
			}
		}
	})
}
