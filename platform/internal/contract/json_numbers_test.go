package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExecutionJSONPreservesFrozenNumericEvidence(t *testing.T) {
	const raw = `{"input":{"coverage":1.0,"large_id":9007199254740993,"exponent":1e+3,"negative_zero":-0.0,"ordinary":7,"nested":[{"value":0.0000}]},"resume_input":{"threshold":1.00}}`
	var request ExecuteRequest
	if err := DecodeJSONPreservingNumbers([]byte(raw), &request); err != nil {
		t.Fatal(err)
	}
	for key, literal := range map[string]string{"coverage": "1.0", "large_id": "9007199254740993", "exponent": "1e+3", "negative_zero": "-0.0", "ordinary": "7"} {
		if number, ok := request.Input[key].(json.Number); !ok || number.String() != literal {
			t.Fatalf("numeric evidence changed at %s: %v", key, request.Input[key])
		}
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{`"coverage":1.0`, `"large_id":9007199254740993`, `"exponent":1e+3`, `"negative_zero":-0.0`, `"value":0.0000`, `"threshold":1.00`} {
		if !strings.Contains(string(encoded), fragment) {
			t.Fatalf("forwarded execution evidence lost %s", fragment)
		}
	}
}

func TestNumberPreservingJSONRejectsIncompleteOrMultipleValues(t *testing.T) {
	for _, raw := range []string{"", `{`, `{"input":{"value":1.0}} {}`, `{"input":{}} null`, `{"input":{}} garbage`, `{"input":{"value":NaN}}`, `{"input":{"value":01}}`} {
		t.Run(raw, func(t *testing.T) {
			var request ExecuteRequest
			if DecodeJSONPreservingNumbers([]byte(raw), &request) == nil {
				t.Fatal("invalid persisted execution accepted")
			}
		})
	}
	var typed struct {
		Count uint64 `json:"count"`
	}
	if err := DecodeJSONPreservingNumbers([]byte("{\"count\":9007199254740993} \r\n\t"), &typed); err != nil || typed.Count != 9007199254740993 {
		t.Fatal("typed integer or JSON whitespace behavior changed", err)
	}
	if DecodeJSONPreservingNumbers([]byte(`{"count":1.5}`), &typed) == nil {
		t.Fatal("fractional integer field accepted")
	}
}

func TestExecutionSignatureDoesNotCollapseFrozenNumbers(t *testing.T) {
	var request ExecuteRequest
	if err := DecodeJSONPreservingNumbers([]byte(`{"input":{"coverage":1.0,"source_id":9007199254740993}}`), &request); err != nil {
		t.Fatal(err)
	}
	original, err := CanonicalExecuteBodyHash(request)
	if err != nil {
		t.Fatal(err)
	}
	request.ContextToken = "excluded-token"
	if hash, err := CanonicalExecuteBodyHash(request); err != nil || hash != original {
		t.Fatal("token entered its own body signature")
	}
	request.Input["source_id"] = json.Number("9007199254740992")
	if hash, err := CanonicalExecuteBodyHash(request); err != nil || hash == original {
		t.Fatal("distinct source identifiers collapsed in signed request")
	}
	request.Input["source_id"] = json.Number("9007199254740993")
	request.Input["coverage"] = json.Number("1")
	if hash, err := CanonicalExecuteBodyHash(request); err != nil || hash == original {
		t.Fatal("frozen numeric representation changed without changing signature")
	}
}
