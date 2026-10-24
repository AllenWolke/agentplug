package contract

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// DecodeJSONPreservingNumbers decodes one complete JSON value without rounding
// untyped numbers or changing their representation. Persisted execution input
// is evidence: decoding it must not change a frozen case or a forwarded command.
// Typed numeric fields retain encoding/json's existing conversion rules.
// Transport-specific size limits and schema validation remain with the caller.
func DecodeJSONPreservingNumbers(data []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return err
		}
		return errors.New("multiple JSON values")
	}
	return nil
}
