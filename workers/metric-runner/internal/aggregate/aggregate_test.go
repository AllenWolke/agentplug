package aggregate

import "testing"

func TestRatio(t *testing.T) {
	r := Ratio([]Sample{{1, 2}, {2, 2}})
	if r.Value != .75 || r.Status != "OK" {
		t.Fatalf("%+v", r)
	}
	if Ratio(nil).Status != "UNKNOWN" {
		t.Fatal("empty must be unknown")
	}
}
