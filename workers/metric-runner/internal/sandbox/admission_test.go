package sandbox

import (
	"errors"
	"testing"
)

func validAdmission() Admission {
	return Admission{SignatureVerified: true, Network: "none", MaxOutputBytes: 1 << 20, MaxSeconds: 30, MaxPIDs: 16}
}

func TestValidateRequiresIsolation(t *testing.T) {
	for name, mutate := range map[string]func(*Admission){
		"signature": func(a *Admission) { a.SignatureVerified = false },
		"network":   func(a *Admission) { a.Network = "default" },
		"secret":    func(a *Admission) { a.SecretAccess = true },
		"limits":    func(a *Admission) { a.MaxOutputBytes = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			a := validAdmission()
			mutate(&a)
			if err := Validate(a); err == nil {
				t.Fatal("invalid admission unexpectedly accepted")
			}
		})
	}
	if err := Validate(validAdmission()); err != nil {
		t.Fatalf("valid admission rejected: %v", err)
	}
	if !errors.Is(Validate(Admission{}), ErrSignatureRequired) {
		t.Fatal("zero admission must fail closed at signature boundary")
	}
}
