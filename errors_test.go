package saml

import "testing"

func TestValidationError(t *testing.T) {
	err := newValidationError("boom")
	if err.Error() != "boom" {
		t.Fatalf("Error() = %q", err.Error())
	}
	// It satisfies the error interface.
	var e error = err
	if e.Error() != "boom" {
		t.Fatalf("interface Error() = %q", e.Error())
	}
}
