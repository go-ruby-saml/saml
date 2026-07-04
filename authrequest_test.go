package saml

import (
	"errors"
	"strings"
	"testing"
	"testing/iotest"
)

// withFixedID pins idFunc to a deterministic value for a test.
func withFixedID(t *testing.T, id string) {
	t.Helper()
	prev := idFunc
	idFunc = func() string { return id }
	t.Cleanup(func() { idFunc = prev })
}

// withMarshalError forces the XML marshaller seam to fail.
func withMarshalError(t *testing.T) {
	t.Helper()
	prev := marshalXML
	marshalXML = func(any) ([]byte, error) { return nil, errors.New("boom") }
	t.Cleanup(func() { marshalXML = prev })
}

func settingsForRequest() *Settings {
	return &Settings{
		IdPSSOTargetURL:             "https://idp.example.com/sso",
		IdPSLOTargetURL:             "https://idp.example.com/slo",
		SPEntityID:                  testAudience,
		AssertionConsumerServiceURL: testACS,
		NameIdentifierFormat:        NameIDFormatEmail,
	}
}

func TestAuthrequestCreate(t *testing.T) {
	withFixedClock(t)
	withFixedID(t, "_authn123")
	a := &Authrequest{}
	u, err := a.Create(settingsForRequest(), "state-xyz")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if a.UUID != "_authn123" {
		t.Errorf("UUID = %q", a.UUID)
	}
	if !strings.HasPrefix(u, "https://idp.example.com/sso?") {
		t.Errorf("redirect URL = %q", u)
	}
	if !strings.Contains(u, "SAMLRequest=") || !strings.Contains(u, "RelayState=state-xyz") {
		t.Errorf("missing query params: %q", u)
	}

	// The SAMLRequest round-trips to well-formed AuthnRequest XML.
	sr, err := a.SAMLRequest(settingsForRequest())
	if err != nil {
		t.Fatalf("saml request: %v", err)
	}
	doc, err := DecodeSAMLRequest(sr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	s := string(doc)
	for _, want := range []string{"AuthnRequest", testACS, testAudience, NameIDFormatEmail} {
		if !strings.Contains(s, want) {
			t.Errorf("decoded request missing %q in %s", want, s)
		}
	}
}

func TestAuthrequestNoRelayState(t *testing.T) {
	withFixedClock(t)
	a := &Authrequest{}
	u, err := a.Create(settingsForRequest(), "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.Contains(u, "RelayState") {
		t.Errorf("unexpected RelayState: %q", u)
	}
}

func TestAuthrequestMinimalSettings(t *testing.T) {
	withFixedClock(t)
	// No SPEntityID and no NameIdentifierFormat exercise the omitted branches.
	s := &Settings{IdPSSOTargetURL: "https://idp.example.com/sso"}
	a := &Authrequest{}
	sr, err := a.SAMLRequest(s)
	if err != nil {
		t.Fatalf("saml request: %v", err)
	}
	doc, err := DecodeSAMLRequest(sr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(string(doc), "Issuer") || strings.Contains(string(doc), "NameIDPolicy") {
		t.Errorf("unexpected optional elements: %s", doc)
	}
}

func TestAuthrequestMarshalError(t *testing.T) {
	withMarshalError(t)
	a := &Authrequest{}
	if _, err := a.SAMLRequest(settingsForRequest()); err == nil {
		t.Fatal("expected marshal error")
	}
	if _, err := a.Create(settingsForRequest(), ""); err == nil {
		t.Fatal("expected marshal error from Create")
	}
}

func TestAuthrequestBadURL(t *testing.T) {
	withFixedClock(t)
	s := settingsForRequest()
	s.IdPSSOTargetURL = "http://a\x7f.example" // control char -> url.Parse error
	a := &Authrequest{}
	if _, err := a.Create(s, ""); err == nil {
		t.Fatal("expected url parse error")
	}
}

func TestDecodeSAMLRequestErrors(t *testing.T) {
	if _, err := DecodeSAMLRequest("!!!not base64!!!"); err == nil {
		t.Fatal("expected base64 error")
	}
	// Valid base64 that is not a valid DEFLATE stream.
	if _, err := DecodeSAMLRequest("aGVsbG8gd29ybGQ="); err == nil {
		t.Fatal("expected inflate error")
	}
}

func TestDefaultIDEntropy(t *testing.T) {
	// The real generator produces an underscore-prefixed identifier.
	id := defaultID()
	if !strings.HasPrefix(id, "_") || len(id) < 10 {
		t.Fatalf("defaultID = %q", id)
	}

	// A failing entropy source makes defaultID panic.
	prev := randReader
	randReader = iotest.ErrReader(errors.New("no entropy"))
	defer func() {
		randReader = prev
		if r := recover(); r == nil {
			t.Fatal("expected panic on entropy failure")
		}
	}()
	_ = defaultID()
}
