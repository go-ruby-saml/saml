package saml

import (
	"errors"
	"strings"
	"testing"

	"github.com/beevik/etree"
)

func TestMetadataGenerateFull(t *testing.T) {
	s := baseSettings()
	out, err := Metadata{}.Generate(s)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	xmlStr := string(out)
	for _, want := range []string{"EntityDescriptor", "SPSSODescriptor", testAudience, testACS,
		"WantAssertionsSigned", "KeyDescriptor", NameIDFormatEmail} {
		if !strings.Contains(xmlStr, want) {
			t.Errorf("metadata missing %q", want)
		}
	}
	// It must parse as valid XML.
	if err := etree.NewDocument().ReadFromString(xmlStr); err != nil {
		t.Fatalf("metadata not well-formed: %v", err)
	}
}

func TestMetadataGenerateMinimal(t *testing.T) {
	s := &Settings{SPEntityID: testAudience, AssertionConsumerServiceURL: testACS}
	out, err := Metadata{}.Generate(s)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(string(out), "KeyDescriptor") {
		t.Errorf("unexpected KeyDescriptor without certificate")
	}
	if strings.Contains(string(out), "WantAssertionsSigned") {
		t.Errorf("unexpected WantAssertionsSigned")
	}
}

func TestMetadataGenerateBadCert(t *testing.T) {
	s := &Settings{SPEntityID: testAudience, Certificate: "not a pem"}
	if _, err := (Metadata{}).Generate(s); err == nil {
		t.Fatal("expected certificate error")
	}
}

func TestMetadataGenerateMarshalError(t *testing.T) {
	prev := marshalIndentXML
	marshalIndentXML = func(any, string, string) ([]byte, error) { return nil, errors.New("boom") }
	defer func() { marshalIndentXML = prev }()
	if _, err := (Metadata{}).Generate(baseSettings()); err == nil {
		t.Fatal("expected marshal error")
	}
}

// idpMetadataXML builds an IdP EntityDescriptor for round-trip parsing.
func idpMetadataXML(t *testing.T, redirectSSO bool, keyUse string) string {
	t.Helper()
	b64, err := certToBase64DER(idpCertPEM)
	if err != nil {
		t.Fatalf("cert der: %v", err)
	}
	kd := ""
	if keyUse != "none" {
		use := ""
		if keyUse != "" {
			use = ` use="` + keyUse + `"`
		}
		kd = `<md:KeyDescriptor` + use + `><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>` + b64 + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`
	}
	ssoBinding := HTTPPostBinding
	sloBinding := HTTPPostBinding
	if redirectSSO {
		ssoBinding = HTTPRedirectBinding
		sloBinding = HTTPRedirectBinding
	}
	return `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + testIssuer + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		kd +
		`<md:SingleSignOnService Binding="` + ssoBinding + `" Location="https://idp.example.com/sso"/>` +
		`<md:SingleLogoutService Binding="` + sloBinding + `" Location="https://idp.example.com/slo"/>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`
}

func TestIdpMetadataParseRoundTrip(t *testing.T) {
	s, err := IdpMetadataParser{}.Parse([]byte(idpMetadataXML(t, true, "signing")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.IdPEntityID != testIssuer {
		t.Errorf("entity id = %q", s.IdPEntityID)
	}
	if s.IdPSSOTargetURL != "https://idp.example.com/sso" {
		t.Errorf("sso = %q", s.IdPSSOTargetURL)
	}
	if s.IdPSLOTargetURL != "https://idp.example.com/slo" {
		t.Errorf("slo = %q", s.IdPSLOTargetURL)
	}
	// The parsed cert must round-trip: re-parsing it succeeds.
	if _, err := parseCertificate(s.IdPCert); err != nil {
		t.Fatalf("parsed idp cert invalid: %v", err)
	}
}

func TestIdpMetadataParseVariants(t *testing.T) {
	// POST-only bindings (redirect=false) still populate via the fallback.
	s, err := IdpMetadataParser{}.Parse([]byte(idpMetadataXML(t, false, "")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.IdPSSOTargetURL == "" || s.IdPSLOTargetURL == "" {
		t.Errorf("expected fallback endpoints, got %+v", s)
	}
	// A non-signing key is used as a fallback certificate.
	if s.IdPCert == "" {
		t.Errorf("expected fallback cert")
	}

	// No key descriptors -> no cert.
	s, err = IdpMetadataParser{}.Parse([]byte(idpMetadataXML(t, false, "none")))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.IdPCert != "" {
		t.Errorf("expected no cert, got %q", s.IdPCert)
	}
}

func TestIdpMetadataParseNoIDP(t *testing.T) {
	xmlDoc := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + testIssuer + `"></md:EntityDescriptor>`
	s, err := IdpMetadataParser{}.Parse([]byte(xmlDoc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.IdPEntityID != testIssuer || s.IdPSSOTargetURL != "" {
		t.Errorf("unexpected settings %+v", s)
	}
}

func TestIdpMetadataParseError(t *testing.T) {
	if _, err := (IdpMetadataParser{}).Parse([]byte("<a><b></a>")); err == nil {
		t.Fatal("expected unmarshal error")
	}
}

func TestFirstSigningCertEmptyKeyDescriptor(t *testing.T) {
	// A KeyDescriptor with an empty X509Data list is skipped.
	xmlDoc := `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + testIssuer + `">` +
		`<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
		`</md:IDPSSODescriptor></md:EntityDescriptor>`
	s, err := IdpMetadataParser{}.Parse([]byte(xmlDoc))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.IdPCert != "" {
		t.Errorf("expected no cert from empty X509Data")
	}
}
