package saml

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
)

// hasErr reports whether errs contains msg.
func hasErr(errs []string, msg string) bool {
	for _, e := range errs {
		if e == msg {
			return true
		}
	}
	return false
}

func TestResponseValidAndExtraction(t *testing.T) {
	withFixedClock(t)
	resp, err := NewResponse(buildResponse(t, defaultOpts()), baseSettings())
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	resp.ExpectedInResponseTo = "_req123"
	if !resp.IsValid() {
		t.Fatalf("expected valid, got errors: %v", resp.Errors)
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got := resp.NameID(); got != testNameID {
		t.Errorf("NameID = %q", got)
	}
	attrs := resp.Attributes()
	if got := attrs["email"]; len(got) != 1 || got[0] != testNameID {
		t.Errorf("email attr = %v", got)
	}
	if got := attrs["roles"]; len(got) != 2 || got[0] != "admin" || got[1] != "user" {
		t.Errorf("roles attr = %v", got)
	}
	if got := resp.SessionIndex(); got != "_session789" {
		t.Errorf("SessionIndex = %q", got)
	}
	if got := resp.StatusCode(); got != statusSuccess {
		t.Errorf("StatusCode = %q", got)
	}
	if got := resp.Issuers(); len(got) != 1 || got[0] != testIssuer {
		t.Errorf("Issuers = %v", got)
	}
	if got := resp.Destination(); got != testACS {
		t.Errorf("Destination = %q", got)
	}
	if got := resp.InResponseTo(); got != "_req123" {
		t.Errorf("InResponseTo = %q", got)
	}
}

func TestResponseFingerprintPath(t *testing.T) {
	withFixedClock(t)
	for _, alg := range []string{"sha1", "sha256"} {
		s := baseSettings()
		s.IdPCert = ""
		s.IdPCertFingerprintAlgorithm = alg
		s.IdPCertFingerprint = idpCertFingerprint(t, alg)
		resp, err := NewResponse(buildResponse(t, defaultOpts()), s)
		if err != nil {
			t.Fatalf("new response: %v", err)
		}
		if !resp.IsValid() {
			t.Fatalf("alg=%s expected valid, errors: %v", alg, resp.Errors)
		}
	}
}

func TestResponseSignedResponseElement(t *testing.T) {
	withFixedClock(t)
	// Only the Response is signed (assertion left unsigned) so validation must
	// fall through to the response-level signature.
	o := defaultOpts()
	o.assertionUnsigned = true
	o.signResponse = true
	resp, err := NewResponse(buildResponse(t, o), baseSettings())
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if !resp.IsValid() {
		t.Fatalf("expected valid, errors: %v", resp.Errors)
	}
}

func TestResponseInvalidCases(t *testing.T) {
	withFixedClock(t)
	cases := []struct {
		name string
		mut  func(o *responseOpts)
		set  func(s *Settings, r *Response)
		want string
	}{
		{name: "tampered", mut: func(o *responseOpts) { o.tamper = true }, want: errInvalidSignature},
		{name: "expired", mut: func(o *responseOpts) { o.notOnOrAfter = refNow.Add(-1 * time.Minute) }, want: errNotOnOrAfter},
		{name: "not-yet", mut: func(o *responseOpts) { o.notBefore = refNow.Add(10 * time.Minute) }, want: errNotBefore},
		{name: "audience", mut: func(o *responseOpts) { o.audience = "https://evil.example.com" }, want: errInvalidAudience},
		{name: "destination", mut: func(o *responseOpts) { o.destination = "https://evil.example.com/acs" }, want: errInvalidDestination},
		{name: "issuer", mut: func(o *responseOpts) { o.issuer = "https://evil.example.com/idp" }, want: errInvalidIssuer},
		{name: "status", mut: func(o *responseOpts) { o.status = "urn:oasis:names:tc:SAML:2.0:status:Requester" }, want: errStatusNotSuccess},
		{name: "two-assertions", mut: func(o *responseOpts) { o.twoAssertion = true }, want: errNumAssertion},
		{
			name: "in-response-to",
			set:  func(s *Settings, r *Response) { r.ExpectedInResponseTo = "_mismatch" },
			want: errInvalidInResponseTo,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := defaultOpts()
			if tc.mut != nil {
				tc.mut(&o)
			}
			s := baseSettings()
			resp, err := NewResponse(buildResponse(t, o), s)
			if err != nil {
				t.Fatalf("new response: %v", err)
			}
			if tc.set != nil {
				tc.set(s, resp)
			}
			if resp.IsValid() {
				t.Fatalf("expected invalid")
			}
			if !hasErr(resp.Errors, tc.want) {
				t.Fatalf("want %q, got %v", tc.want, resp.Errors)
			}
		})
	}
}

func TestResponseValidateFailFast(t *testing.T) {
	withFixedClock(t)
	o := defaultOpts()
	o.tamper = true
	resp, err := NewResponse(buildResponse(t, o), baseSettings())
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	verr := resp.Validate()
	if verr == nil {
		t.Fatal("expected error")
	}
	if _, ok := verr.(*ValidationError); !ok {
		t.Fatalf("want *ValidationError, got %T", verr)
	}
}

func TestResponseUntrustedSigner(t *testing.T) {
	withFixedClock(t)
	// Sign with the SP key but keep idp_cert pointing at the IdP cert: the
	// embedded (SP) certificate will not match the trusted (IdP) root.
	o := defaultOpts()
	o.signWith = signerFromPEM(t, spKeyPEM, spCertPEM)
	resp, err := NewResponse(buildResponse(t, o), baseSettings())
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if resp.IsValid() {
		t.Fatal("expected invalid")
	}
	if !hasErr(resp.Errors, errInvalidSignature) {
		t.Fatalf("want signature error, got %v", resp.Errors)
	}
}

func TestResponseSettingsGuards(t *testing.T) {
	withFixedClock(t)
	valid := buildResponse(t, defaultOpts())

	// No settings.
	r, _ := NewResponse(valid, nil)
	if r.IsValid() || !hasErr(r.Errors, errNoSettings) {
		t.Fatalf("want no-settings error, got %v", r.Errors)
	}

	// Neither idp_cert nor fingerprint.
	s := baseSettings()
	s.IdPCert = ""
	s.IdPCertFingerprint = ""
	r, _ = NewResponse(valid, s)
	if r.IsValid() || !hasErr(r.Errors, errNoIdPCert) {
		t.Fatalf("want no-cert error, got %v", r.Errors)
	}
}

func TestResponseBlank(t *testing.T) {
	// A rootless document triggers the blank-response guard, and every
	// extraction accessor returns its zero value.
	r := &Response{settings: baseSettings(), doc: etree.NewDocument()}
	if r.IsValid() || !hasErr(r.Errors, errBlankResponse) {
		t.Fatalf("want blank error, got %v", r.Errors)
	}
	if r.NameID() != "" || r.SessionIndex() != "" || r.StatusCode() != "" ||
		r.Destination() != "" || r.InResponseTo() != "" {
		t.Fatal("expected empty accessors on rootless response")
	}
	if len(r.Attributes()) != 0 || len(r.Issuers()) != 0 || len(r.audiences()) != 0 || len(r.assertions()) != 0 {
		t.Fatal("expected empty collections on rootless response")
	}
	nb, na := r.conditionsTimes()
	if !nb.IsZero() || !na.IsZero() {
		t.Fatal("expected zero condition times")
	}
}

func TestResponseBadInput(t *testing.T) {
	if _, err := NewResponse("!!!not base64!!!", baseSettings()); err == nil {
		t.Fatal("expected base64 error")
	}
	// Valid base64 but malformed XML (mismatched tags).
	malformed := base64.StdEncoding.EncodeToString([]byte("<a><b></a>"))
	if _, err := NewResponse(malformed, baseSettings()); err == nil {
		t.Fatal("expected xml parse error")
	}
}

// rawResponse wraps a raw (unsigned) Response body around the given inner XML so
// extraction edge cases can be exercised directly.
func rawResponse(t *testing.T, inner string) *Response {
	t.Helper()
	xmlDoc := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r">` + inner + `</samlp:Response>`
	r, err := NewResponse(xmlDoc, baseSettings())
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	return r
}

func TestResponseExtractionEdges(t *testing.T) {
	// Response with no assertion: assertion-dependent accessors are empty.
	r := rawResponse(t, `<samlp:Status><samlp:StatusCode Value="`+statusSuccess+`"/></samlp:Status>`)
	if r.NameID() != "" || r.SessionIndex() != "" || len(r.Attributes()) != 0 {
		t.Fatal("expected empty accessors without assertion")
	}
	if len(r.audiences()) != 0 {
		t.Fatal("expected no audiences without assertion")
	}
	nb, na := r.conditionsTimes()
	if !nb.IsZero() || !na.IsZero() {
		t.Fatal("expected zero times without assertion")
	}

	// Assertion present but Subject lacks a NameID, no AuthnStatement, an
	// unnamed attribute (skipped) and Conditions without time bounds.
	inner := `<saml:Assertion><saml:Issuer>` + testIssuer + `</saml:Issuer>` +
		`<saml:Subject></saml:Subject>` +
		`<saml:Conditions></saml:Conditions>` +
		`<saml:AttributeStatement><saml:Attribute><saml:AttributeValue>x</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>` +
		`</saml:Assertion>`
	r = rawResponse(t, inner)
	if r.NameID() != "" {
		t.Errorf("NameID should be empty")
	}
	if r.SessionIndex() != "" {
		t.Errorf("SessionIndex should be empty")
	}
	if len(r.Attributes()) != 0 {
		t.Errorf("unnamed attribute must be skipped, got %v", r.Attributes())
	}
	nb, na = r.conditionsTimes()
	if !nb.IsZero() || !na.IsZero() {
		t.Errorf("missing bounds should be zero")
	}

	// StatusCode absent.
	r = rawResponse(t, `<saml:Assertion></saml:Assertion>`)
	if r.StatusCode() != "" {
		t.Errorf("StatusCode should be empty")
	}
}

func TestResponseIssuersDedup(t *testing.T) {
	// Response and Assertion carry the same issuer, plus an empty one to skip.
	inner := `<saml:Issuer>` + testIssuer + `</saml:Issuer>` +
		`<saml:Assertion><saml:Issuer>` + testIssuer + `</saml:Issuer></saml:Assertion>`
	r := rawResponse(t, inner)
	if got := r.Issuers(); len(got) != 1 || got[0] != testIssuer {
		t.Fatalf("Issuers dedup = %v", got)
	}
}

func TestResponseClockDrift(t *testing.T) {
	withFixedClock(t)
	// Expired by 30s, but a 60s drift tolerance keeps it valid.
	o := defaultOpts()
	o.notOnOrAfter = refNow.Add(-30 * time.Second)
	o.notBefore = refNow.Add(-2 * time.Hour)
	s := baseSettings()
	s.AllowedClockDrift = 60 * time.Second
	resp, err := NewResponse(buildResponse(t, o), s)
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if !resp.IsValid() {
		t.Fatalf("drift should keep valid, errors: %v", resp.Errors)
	}
}

func TestResponseNoSignatureElement(t *testing.T) {
	withFixedClock(t)
	// Neither assertion nor response signed: signature validation fails on the
	// missing signed element.
	o := defaultOpts()
	o.assertionUnsigned = true
	resp, err := NewResponse(buildResponse(t, o), baseSettings())
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if resp.IsValid() || !hasErr(resp.Errors, errInvalidSignature) {
		t.Fatalf("want signature error, got %v", resp.Errors)
	}
}

func TestResponseBadIdPCertPEM(t *testing.T) {
	withFixedClock(t)
	s := baseSettings()
	s.IdPCert = "-----BEGIN CERTIFICATE-----\ngarbage\n-----END CERTIFICATE-----"
	resp, err := NewResponse(buildResponse(t, defaultOpts()), s)
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if resp.IsValid() || !hasErr(resp.Errors, errInvalidSignature) {
		t.Fatalf("want signature error, got %v", resp.Errors)
	}
}

func TestResponseFingerprintMismatch(t *testing.T) {
	withFixedClock(t)
	s := baseSettings()
	s.IdPCert = ""
	s.IdPCertFingerprint = "AA:BB:CC"
	resp, err := NewResponse(buildResponse(t, defaultOpts()), s)
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if resp.IsValid() || !hasErr(resp.Errors, errInvalidSignature) {
		t.Fatalf("want signature error, got %v", resp.Errors)
	}
}

func TestResponseFingerprintBadAlgorithm(t *testing.T) {
	withFixedClock(t)
	s := baseSettings()
	s.IdPCert = ""
	s.IdPCertFingerprint = "whatever"
	s.IdPCertFingerprintAlgorithm = "md5"
	resp, err := NewResponse(buildResponse(t, defaultOpts()), s)
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if resp.IsValid() || !hasErr(resp.Errors, errInvalidSignature) {
		t.Fatalf("want signature error, got %v", resp.Errors)
	}
}

// signatureFixture returns a raw signed-element XML whose Signature can be
// mangled to hit embeddedCert failure paths.
func embeddedCertFixture(t *testing.T, certBody string) *etree.Element {
	t.Helper()
	el := etree.NewElement("Assertion")
	sig := el.CreateElement("Signature")
	if certBody != "" {
		x := sig.CreateElement("KeyInfo").CreateElement("X509Data").CreateElement("X509Certificate")
		x.SetText(certBody)
	}
	return el
}

func TestEmbeddedCertErrors(t *testing.T) {
	// Missing X509Certificate.
	if _, err := embeddedCert(embeddedCertFixture(t, "")); err == nil {
		t.Fatal("expected missing-cert error")
	}
	// Invalid base64.
	if _, err := embeddedCert(embeddedCertFixture(t, "!!not base64!!")); err == nil {
		t.Fatal("expected base64 error")
	}
	// Valid base64 that is not a certificate.
	if _, err := embeddedCert(embeddedCertFixture(t, "aGVsbG8=")); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestTrustedCertFingerprintPaths(t *testing.T) {
	withFixedClock(t)
	// trustedCert via fingerprint over a signed element lacking KeyInfo returns
	// the embeddedCert error.
	s := baseSettings()
	s.IdPCert = ""
	s.IdPCertFingerprint = "AA"
	r := &Response{settings: s}
	if _, err := r.trustedCert(embeddedCertFixture(t, "")); err == nil {
		t.Fatal("expected embeddedCert error")
	}
}

func TestDecodeResponseRawXML(t *testing.T) {
	// Leading whitespace before '<' still selects the raw-XML branch.
	b, err := decodeResponse("  <root/>")
	if err != nil || !strings.Contains(string(b), "<root/>") {
		t.Fatalf("decodeResponse raw = %q, %v", b, err)
	}
}

func TestValidatorSkipBranches(t *testing.T) {
	// A response whose assertion has no Conditions triggers the cond==nil path.
	r := rawResponse(t, `<saml:Assertion><saml:Issuer>x</saml:Issuer></saml:Assertion>`)
	if nb, na := r.conditionsTimes(); !nb.IsZero() || !na.IsZero() {
		t.Fatal("expected zero times without Conditions")
	}

	// Empty settings skip audience, destination and issuer checks.
	r.settings = &Settings{}
	r.Errors = nil
	r.validateAudience()
	r.validateDestination()
	r.validateIssuer()
	if len(r.Errors) != 0 {
		t.Fatalf("expected no errors with empty settings, got %v", r.Errors)
	}

	// ACS configured but the response carries no Destination -> skip.
	r.settings = &Settings{AssertionConsumerServiceURL: testACS}
	r.Errors = nil
	r.validateDestination()
	if len(r.Errors) != 0 {
		t.Fatalf("expected no destination error when Destination absent, got %v", r.Errors)
	}
}
