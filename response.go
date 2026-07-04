package saml

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// Response mirrors OneLogin::RubySaml::Response, the parsed and validatable
// SAML 2.0 authentication response received at the SP Assertion Consumer
// Service.
type Response struct {
	settings *Settings
	doc      *etree.Document

	// ExpectedInResponseTo, when set, is compared against the response's
	// InResponseTo attribute during validation (mirrors ruby-saml's
	// matches_request_id option).
	ExpectedInResponseTo string

	// Errors accumulates the validation failures found by IsValid, mirroring
	// ruby-saml's @errors array.
	Errors []string
}

// NewResponse parses a SAML Response. The input is either the base64-encoded
// response as delivered on the HTTP-POST binding, or the raw XML document.
func NewResponse(input string, settings *Settings) (*Response, error) {
	raw, err := decodeResponse(input)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, err
	}
	return &Response{settings: settings, doc: doc}, nil
}

// decodeResponse returns the response XML bytes, accepting either raw XML (when
// it begins with '<') or a base64-encoded payload.
func decodeResponse(input string) ([]byte, error) {
	trimmed := strings.TrimSpace(input)
	if strings.HasPrefix(trimmed, "<") {
		return []byte(trimmed), nil
	}
	return base64.StdEncoding.DecodeString(trimmed)
}

// root returns the document root element (the samlp:Response).
func (r *Response) root() *etree.Element { return r.doc.Root() }

// assertion returns the single saml:Assertion element, or nil.
func (r *Response) assertion() *etree.Element {
	root := r.root()
	if root == nil {
		return nil
	}
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" {
			return child
		}
	}
	return nil
}

// assertions returns every saml:Assertion child of the response.
func (r *Response) assertions() []*etree.Element {
	root := r.root()
	if root == nil {
		return nil
	}
	var out []*etree.Element
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" {
			out = append(out, child)
		}
	}
	return out
}

// NameID returns the value of the assertion's Subject/NameID.
func (r *Response) NameID() string {
	a := r.assertion()
	if a == nil {
		return ""
	}
	if subject := a.FindElement("./Subject/NameID"); subject != nil {
		return strings.TrimSpace(subject.Text())
	}
	return ""
}

// Attributes returns the assertion's attributes as a multi-valued map, mirroring
// ruby-saml's OneLogin::RubySaml::Attributes (each key maps to all its values).
func (r *Response) Attributes() map[string][]string {
	out := map[string][]string{}
	a := r.assertion()
	if a == nil {
		return out
	}
	for _, attr := range a.FindElements("./AttributeStatement/Attribute") {
		name := attr.SelectAttrValue("Name", "")
		if name == "" {
			continue
		}
		for _, v := range attr.FindElements("./AttributeValue") {
			out[name] = append(out[name], strings.TrimSpace(v.Text()))
		}
	}
	return out
}

// SessionIndex returns the AuthnStatement SessionIndex, if present.
func (r *Response) SessionIndex() string {
	a := r.assertion()
	if a == nil {
		return ""
	}
	if s := a.FindElement("./AuthnStatement"); s != nil {
		return s.SelectAttrValue("SessionIndex", "")
	}
	return ""
}

// StatusCode returns the top-level samlp:Status/StatusCode Value.
func (r *Response) StatusCode() string {
	root := r.root()
	if root == nil {
		return ""
	}
	if sc := root.FindElement("./Status/StatusCode"); sc != nil {
		return sc.SelectAttrValue("Value", "")
	}
	return ""
}

// Issuers returns the unique issuer values from the Response and its Assertion.
func (r *Response) Issuers() []string {
	seen := map[string]bool{}
	var out []string
	add := func(el *etree.Element) {
		if el == nil {
			return
		}
		if iss := el.FindElement("./Issuer"); iss != nil {
			v := strings.TrimSpace(iss.Text())
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	add(r.root())
	add(r.assertion())
	return out
}

// Destination returns the Response Destination attribute.
func (r *Response) Destination() string {
	if root := r.root(); root != nil {
		return root.SelectAttrValue("Destination", "")
	}
	return ""
}

// InResponseTo returns the Response InResponseTo attribute.
func (r *Response) InResponseTo() string {
	if root := r.root(); root != nil {
		return root.SelectAttrValue("InResponseTo", "")
	}
	return ""
}

// audiences returns the assertion's AudienceRestriction audiences.
func (r *Response) audiences() []string {
	a := r.assertion()
	if a == nil {
		return nil
	}
	var out []string
	for _, aud := range a.FindElements("./Conditions/AudienceRestriction/Audience") {
		out = append(out, strings.TrimSpace(aud.Text()))
	}
	return out
}

// conditionsTimes returns the NotBefore and NotOnOrAfter of the assertion's
// Conditions element. A zero time indicates the bound was absent.
func (r *Response) conditionsTimes() (notBefore, notOnOrAfter time.Time) {
	a := r.assertion()
	if a == nil {
		return
	}
	cond := a.FindElement("./Conditions")
	if cond == nil {
		return
	}
	if v := cond.SelectAttrValue("NotBefore", ""); v != "" {
		notBefore, _ = time.Parse(time.RFC3339, v)
	}
	if v := cond.SelectAttrValue("NotOnOrAfter", ""); v != "" {
		notOnOrAfter, _ = time.Parse(time.RFC3339, v)
	}
	return
}

// IsValid mirrors OneLogin::RubySaml::Response#is_valid?. It runs every
// validation, appends each failure to Errors, and reports whether the response
// is valid. It never depends on the local timezone: all comparisons use UTC
// instants read through the injectable clock.
func (r *Response) IsValid() bool {
	r.Errors = nil
	now := nowFunc().UTC()

	if r.root() == nil {
		r.Errors = append(r.Errors, errBlankResponse)
		return false
	}
	if r.settings == nil {
		r.Errors = append(r.Errors, errNoSettings)
		return false
	}
	if r.settings.IdPCert == "" && r.settings.IdPCertFingerprint == "" {
		r.Errors = append(r.Errors, errNoIdPCert)
		return false
	}

	if r.StatusCode() != statusSuccess {
		r.Errors = append(r.Errors, errStatusNotSuccess)
	}
	if len(r.assertions()) != 1 {
		r.Errors = append(r.Errors, errNumAssertion)
		// Without exactly one assertion the remaining checks are meaningless.
		return len(r.Errors) == 0
	}

	if err := r.validateSignature(); err != nil {
		r.Errors = append(r.Errors, err.Error())
	}
	r.validateConditions(now)
	r.validateAudience()
	r.validateDestination()
	r.validateInResponseTo()
	r.validateIssuer()

	return len(r.Errors) == 0
}

// Validate is the fail-fast counterpart of IsValid: it returns the first
// validation error as a *ValidationError, or nil when the response is valid.
func (r *Response) Validate() error {
	if r.IsValid() {
		return nil
	}
	return newValidationError(r.Errors[0])
}

// validateConditions checks the NotBefore / NotOnOrAfter bounds with the
// configured clock drift tolerance.
func (r *Response) validateConditions(now time.Time) {
	notBefore, notOnOrAfter := r.conditionsTimes()
	drift := r.settings.AllowedClockDrift
	if !notBefore.IsZero() && now.Add(drift).Before(notBefore) {
		r.Errors = append(r.Errors, errNotBefore)
	}
	if !notOnOrAfter.IsZero() && !now.Add(-drift).Before(notOnOrAfter) {
		r.Errors = append(r.Errors, errNotOnOrAfter)
	}
}

// validateAudience checks the assertion audience matches the configured one.
func (r *Response) validateAudience() {
	expected := r.settings.audience()
	if expected == "" {
		return
	}
	for _, a := range r.audiences() {
		if a == expected {
			return
		}
	}
	r.Errors = append(r.Errors, errInvalidAudience)
}

// validateDestination checks the Response Destination matches the SP ACS URL.
func (r *Response) validateDestination() {
	acs := r.settings.AssertionConsumerServiceURL
	if acs == "" {
		return
	}
	dest := r.Destination()
	if dest == "" {
		return
	}
	if dest != acs {
		r.Errors = append(r.Errors, errInvalidDestination)
	}
}

// validateInResponseTo checks the Response InResponseTo matches the expected
// AuthnRequest ID, when one was supplied.
func (r *Response) validateInResponseTo() {
	if r.ExpectedInResponseTo == "" {
		return
	}
	if r.InResponseTo() != r.ExpectedInResponseTo {
		r.Errors = append(r.Errors, errInvalidInResponseTo)
	}
}

// validateIssuer checks the issuers match the configured IdP entity ID.
func (r *Response) validateIssuer() {
	expected := r.settings.IdPEntityID
	if expected == "" {
		return
	}
	for _, iss := range r.Issuers() {
		if iss != expected {
			r.Errors = append(r.Errors, errInvalidIssuer)
			return
		}
	}
}

// validateSignature verifies the enveloped XML signature on the signed element
// (Assertion preferred, else Response) using either the configured IdP
// certificate or the configured certificate fingerprint.
func (r *Response) validateSignature() error {
	signed := r.signedElement()
	if signed == nil {
		return newValidationError(errInvalidSignature)
	}

	cert, err := r.trustedCert(signed)
	if err != nil {
		return newValidationError(errInvalidSignature)
	}

	ctx := &dsig.ValidationContext{
		CertificateStore: &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
		IdAttribute:      "ID",
		Clock:            dsig.NewFakeClockAt(nowFunc().UTC()),
	}
	if _, err := ctx.Validate(signed); err != nil {
		return newValidationError(errInvalidSignature)
	}
	return nil
}

// signedElement returns a copy of the element that carries the enveloped
// ds:Signature — the Assertion if it is signed, otherwise the Response.
func (r *Response) signedElement() *etree.Element {
	if a := r.assertion(); a != nil && hasSignatureChild(a) {
		return a.Copy()
	}
	if root := r.root(); root != nil && hasSignatureChild(root) {
		return root.Copy()
	}
	return nil
}

// hasSignatureChild reports whether el has a direct ds:Signature child.
func hasSignatureChild(el *etree.Element) bool {
	for _, c := range el.ChildElements() {
		if c.Tag == "Signature" {
			return true
		}
	}
	return false
}

// trustedCert selects the certificate to validate the signature against. With
// idp_cert configured it parses that certificate; otherwise it extracts the
// certificate embedded in the signature and checks its fingerprint against the
// configured idp_cert_fingerprint.
func (r *Response) trustedCert(signed *etree.Element) (*x509.Certificate, error) {
	if r.settings.IdPCert != "" {
		return parseCertificate(r.settings.IdPCert)
	}
	cert, err := embeddedCert(signed)
	if err != nil {
		return nil, err
	}
	fp, err := certFingerprint(cert, r.settings.idpCertFingerprintAlgorithm())
	if err != nil {
		return nil, err
	}
	if normalizeFingerprint(fp) != normalizeFingerprint(r.settings.IdPCertFingerprint) {
		return nil, newValidationError(errInvalidSignature)
	}
	return cert, nil
}

// embeddedCert extracts the X.509 certificate carried in the signature's
// KeyInfo/X509Data/X509Certificate element.
func embeddedCert(signed *etree.Element) (*x509.Certificate, error) {
	el := signed.FindElement("./Signature/KeyInfo/X509Data/X509Certificate")
	if el == nil {
		return nil, newValidationError(errInvalidSignature)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(el.Text()), ""))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}
