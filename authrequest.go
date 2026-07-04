package saml

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"net/url"

	crewjam "github.com/crewjam/saml"
)

// randReader is the entropy source for identifier generation, injectable so the
// error path of defaultID can be exercised deterministically.
var randReader io.Reader = rand.Reader

// marshalXML is the XML marshaller seam, injectable so the marshal-error paths
// of request/response builders can be exercised.
var marshalXML = xml.Marshal

// defaultID mints a random request identifier. It mirrors ruby-saml's UUID
// generation. The returned value is used verbatim as the SAML message ID and
// must be an NCName (hence the leading underscore).
func defaultID() string {
	var b [16]byte
	if _, err := io.ReadFull(randReader, b[:]); err != nil {
		panic(err) // entropy exhaustion is fatal; injectable for coverage.
	}
	return fmt.Sprintf("_%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// idFunc is the identifier seam; tests may override it for determinism.
var idFunc = defaultID

// Authrequest mirrors OneLogin::RubySaml::Authrequest, the builder for an
// SP-initiated SSO AuthnRequest.
type Authrequest struct {
	// UUID holds the ID of the most recently created request, matching the
	// ruby-saml attribute of the same name (used to correlate InResponseTo).
	UUID string
}

// requestXML builds the AuthnRequest XML document for the given settings using
// the crewjam/saml schema types.
func (a *Authrequest) requestXML(s *Settings) ([]byte, error) {
	id := idFunc()
	a.UUID = id

	req := crewjam.AuthnRequest{
		ID:                          id,
		Version:                     "2.0",
		IssueInstant:                nowFunc().UTC(),
		Destination:                 s.IdPSSOTargetURL,
		AssertionConsumerServiceURL: s.AssertionConsumerServiceURL,
		ProtocolBinding:             HTTPPostBinding,
	}
	if s.SPEntityID != "" {
		req.Issuer = &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  s.SPEntityID,
		}
	}
	if s.NameIdentifierFormat != "" {
		allow := true
		format := s.NameIdentifierFormat
		req.NameIDPolicy = &crewjam.NameIDPolicy{
			Format:      &format,
			AllowCreate: &allow,
		}
	}
	return marshalXML(req)
}

// deflate compresses data with raw DEFLATE, the encoding the HTTP-Redirect
// binding uses before base64. Writing to an in-memory buffer with a constant,
// valid compression level cannot fail, so no error is returned.
func deflate(data []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

// SAMLRequest returns the deflate+base64 encoded AuthnRequest, the value placed
// in the SAMLRequest query parameter of the HTTP-Redirect binding.
func (a *Authrequest) SAMLRequest(s *Settings) (string, error) {
	doc, err := a.requestXML(s)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(deflate(doc)), nil
}

// Create mirrors OneLogin::RubySaml::Authrequest#create: it returns the full
// IdP redirect URL carrying the SAMLRequest (and RelayState, when non-empty).
func (a *Authrequest) Create(s *Settings, relayState string) (string, error) {
	samlRequest, err := a.SAMLRequest(s)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(s.IdPSSOTargetURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("SAMLRequest", samlRequest)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// DecodeSAMLRequest reverses SAMLRequest (base64 + inflate), returning the
// AuthnRequest XML. It is exposed so callers (and tests) can verify the encoded
// payload round-trips to well-formed XML.
func DecodeSAMLRequest(encoded string) ([]byte, error) {
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
