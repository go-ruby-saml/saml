package saml

import (
	"encoding/base64"
	"net/url"
	"time"

	crewjam "github.com/crewjam/saml"
)

// Logoutrequest mirrors OneLogin::RubySaml::Logoutrequest, the builder for an
// SP-initiated Single Logout request.
type Logoutrequest struct {
	// UUID holds the ID of the most recently created request.
	UUID string
}

// requestXML builds the LogoutRequest XML for the given settings and subject
// NameID.
func (l *Logoutrequest) requestXML(s *Settings, nameID string) ([]byte, error) {
	id := idFunc()
	l.UUID = id
	now := nowFunc().UTC()
	// crewjam marshals NotOnOrAfter as a pointer attribute; leaving it nil makes
	// encoding/xml panic on the value receiver, so always supply a bound.
	notOnOrAfter := now.Add(5 * time.Minute)
	req := crewjam.LogoutRequest{
		ID:           id,
		Version:      "2.0",
		IssueInstant: now,
		NotOnOrAfter: &notOnOrAfter,
		Destination:  s.IdPSLOTargetURL,
	}
	if s.SPEntityID != "" {
		req.Issuer = &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  s.SPEntityID,
		}
	}
	if nameID != "" {
		req.NameID = &crewjam.NameID{
			Format: s.NameIdentifierFormat,
			Value:  nameID,
		}
	}
	return marshalXML(req)
}

// Create mirrors OneLogin::RubySaml::Logoutrequest#create: it returns the IdP
// SLO redirect URL carrying the deflate+base64 SAMLRequest.
func (l *Logoutrequest) Create(s *Settings, nameID, relayState string) (string, error) {
	doc, err := l.requestXML(s, nameID)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(deflate(doc))
	u, err := url.Parse(s.IdPSLOTargetURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("SAMLRequest", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SloLogoutresponse mirrors OneLogin::RubySaml::SloLogoutresponse, the builder
// for the SP's response to an IdP-initiated logout request.
type SloLogoutresponse struct {
	// UUID holds the ID of the most recently created response.
	UUID string
}

// responseXML builds the LogoutResponse XML answering the given request ID.
func (l *SloLogoutresponse) responseXML(s *Settings, requestID string) ([]byte, error) {
	id := idFunc()
	l.UUID = id
	resp := crewjam.LogoutResponse{
		ID:           id,
		InResponseTo: requestID,
		Version:      "2.0",
		IssueInstant: nowFunc().UTC(),
		Destination:  s.IdPSLOTargetURL,
		Status: crewjam.Status{
			StatusCode: crewjam.StatusCode{Value: statusSuccess},
		},
	}
	if s.SPEntityID != "" {
		resp.Issuer = &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  s.SPEntityID,
		}
	}
	return marshalXML(resp)
}

// Create mirrors OneLogin::RubySaml::SloLogoutresponse#create: it returns the
// IdP SLO redirect URL carrying the deflate+base64 SAMLResponse.
func (l *SloLogoutresponse) Create(s *Settings, requestID, relayState string) (string, error) {
	doc, err := l.responseXML(s, requestID)
	if err != nil {
		return "", err
	}
	encoded := base64.StdEncoding.EncodeToString(deflate(doc))
	u, err := url.Parse(s.IdPSLOTargetURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("SAMLResponse", encoded)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
