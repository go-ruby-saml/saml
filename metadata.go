package saml

import (
	"encoding/xml"

	crewjam "github.com/crewjam/saml"
)

// marshalIndentXML and unmarshalXML are seams over the encoding/xml functions so
// the marshal/unmarshal error paths can be exercised in tests.
var (
	marshalIndentXML = xml.MarshalIndent
	unmarshalXML     = xml.Unmarshal
)

// Metadata mirrors OneLogin::RubySaml::Metadata, the generator for SP metadata.
type Metadata struct{}

// Generate returns the SP EntityDescriptor XML for the given settings, matching
// the document ruby-saml's Metadata#generate produces (SPSSODescriptor with the
// Assertion Consumer Service, NameIDFormat and, when configured, a signing key
// and WantAssertionsSigned).
func (Metadata) Generate(s *Settings) ([]byte, error) {
	spd := crewjam.SPSSODescriptor{
		AssertionConsumerServices: []crewjam.IndexedEndpoint{
			{
				Binding:  HTTPPostBinding,
				Location: s.AssertionConsumerServiceURL,
				Index:    0,
			},
		},
	}
	spd.ProtocolSupportEnumeration = "urn:oasis:names:tc:SAML:2.0:protocol"
	if s.NameIdentifierFormat != "" {
		spd.NameIDFormats = []crewjam.NameIDFormat{crewjam.NameIDFormat(s.NameIdentifierFormat)}
	}
	if s.WantAssertionsSigned {
		want := true
		spd.WantAssertionsSigned = &want
	}
	if s.Certificate != "" {
		b64, err := certToBase64DER(s.Certificate)
		if err != nil {
			return nil, err
		}
		spd.KeyDescriptors = []crewjam.KeyDescriptor{{
			Use: "signing",
			KeyInfo: crewjam.KeyInfo{
				X509Data: crewjam.X509Data{
					X509Certificates: []crewjam.X509Certificate{{Data: b64}},
				},
			},
		}}
	}

	ed := crewjam.EntityDescriptor{
		EntityID:         s.SPEntityID,
		SPSSODescriptors: []crewjam.SPSSODescriptor{spd},
	}
	out, err := marshalIndentXML(ed, "", "  ")
	if err != nil {
		return nil, err // unreachable: the descriptor always marshals.
	}
	return append([]byte(xml.Header), out...), nil
}

// IdpMetadataParser mirrors OneLogin::RubySaml::IdpMetadataParser: it ingests an
// IdP EntityDescriptor and populates the IdP-facing fields of a Settings.
type IdpMetadataParser struct{}

// Parse reads IdP metadata XML and returns a Settings with idp_entity_id,
// idp_sso_target_url, idp_slo_target_url and idp_cert filled in from the first
// IDPSSODescriptor.
func (IdpMetadataParser) Parse(metadataXML []byte) (*Settings, error) {
	var ed crewjam.EntityDescriptor
	if err := unmarshalXML(metadataXML, &ed); err != nil {
		return nil, err
	}
	s := &Settings{IdPEntityID: ed.EntityID}
	if len(ed.IDPSSODescriptors) == 0 {
		return s, nil
	}
	idp := ed.IDPSSODescriptors[0]
	for _, sso := range idp.SingleSignOnServices {
		if sso.Binding == HTTPRedirectBinding || s.IdPSSOTargetURL == "" {
			s.IdPSSOTargetURL = sso.Location
		}
	}
	for _, slo := range idp.SingleLogoutServices {
		if slo.Binding == HTTPRedirectBinding || s.IdPSLOTargetURL == "" {
			s.IdPSLOTargetURL = slo.Location
		}
	}
	if cert := firstSigningCert(idp); cert != "" {
		s.IdPCert = wrapPEMCertificate(cert)
	}
	return s, nil
}

// firstSigningCert returns the base64 DER of the first usable signing key in an
// IDPSSODescriptor (preferring keys marked use="signing").
func firstSigningCert(idp crewjam.IDPSSODescriptor) string {
	var fallback string
	for _, kd := range idp.KeyDescriptors {
		if len(kd.KeyInfo.X509Data.X509Certificates) == 0 {
			continue
		}
		data := kd.KeyInfo.X509Data.X509Certificates[0].Data
		if kd.Use == "signing" {
			return data
		}
		if fallback == "" {
			fallback = data
		}
	}
	return fallback
}
