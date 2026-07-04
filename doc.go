// Package saml is a pure-Go (CGO=0), MRI-faithful port of Ruby's ruby-saml gem
// (OneLogin::RubySaml), the SAML 2.0 Service Provider toolkit.
//
// It mirrors the surface of ruby-saml while building on the pure-Go SAML
// ecosystem — github.com/crewjam/saml for the SAML schema types and
// github.com/russellhaering/goxmldsig for XML digital-signature validation —
// rather than reimplementing XML signing or the SAML schema from scratch.
//
// # Surface
//
//   - [Settings] mirrors OneLogin::RubySaml::Settings: IdP and SP configuration
//     (idp_sso_target_url, idp_cert / idp_cert_fingerprint, sp_entity_id,
//     assertion_consumer_service_url, name_identifier_format, private_key /
//     certificate) plus security options (want_assertions_signed,
//     signature_method, digest_method).
//   - [Authrequest] mirrors OneLogin::RubySaml::Authrequest: Create builds the
//     SP-initiated SSO redirect URL and the deflate+base64 SAMLRequest.
//   - [Response] mirrors OneLogin::RubySaml::Response: IsValid validates the XML
//     signature (via the IdP certificate or its fingerprint), the Conditions
//     window (NotBefore / NotOnOrAfter with clock drift), the audience, the
//     destination, the InResponseTo correlation and the issuer; NameID,
//     Attributes (multi-valued), SessionIndex, StatusCode and Issuers extract
//     the assertion contents.
//   - [Metadata] mirrors OneLogin::RubySaml::Metadata (SP metadata generation)
//     and [IdpMetadataParser] ingests IdP metadata into a [Settings].
//   - [Logoutrequest] and [SloLogoutresponse] implement SP-initiated Single
//     Logout.
//   - [ValidationError] mirrors OneLogin::RubySaml::ValidationError.
//
// All time-dependent validation reads the clock through an injectable seam so
// the Conditions checks are deterministic and timezone-independent.
package saml
