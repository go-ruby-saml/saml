package saml

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Common SAML binding, format and algorithm identifiers, mirroring the
// constants ruby-saml exposes.
const (
	HTTPRedirectBinding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
	HTTPPostBinding     = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

	NameIDFormatEmail       = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	NameIDFormatTransient   = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
	NameIDFormatPersistent  = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
	NameIDFormatUnspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"

	SignatureMethodRSASHA1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SignatureMethodRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	DigestMethodSHA1         = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestMethodSHA256       = "http://www.w3.org/2001/04/xmlenc#sha256"

	statusSuccess = "urn:oasis:names:tc:SAML:2.0:status:Success"
)

// Settings mirrors OneLogin::RubySaml::Settings: the SP and IdP configuration
// that drives request generation and response validation.
type Settings struct {
	// IdP configuration.
	IdPEntityID                 string // idp_entity_id (expected issuer)
	IdPSSOTargetURL             string // idp_sso_target_url
	IdPSLOTargetURL             string // idp_slo_target_url
	IdPCert                     string // idp_cert (PEM)
	IdPCertFingerprint          string // idp_cert_fingerprint (hex, ':'-separated allowed)
	IdPCertFingerprintAlgorithm string // sha1 (default) or sha256

	// SP configuration.
	SPEntityID                  string // sp_entity_id / issuer
	AssertionConsumerServiceURL string // assertion_consumer_service_url
	NameIdentifierFormat        string // name_identifier_format
	Certificate                 string // certificate (PEM)
	PrivateKey                  string // private_key (PEM)

	// Security options (subset of ruby-saml's security hash).
	WantAssertionsSigned bool
	SignatureMethod      string
	DigestMethod         string

	// AllowedClockDrift is the tolerance applied to condition timestamps,
	// mirroring ruby-saml's allowed_clock_drift.
	AllowedClockDrift time.Duration

	// Audience is the expected audience URI; defaults to SPEntityID when blank.
	Audience string
}

// idpCertFingerprintAlgorithm returns the configured fingerprint hash, defaulting
// to sha1 as ruby-saml does.
func (s *Settings) idpCertFingerprintAlgorithm() string {
	if s.IdPCertFingerprintAlgorithm == "" {
		return "sha1"
	}
	return strings.ToLower(s.IdPCertFingerprintAlgorithm)
}

// audience returns the effective expected audience.
func (s *Settings) audience() string {
	if s.Audience != "" {
		return s.Audience
	}
	return s.SPEntityID
}

// parseCertificate parses a PEM-encoded X.509 certificate.
func parseCertificate(pemData string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("saml: failed to decode PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePrivateKey parses a PEM-encoded RSA private key (PKCS#1 or PKCS#8).
func parsePrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("saml: failed to decode PEM private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("saml: private key is not RSA")
	}
	return rsaKey, nil
}

// certFingerprint computes the ':'-separated uppercase hex fingerprint of a
// certificate under the named algorithm ("sha1" or "sha256"), matching the form
// ruby-saml compares against.
func certFingerprint(cert *x509.Certificate, algorithm string) (string, error) {
	var sum []byte
	switch strings.ToLower(algorithm) {
	case "sha256":
		h := sha256.Sum256(cert.Raw)
		sum = h[:]
	case "sha1", "":
		h := sha1.Sum(cert.Raw)
		sum = h[:]
	default:
		return "", fmt.Errorf("saml: unsupported fingerprint algorithm %q", algorithm)
	}
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":"), nil
}

// normalizeFingerprint upcases a fingerprint and strips ':' separators and
// whitespace so two representations of the same fingerprint compare equal.
func normalizeFingerprint(fp string) string {
	fp = strings.ToUpper(fp)
	fp = strings.ReplaceAll(fp, ":", "")
	fp = strings.ReplaceAll(fp, " ", "")
	return fp
}

// wrapPEMCertificate wraps a single-line base64 DER certificate body (as found
// in metadata) into a PEM block.
func wrapPEMCertificate(b64 string) string {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: mustBase64(b64)}
	return string(pem.EncodeToMemory(block))
}

// mustBase64 decodes a base64 string, ignoring surrounding whitespace. On a
// decode error it returns nil, yielding an empty (and therefore unparseable)
// certificate rather than panicking.
func mustBase64(s string) []byte {
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return nil
	}
	return der
}

// certToBase64DER returns the base64-encoded DER of a PEM certificate, i.e. the
// single-line body used inside <ds:X509Certificate> and SP metadata.
func certToBase64DER(pemData string) (string, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return "", errors.New("saml: failed to decode PEM certificate")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}
