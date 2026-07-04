package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func TestFingerprintAlgorithmDefault(t *testing.T) {
	s := &Settings{}
	if got := s.idpCertFingerprintAlgorithm(); got != "sha1" {
		t.Errorf("default algorithm = %q", got)
	}
	s.IdPCertFingerprintAlgorithm = "SHA256"
	if got := s.idpCertFingerprintAlgorithm(); got != "sha256" {
		t.Errorf("algorithm = %q", got)
	}
}

func TestAudienceOverride(t *testing.T) {
	s := &Settings{SPEntityID: "sp", Audience: "explicit"}
	if got := s.audience(); got != "explicit" {
		t.Errorf("audience = %q", got)
	}
	s.Audience = ""
	if got := s.audience(); got != "sp" {
		t.Errorf("audience fallback = %q", got)
	}
}

func TestFingerprintDefaultAlgorithmValidation(t *testing.T) {
	// A fingerprint check with an empty algorithm falls back to SHA-1.
	withFixedClock(t)
	s := baseSettings()
	s.IdPCert = ""
	s.IdPCertFingerprintAlgorithm = ""
	s.IdPCertFingerprint = idpCertFingerprint(t, "sha1")
	resp, err := NewResponse(buildResponse(t, defaultOpts()), s)
	if err != nil {
		t.Fatalf("new response: %v", err)
	}
	if !resp.IsValid() {
		t.Fatalf("default-algorithm fingerprint should validate: %v", resp.Errors)
	}
}

func TestParseCertificateError(t *testing.T) {
	if _, err := parseCertificate("garbage"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestParsePrivateKeyPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	pkcs1 := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	got, err := parsePrivateKey(string(pkcs1))
	if err != nil {
		t.Fatalf("parse pkcs1: %v", err)
	}
	if !got.PublicKey.Equal(&key.PublicKey) {
		t.Fatal("key mismatch")
	}
}

func TestParsePrivateKeyErrors(t *testing.T) {
	// Undecodable PEM.
	if _, err := parsePrivateKey("garbage"); err == nil {
		t.Fatal("expected decode error")
	}

	// Valid PKCS#8 but a non-RSA (EC) key.
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ec)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := parsePrivateKey(string(ecPEM)); err == nil {
		t.Fatal("expected non-RSA error")
	}

	// PKCS#8 body that is neither PKCS#1 nor PKCS#8.
	junk := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-a-key")})
	if _, err := parsePrivateKey(string(junk)); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestCertFingerprintUnsupported(t *testing.T) {
	cert, err := parseCertificate(idpCertPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := certFingerprint(cert, "md5"); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
}

func TestNormalizeFingerprint(t *testing.T) {
	if got := normalizeFingerprint("aa:bb cc"); got != "AABBCC" {
		t.Errorf("normalize = %q", got)
	}
}

func TestCertToBase64DERError(t *testing.T) {
	if _, err := certToBase64DER("garbage"); err == nil {
		t.Fatal("expected decode error")
	}
}

func TestMustBase64Error(t *testing.T) {
	if got := mustBase64("!!!not base64!!!"); got != nil {
		t.Errorf("expected nil on bad base64, got %v", got)
	}
}

func TestWrapPEMCertificate(t *testing.T) {
	b64, err := certToBase64DER(idpCertPEM)
	if err != nil {
		t.Fatalf("der: %v", err)
	}
	wrapped := wrapPEMCertificate(b64)
	if !strings.Contains(wrapped, "BEGIN CERTIFICATE") {
		t.Fatalf("not PEM: %q", wrapped)
	}
	if _, err := parseCertificate(wrapped); err != nil {
		t.Fatalf("re-parse: %v", err)
	}
}
