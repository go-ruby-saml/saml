package saml

import (
	"crypto/rsa"
	_ "embed"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

//go:embed testdata/idp_cert.pem
var idpCertPEM string

//go:embed testdata/idp_key.pem
var idpKeyPEM string

//go:embed testdata/sp_cert.pem
var spCertPEM string

//go:embed testdata/sp_key.pem
var spKeyPEM string

// refNow is the fixed reference "current time" every time-dependent test pins.
// It is deterministic and expressed in UTC, so the suite is timezone-independent.
var refNow = time.Date(2024, 1, 1, 0, 30, 0, 0, time.UTC)

const (
	testIssuer   = "https://idp.example.com/metadata"
	testAudience = "https://sp.example.com/metadata"
	testACS      = "https://sp.example.com/acs"
	testNameID   = "user@example.com"
)

// withFixedClock pins nowFunc to refNow for the duration of a test.
func withFixedClock(t *testing.T) {
	t.Helper()
	prev := nowFunc
	nowFunc = func() time.Time { return refNow }
	t.Cleanup(func() { nowFunc = prev })
}

// idpKeyStore is the goxmldsig keystore that signs assertions with the embedded
// IdP key and certificate.
type idpKeyStore struct {
	key     *rsa.PrivateKey
	certDER []byte
}

func (k idpKeyStore) GetKeyPair() (*rsa.PrivateKey, []byte, error) {
	return k.key, k.certDER, nil
}

func loadIdPKeyStore(t *testing.T) idpKeyStore {
	t.Helper()
	key, err := parsePrivateKey(idpKeyPEM)
	if err != nil {
		t.Fatalf("parse idp key: %v", err)
	}
	block, _ := pem.Decode([]byte(idpCertPEM))
	if block == nil {
		t.Fatal("decode idp cert")
	}
	return idpKeyStore{key: key, certDER: block.Bytes}
}

// responseOpts parametrizes fixture generation so each invalid variant can be
// produced from the same signed template.
type responseOpts struct {
	issuer            string
	audience          string
	destination       string
	inResponseTo      string
	notBefore         time.Time
	notOnOrAfter      time.Time
	status            string
	tamper            bool // corrupt the assertion after signing
	twoAssertion      bool // emit two assertions
	signResponse      bool // additionally sign the Response element
	assertionUnsigned bool // leave the Assertion unsigned
	signWith          dsig.X509KeyStore
}

func defaultOpts() responseOpts {
	return responseOpts{
		issuer:       testIssuer,
		audience:     testAudience,
		destination:  testACS,
		inResponseTo: "_req123",
		notBefore:    refNow.Add(-30 * time.Minute),
		notOnOrAfter: refNow.Add(30 * time.Minute),
		status:       statusSuccess,
	}
}

// assertionXML renders a saml:Assertion with all namespaces declared on itself
// so its canonical form is identical whether signed standalone or validated in
// the context of the enclosing Response.
func assertionXML(o responseOpts) string {
	return fmt.Sprintf(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_assert123" Version="2.0" IssueInstant="%s">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID></saml:Subject>`+
		`<saml:Conditions NotBefore="%s" NotOnOrAfter="%s">`+
		`<saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>`+
		`</saml:Conditions>`+
		`<saml:AuthnStatement SessionIndex="_session789" AuthnInstant="%s"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`+
		`<saml:AttributeStatement>`+
		`<saml:Attribute Name="email"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>`+
		`<saml:Attribute Name="roles"><saml:AttributeValue>admin</saml:AttributeValue><saml:AttributeValue>user</saml:AttributeValue></saml:Attribute>`+
		`</saml:AttributeStatement>`+
		`</saml:Assertion>`,
		refNow.Format(time.RFC3339), o.issuer, testNameID,
		o.notBefore.Format(time.RFC3339), o.notOnOrAfter.Format(time.RFC3339),
		o.audience, refNow.Format(time.RFC3339), testNameID)
}

// buildResponse renders and (unless building an unsigned variant) signs a SAML
// Response according to opts, returning the base64-encoded document.
func buildResponse(t *testing.T, o responseOpts) string {
	t.Helper()
	ks := o.signWith
	if ks == nil {
		ks = loadIdPKeyStore(t)
	}
	signer := dsig.NewDefaultSigningContext(ks)

	// Build and (optionally) sign the assertion.
	adoc := etree.NewDocument()
	if err := adoc.ReadFromString(assertionXML(o)); err != nil {
		t.Fatalf("parse assertion: %v", err)
	}
	signedAssertion := adoc.Root()
	if !o.assertionUnsigned {
		var err error
		signedAssertion, err = signer.SignEnveloped(adoc.Root())
		if err != nil {
			t.Fatalf("sign assertion: %v", err)
		}
	}
	if o.tamper {
		// Flip the NameID after signing so the digest no longer matches.
		if nid := signedAssertion.FindElement("./Subject/NameID"); nid != nil {
			nid.SetText("attacker@evil.example.com")
		}
	}

	assertionDoc := etree.NewDocument()
	assertionDoc.SetRoot(signedAssertion.Copy())
	assertionStr, err := assertionDoc.WriteToString()
	if err != nil {
		t.Fatalf("serialize assertion: %v", err)
	}

	assertions := assertionStr
	if o.twoAssertion {
		assertions += assertionStr
	}

	respXML := fmt.Sprintf(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp456" Version="2.0" IssueInstant="%s" Destination="%s" InResponseTo="%s">`+
		`<saml:Issuer>%s</saml:Issuer>`+
		`<samlp:Status><samlp:StatusCode Value="%s"/></samlp:Status>`+
		`%s</samlp:Response>`,
		refNow.Format(time.RFC3339), o.destination, o.inResponseTo, o.issuer, o.status, assertions)

	if o.signResponse {
		rdoc := etree.NewDocument()
		if err := rdoc.ReadFromString(respXML); err != nil {
			t.Fatalf("parse response: %v", err)
		}
		signedResp, err := signer.SignEnveloped(rdoc.Root())
		if err != nil {
			t.Fatalf("sign response: %v", err)
		}
		out := etree.NewDocument()
		out.SetRoot(signedResp)
		respXML, err = out.WriteToString()
		if err != nil {
			t.Fatalf("serialize response: %v", err)
		}
	}

	return base64.StdEncoding.EncodeToString([]byte(respXML))
}

// idpCertFingerprint returns the SHA-256 fingerprint of the embedded IdP cert.
func idpCertFingerprint(t *testing.T, algorithm string) string {
	t.Helper()
	cert, err := parseCertificate(idpCertPEM)
	if err != nil {
		t.Fatalf("parse idp cert: %v", err)
	}
	fp, err := certFingerprint(cert, algorithm)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return fp
}

// baseSettings returns Settings wired to trust the embedded IdP certificate.
func baseSettings() *Settings {
	return &Settings{
		IdPEntityID:                 testIssuer,
		IdPSSOTargetURL:             "https://idp.example.com/sso",
		IdPSLOTargetURL:             "https://idp.example.com/slo",
		IdPCert:                     idpCertPEM,
		SPEntityID:                  testAudience,
		AssertionConsumerServiceURL: testACS,
		NameIdentifierFormat:        NameIDFormatEmail,
		Certificate:                 spCertPEM,
		PrivateKey:                  spKeyPEM,
		WantAssertionsSigned:        true,
	}
}

// signerFromPEM builds a goxmldsig keystore from arbitrary PEM key+cert (used to
// forge a signature with an untrusted key).
func signerFromPEM(t *testing.T, keyPEM, certPEM string) dsig.X509KeyStore {
	t.Helper()
	key, err := parsePrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("decode cert")
	}
	return idpKeyStore{key: key, certDER: block.Bytes}
}
