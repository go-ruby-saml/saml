package saml

import (
	"net/url"
	"strings"
	"testing"
)

func TestLogoutrequestCreate(t *testing.T) {
	withFixedClock(t)
	withFixedID(t, "_logout123")
	l := &Logoutrequest{}
	u, err := l.Create(settingsForRequest(), testNameID, "state1")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if l.UUID != "_logout123" {
		t.Errorf("UUID = %q", l.UUID)
	}
	parsed, err := url.Parse(u)
	if err != nil {
		t.Fatalf("bad url: %v", err)
	}
	q := parsed.Query()
	if q.Get("SAMLRequest") == "" || q.Get("RelayState") != "state1" {
		t.Errorf("query = %v", q)
	}
	doc, err := DecodeSAMLRequest(q.Get("SAMLRequest"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{"LogoutRequest", testNameID, testAudience} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("logout request missing %q in %s", want, doc)
		}
	}
}

func TestLogoutrequestMinimal(t *testing.T) {
	withFixedClock(t)
	// Empty NameID and SPEntityID exercise the omitted branches; empty
	// RelayState omits that param.
	s := &Settings{IdPSLOTargetURL: "https://idp.example.com/slo"}
	l := &Logoutrequest{}
	u, err := l.Create(s, "", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.Contains(u, "RelayState") {
		t.Errorf("unexpected RelayState")
	}
	doc, err := DecodeSAMLRequest(mustQuery(t, u, "SAMLRequest"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(string(doc), "Issuer") || strings.Contains(string(doc), "NameID") {
		t.Errorf("unexpected optional elements: %s", doc)
	}
}

func TestLogoutrequestMarshalError(t *testing.T) {
	withMarshalError(t)
	l := &Logoutrequest{}
	if _, err := l.Create(settingsForRequest(), testNameID, ""); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestLogoutrequestBadURL(t *testing.T) {
	withFixedClock(t)
	s := settingsForRequest()
	s.IdPSLOTargetURL = "http://a\x7f.example"
	l := &Logoutrequest{}
	if _, err := l.Create(s, testNameID, ""); err == nil {
		t.Fatal("expected url error")
	}
}

func TestSloLogoutresponseCreate(t *testing.T) {
	withFixedClock(t)
	withFixedID(t, "_sloresp123")
	l := &SloLogoutresponse{}
	u, err := l.Create(settingsForRequest(), "_origreq", "state2")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if l.UUID != "_sloresp123" {
		t.Errorf("UUID = %q", l.UUID)
	}
	q := mustQueryValues(t, u)
	if q.Get("SAMLResponse") == "" || q.Get("RelayState") != "state2" {
		t.Errorf("query = %v", q)
	}
	doc, err := DecodeSAMLRequest(q.Get("SAMLResponse"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, want := range []string{"LogoutResponse", "_origreq", statusSuccess} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("logout response missing %q in %s", want, doc)
		}
	}
}

func TestSloLogoutresponseMinimal(t *testing.T) {
	withFixedClock(t)
	s := &Settings{IdPSLOTargetURL: "https://idp.example.com/slo"}
	l := &SloLogoutresponse{}
	u, err := l.Create(s, "_origreq", "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if strings.Contains(u, "RelayState") {
		t.Errorf("unexpected RelayState")
	}
	doc, err := DecodeSAMLRequest(mustQuery(t, u, "SAMLResponse"))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(string(doc), "Issuer") {
		t.Errorf("unexpected Issuer: %s", doc)
	}
}

func TestSloLogoutresponseMarshalError(t *testing.T) {
	withMarshalError(t)
	l := &SloLogoutresponse{}
	if _, err := l.Create(settingsForRequest(), "_origreq", ""); err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestSloLogoutresponseBadURL(t *testing.T) {
	withFixedClock(t)
	s := settingsForRequest()
	s.IdPSLOTargetURL = "http://a\x7f.example"
	l := &SloLogoutresponse{}
	if _, err := l.Create(s, "_origreq", ""); err == nil {
		t.Fatal("expected url error")
	}
}

func mustQueryValues(t *testing.T, rawURL string) url.Values {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return u.Query()
}

func mustQuery(t *testing.T, rawURL, key string) string {
	t.Helper()
	return mustQueryValues(t, rawURL).Get(key)
}
