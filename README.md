<p align="center"><img src="https://raw.githubusercontent.com/go-ruby-saml/brand/main/social/go-ruby-saml-saml.png" alt="go-ruby-saml/saml" width="720"></p>

# saml — go-ruby-saml

[![ci](https://github.com/go-ruby-saml/saml/actions/workflows/ci.yml/badge.svg)](https://github.com/go-ruby-saml/saml/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-mkdocs--material-DC2626)](https://go-ruby-saml.github.io/docs/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26.4%2B-00ADD8)](https://go.dev/dl/)
[![coverage](https://img.shields.io/badge/coverage-100%25-1a7f37)](#testing)

**A pure-Go (no cgo), MRI-faithful port of Ruby's [`ruby-saml`](https://github.com/SAML-Toolkits/ruby-saml) gem** —
the SAML 2.0 Service Provider toolkit exposed as `OneLogin::RubySaml`.

It mirrors the ruby-saml surface while standing on the pure-Go SAML ecosystem —
[`github.com/crewjam/saml`](https://github.com/crewjam/saml) for the SAML schema
types and [`github.com/russellhaering/goxmldsig`](https://github.com/russellhaering/goxmldsig)
for XML digital-signature validation — rather than reimplementing XML signing or
the SAML schema from scratch. It is the SAML backend for
[go-embedded-ruby](https://github.com/go-embedded-ruby/ruby) but is a
**standalone, reusable** module with no dependency on the Ruby runtime.

## Ruby-faithful surface

| ruby-saml (`OneLogin::RubySaml`) | this module |
| --- | --- |
| `Settings` | [`Settings`](settings.go) — `idp_sso_target_url`, `idp_cert` / `idp_cert_fingerprint`, `sp_entity_id`, `assertion_consumer_service_url`, `name_identifier_format`, `private_key` / `certificate`, `want_assertions_signed`, `signature_method`, `digest_method` |
| `Authrequest#create` | [`Authrequest.Create`](authrequest.go) — SP-initiated SSO redirect URL + deflate+base64 `SAMLRequest` |
| `Response#is_valid?`, `#name_id`, `#attributes`, `#sessionindex`, `#status_code`, `#issuers` | [`Response`](response.go) |
| `Metadata#generate` | [`Metadata.Generate`](metadata.go) — SP metadata XML |
| `IdpMetadataParser#parse` | [`IdpMetadataParser.Parse`](metadata.go) |
| `Logoutrequest#create`, `SloLogoutresponse#create` | [`Logoutrequest`](logout.go), [`SloLogoutresponse`](logout.go) — SP-initiated SLO |
| `ValidationError` | [`ValidationError`](errors.go) |

## Response validation

`Response.IsValid` mirrors ruby-saml's `is_valid?`, collecting each failure into
`Errors`:

- **Signature** — verified against the configured `idp_cert` *or* its
  `idp_cert_fingerprint` (SHA-1 / SHA-256), via goxmldsig.
- **Conditions** — `NotBefore` / `NotOnOrAfter` with `allowed_clock_drift`.
- **Audience** — `AudienceRestriction` matches `sp_entity_id`.
- **Destination** — matches `assertion_consumer_service_url`.
- **InResponseTo** — matches the originating `AuthnRequest` ID.
- **Issuer** — matches `idp_entity_id`.
- **Status / Assertion count** — `Success`, exactly one assertion.

All time-dependent checks read an injectable clock, so validation is
deterministic and **timezone-independent** (the suite runs under `TZ=UTC`).

## Example

```go
settings := &saml.Settings{
    IdPSSOTargetURL:             "https://idp.example.com/sso",
    IdPCert:                     idpCertPEM,
    SPEntityID:                  "https://sp.example.com/metadata",
    AssertionConsumerServiceURL: "https://sp.example.com/acs",
    NameIdentifierFormat:        saml.NameIDFormatEmail,
}

// SP-initiated SSO.
authn := &saml.Authrequest{}
redirect, _ := authn.Create(settings, "" /* relayState */)

// Consume the IdP response.
resp, _ := saml.NewResponse(base64SAMLResponse, settings)
resp.ExpectedInResponseTo = authn.UUID
if resp.IsValid() {
    fmt.Println(resp.NameID(), resp.Attributes())
}
```

## Testing

Every fixture — RSA keys, X.509 certificates, and signed SAML documents (valid,
tampered, expired, wrong-audience, wrong-destination, wrong-issuer,
wrong-`InResponseTo`) — is embedded; no network is used. The suite runs with
`-race` and enforces **100% statement coverage** across **three OSes** and the
**six supported 64-bit architectures** (amd64, arm64, riscv64, loong64, ppc64le,
and big-endian **s390x**).

```sh
GOWORK=off TZ=UTC go test -race -cover ./...
```

## License

BSD-3-Clause — see [LICENSE](LICENSE). Copyright (c) 2026, the go-ruby-saml/saml authors.
