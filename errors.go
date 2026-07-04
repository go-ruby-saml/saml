package saml

// ValidationError mirrors OneLogin::RubySaml::ValidationError, the exception
// ruby-saml raises when a SAML document fails a validation check. In this
// pure-Go port it is a plain error value; callers inspect Message (or use it
// via the standard error interface). It corresponds to the single message that
// aborts a fail-fast validation in the Ruby gem.
type ValidationError struct {
	Message string
}

// Error implements the error interface.
func (e *ValidationError) Error() string { return e.Message }

// newValidationError constructs a *ValidationError with the given message.
func newValidationError(msg string) *ValidationError {
	return &ValidationError{Message: msg}
}

// The canonical validation messages, mirrored from ruby-saml so downstream
// code (and the rbgo binding) can match on the same strings the Ruby gem
// produces.
const (
	errBlankResponse       = "Blank SAML Response"
	errNoSettings          = "No settings on SAML Response"
	errNoIdPCert           = "No idp_cert_fingerprint or idp_cert provided on settings"
	errStatusNotSuccess    = "The status code of the Response was not Success"
	errNumAssertion        = "SAML Response must contain 1 Assertion"
	errInvalidSignature    = "Invalid Signature on SAML Response"
	errNotBefore           = "Current time is earlier than NotBefore condition"
	errNotOnOrAfter        = "Current time is on or after NotOnOrAfter condition"
	errInvalidAudience     = "Invalid Audience. The audience did not match the requested audience"
	errInvalidDestination  = "The response was received at a destination that does not match the settings"
	errInvalidInResponseTo = "The InResponseTo of the Response does not match the ID of the AuthnRequest sent by the SP"
	errInvalidIssuer       = "Invalid issuer in the Assertion/Response"
)
