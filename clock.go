package saml

import "time"

// nowFunc is the clock seam. All time-dependent validation reads the current
// time through this variable so tests can pin a deterministic reference time
// and remain TZ-independent. It defaults to time.Now.
//
// It mirrors the role of ruby-saml relying on Time.now, but made injectable so
// the condition checks (NotBefore / NotOnOrAfter) can be exercised without any
// wall-clock or timezone dependence.
var nowFunc = time.Now
