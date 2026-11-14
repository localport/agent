package cli

import (
	"net/http"
	"testing"

	"github.com/localport/agent/internal/identity"
	"github.com/localport/agent/internal/security"
)

// A refusal is not a spent token, also behind the redaction wrapper.
func TestMayHaveSpentSeesARedactedRefusal(t *testing.T) {
	refused := security.RedactError(&identity.APIError{Status: http.StatusForbidden, Code: "SE010"}, "tok")
	if mayHaveSpent(refused) {
		t.Fatal("a 403 refusal was read as a possibly spent token")
	}
	if !mayHaveSpent(security.RedactError(&identity.APIError{Status: http.StatusBadGateway}, "tok")) {
		t.Fatal("a 502 must keep the spent-token remedy")
	}
}
