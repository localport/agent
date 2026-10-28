package cli

import (
	"github.com/localport/agent/internal/identity"
)

func deviceRef(id string) identity.Ref {
	return identity.Ref{Team: "01kpq7x2abcd34", Kind: identity.KindDevice, Identity: id}
}
