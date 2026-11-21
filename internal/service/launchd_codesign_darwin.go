package service

import (
	"context"
	"fmt"
)

// releaseCertSHA1 is the SHA-1 fingerprint of the Localport release signing
// certificate, set by release builds (-ldflags -X). Empty in local and CI
// builds, whose bundles are ad-hoc signed and checked by identifier only.
var releaseCertSHA1 string

// codesignVerify checks bundle's signature, strictly, against appRequirement.
func codesignVerify(ctx context.Context, bundle string) error {
	req, err := appRequirement(releaseCertSHA1)
	if err != nil {
		return err
	}
	if _, err := execRun(ctx, codesignPath, "--verify", "--strict", "-R="+req, bundle); err != nil {
		return errAppInvalid.With(err, fmt.Sprintf("%s is not signed by Localport", bundle))
	}
	return nil
}
