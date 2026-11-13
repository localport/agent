//go:build cgo && !pam && linux

package sessionhelper

import "fmt"

// fileLimitTestStage is limits_test.go's stage variable; a build without PAM
// keeps no start limit, so the stage only reports that.
const fileLimitTestStage = "LOCALPORT_FILE_LIMIT_STAGE"

func runFileLimitStage() int {
	fmt.Println("no PAM build")
	return 1
}
