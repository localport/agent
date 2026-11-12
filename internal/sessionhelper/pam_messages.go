//go:build cgo && ((pam && linux) || darwin)

package sessionhelper

// #include <stdint.h>
import "C"

import "runtime/cgo"

// lpPamMessage is the PAM conversation's collector callback: collector is
// the cgo.Handle of the *pamMessages openPAM passed as appdata.
//
//export lpPamMessage
func lpPamMessage(collector C.uintptr_t, msg *C.char) {
	if m, ok := cgo.Handle(collector).Value().(*pamMessages); ok {
		m.add(C.GoString(msg))
	}
}
