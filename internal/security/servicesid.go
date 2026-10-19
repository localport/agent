package security

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"
)

// WindowsServiceName is the name of the Windows device service. Its virtual
// account NT SERVICE\localport-device may own and reach the files under the
// machine-wide device config directory, beside SYSTEM and Administrators.
const WindowsServiceName = "localport-device"

// DeviceDirName is the name of the machine-wide device config directory on
// every OS: /etc/localport-device, /Library/Application Support/localport-device
// and %ProgramData%\localport-device. It differs from the tunnel units'
// directories (/etc/localport and /Library/Application Support/localport) on
// case-insensitive file systems too.
const DeviceDirName = "localport-device"

// ServiceSID returns the SID Windows gives the virtual account NT
// SERVICE\<name>: S-1-5-80 followed by the SHA-1 of the upper-case name in
// UTF-16LE, read as five little-endian 32-bit sub-authorities. It is fixed by
// the name, so files can grant it before the service exists.
func ServiceSID(name string) string {
	units := utf16.Encode([]rune(strings.ToUpper(name)))
	encoded := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(encoded[2*i:], u)
	}
	sum := sha1.Sum(encoded)
	var sid strings.Builder
	sid.WriteString("S-1-5-80")
	for i := 0; i < len(sum); i += 4 {
		fmt.Fprintf(&sid, "-%d", binary.LittleEndian.Uint32(sum[i:]))
	}
	return sid.String()
}
