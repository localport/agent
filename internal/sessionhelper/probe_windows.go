//go:build windows

package sessionhelper

import (
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/localport/agent/internal/launcher"
)

// PAMAvailable is false: Windows sessions log on through LSA.
func PAMAvailable() bool { return false }

var procDsGetDcNameW = windows.NewLazySystemDLL("netapi32.dll").NewProc("DsGetDcNameW")

const (
	// netSetupDomainName is NETSETUP_JOIN_STATUS NetSetupDomainName.
	netSetupDomainName = 3
	// dsForceRediscovery is DsGetDcName's DS_FORCE_REDISCOVERY.
	dsForceRediscovery = 0x1
)

// S4UAvailability reports which logins S4U can serve now: local accounts
// only on a machine outside a domain, domain accounts too when a domain
// controller answers, and launcher.S4UDomainUnreachable when the machine is
// joined but none does (domain logins then fail).
func S4UAvailability() string {
	var name *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &name, &status); err != nil {
		return launcher.S4UUnknown
	}
	windows.NetApiBufferFree((*byte)(unsafe.Pointer(name)))
	if status != netSetupDomainName {
		return launcher.S4ULocal
	}
	// Forced rediscovery: a cached answer would report a controller that
	// went away. The launcher calls this in the background only.
	var info *byte
	r, _, _ := procDsGetDcNameW.Call(0, 0, 0, 0, dsForceRediscovery, uintptr(unsafe.Pointer(&info)))
	switch windows.Errno(r) {
	case 0:
	case windows.ERROR_NO_SUCH_DOMAIN:
		return launcher.S4UDomainUnreachable
	default:
		return launcher.S4UUnknown
	}
	windows.NetApiBufferFree(info)
	return launcher.S4UDomain
}
