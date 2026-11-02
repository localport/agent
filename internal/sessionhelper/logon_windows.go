//go:build windows

package sessionhelper

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Bindings x/sys/windows does not carry.
var (
	modsecur32  = windows.NewLazySystemDLL("secur32.dll")
	modadvapi32 = windows.NewLazySystemDLL("advapi32.dll")
	moduserenv  = windows.NewLazySystemDLL("userenv.dll")

	procLsaRegisterLogonProcess        = modsecur32.NewProc("LsaRegisterLogonProcess")
	procLsaLookupAuthenticationPackage = modsecur32.NewProc("LsaLookupAuthenticationPackage")
	procLsaLogonUser                   = modsecur32.NewProc("LsaLogonUser")
	procLsaFreeReturnBuffer            = modsecur32.NewProc("LsaFreeReturnBuffer")
	procLsaDeregisterLogonProcess      = modsecur32.NewProc("LsaDeregisterLogonProcess")
	procTranslateNameW                 = modsecur32.NewProc("TranslateNameW")
	procLsaNtStatusToWinError          = modadvapi32.NewProc("LsaNtStatusToWinError")
	procAllocateLocallyUniqueId        = modadvapi32.NewProc("AllocateLocallyUniqueId")
	procLogonUserW                     = modadvapi32.NewProc("LogonUserW")
	procLoadUserProfileW               = moduserenv.NewProc("LoadUserProfileW")
	procUnloadUserProfile              = moduserenv.NewProc("UnloadUserProfile")
)

const (
	// logonNetwork is SECURITY_LOGON_TYPE Network, the S4U logon Win32-OpenSSH
	// uses.
	logonNetwork = 3
	// msv1_0S4ULogon and kerbS4ULogon are the S4U submit types (both 12).
	msv1_0S4ULogon = 12
	kerbS4ULogon   = 12
	// logon32NetworkCleartext and logon32ProviderDefault select a password
	// logon that keeps the credentials for network access.
	logon32NetworkCleartext = 8
	logon32ProviderDefault  = 0
	// nameSamCompatible and nameUserPrincipal are EXTENDED_NAME_FORMAT values.
	nameSamCompatible = 2
	nameUserPrincipal = 8
	// piNoUI is PROFILEINFO's PI_NOUI flag.
	piNoUI = 1
)

// unicodeString is UNICODE_STRING.
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

// s4uLogon is MSV1_0_S4U_LOGON and KERB_S4U_LOGON, which share one layout.
type s4uLogon struct {
	MessageType uint32
	Flags       uint32
	Name        unicodeString
	Domain      unicodeString
}

// tokenSource is TOKEN_SOURCE.
type tokenSource struct {
	SourceName       [8]byte
	SourceIdentifier windows.LUID
}

// quotaLimits is QUOTA_LIMITS.
type quotaLimits struct {
	PagedPoolLimit        uintptr
	NonPagedPoolLimit     uintptr
	MinimumWorkingSetSize uintptr
	MaximumWorkingSetSize uintptr
	PagefileLimit         uintptr
	TimeLimit             int64
}

// profileInfo is PROFILEINFOW.
type profileInfo struct {
	Size        uint32
	Flags       uint32
	UserName    *uint16
	ProfilePath *uint16
	DefaultPath *uint16
	ServerName  *uint16
	PolicyPath  *uint16
	Profile     windows.Handle
}

func ntError(status uintptr) error {
	r, _, _ := procLsaNtStatusToWinError.Call(status)
	return windows.Errno(r)
}

// login is a parsed Windows login: a local account (Domain empty), DOMAIN\user
// or a UPN user@domain.
type login struct {
	User, Domain, UPN string
}

// parseLogin splits name into its form. The OS decides whether it exists.
func parseLogin(name string) (login, error) {
	if d, u, ok := strings.Cut(name, `\`); ok {
		if d == "" || u == "" || strings.ContainsAny(u, `\@`) {
			return login{}, fmt.Errorf("login %q is not DOMAIN\\user", name)
		}
		return login{User: u, Domain: d}, nil
	}
	if u, d, ok := strings.Cut(name, "@"); ok {
		if u == "" || d == "" || strings.Contains(d, "@") {
			return login{}, fmt.Errorf("login %q is not user@domain", name)
		}
		return login{User: u, UPN: name}, nil
	}
	return login{User: name}, nil
}

// local reports whether l names an account of this machine: no domain, or
// the computer's own name as the domain.
func (l login) local() bool {
	if l.UPN != "" {
		return false
	}
	if l.Domain == "" || l.Domain == "." {
		return true
	}
	host, err := windows.ComputerName()
	return err == nil && strings.EqualFold(host, l.Domain)
}

// s4uLogonToken logs l on with S4U, without a password, and returns a
// primary token. Local accounts go through MSV1_0, domain accounts through
// Kerberos, as Win32-OpenSSH does. The token has no network credentials.
func s4uLogonToken(l login) (windows.Token, error) {
	var lsa windows.Handle
	process, err := windows.NewNTString("localport-session")
	if err != nil {
		return 0, err
	}
	var mode uint32
	if st, _, _ := procLsaRegisterLogonProcess.Call(uintptr(unsafe.Pointer(process)), uintptr(unsafe.Pointer(&lsa)), uintptr(unsafe.Pointer(&mode))); st != 0 {
		return 0, fmt.Errorf("LsaRegisterLogonProcess: %w", ntError(st))
	}
	defer procLsaDeregisterLogonProcess.Call(uintptr(lsa))

	pkgName, name, domain := "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0", l.User, "."
	messageType := uint32(msv1_0S4ULogon)
	if !l.local() {
		pkgName, messageType, domain = "Kerberos", kerbS4ULogon, ""
		name = l.UPN
		if name == "" {
			name, domain = domainUPN(l)
		}
	}
	pkg, err := windows.NewNTString(pkgName)
	if err != nil {
		return 0, err
	}
	var pkgID uint32
	if st, _, _ := procLsaLookupAuthenticationPackage.Call(uintptr(lsa), uintptr(unsafe.Pointer(pkg)), uintptr(unsafe.Pointer(&pkgID))); st != 0 {
		return 0, fmt.Errorf("LsaLookupAuthenticationPackage %s: %w", pkgName, ntError(st))
	}

	// The package reads the strings from the same buffer as the struct.
	nameU, err := windows.UTF16FromString(name)
	if err != nil {
		return 0, err
	}
	domainU, err := windows.UTF16FromString(domain)
	if err != nil {
		return 0, err
	}
	nameU, domainU = nameU[:len(nameU)-1], domainU[:len(domainU)-1]
	head := unsafe.Sizeof(s4uLogon{})
	size := head + uintptr(2*(len(nameU)+len(domainU)))
	// uint64 words keep the struct aligned; the heap never moves it.
	words := make([]uint64, (size+7)/8)
	buf := unsafe.Pointer(&words[0])
	info := (*s4uLogon)(buf)
	info.MessageType = messageType
	strs := unsafe.Slice((*uint16)(unsafe.Add(buf, head)), len(nameU)+len(domainU))
	copy(strs, nameU)
	copy(strs[len(nameU):], domainU)
	if len(nameU) > 0 {
		info.Name = unicodeString{Length: uint16(2 * len(nameU)), MaximumLength: uint16(2 * len(nameU)), Buffer: &strs[0]}
	}
	if len(domainU) > 0 {
		info.Domain = unicodeString{Length: uint16(2 * len(domainU)), MaximumLength: uint16(2 * len(domainU)), Buffer: &strs[len(nameU)]}
	}

	var src tokenSource
	copy(src.SourceName[:], "localprt")
	if r, _, e := procAllocateLocallyUniqueId.Call(uintptr(unsafe.Pointer(&src.SourceIdentifier))); r == 0 {
		return 0, fmt.Errorf("AllocateLocallyUniqueId: %w", e)
	}
	origin, err := windows.NewNTString("localport")
	if err != nil {
		return 0, err
	}
	var (
		profile    uintptr
		profileLen uint32
		logonID    windows.LUID
		token      windows.Token
		quotas     quotaLimits
		sub        windows.NTStatus
	)
	st, _, _ := procLsaLogonUser.Call(uintptr(lsa), uintptr(unsafe.Pointer(origin)), logonNetwork, uintptr(pkgID),
		uintptr(buf), size, 0, uintptr(unsafe.Pointer(&src)),
		uintptr(unsafe.Pointer(&profile)), uintptr(unsafe.Pointer(&profileLen)), uintptr(unsafe.Pointer(&logonID)),
		uintptr(unsafe.Pointer(&token)), uintptr(unsafe.Pointer(&quotas)), uintptr(unsafe.Pointer(&sub)))
	if profile != 0 {
		procLsaFreeReturnBuffer.Call(profile)
	}
	if st != 0 {
		return 0, fmt.Errorf("%w: LsaLogonUser: %w (substatus %#x)", errAccount, ntError(st), uint32(sub))
	}
	return primaryToken(token)
}

// domainUPN returns the Kerberos client name for DOMAIN\user: its UPN from
// the directory, else user with DOMAIN as the realm.
func domainUPN(l login) (name, realm string) {
	sam, err := windows.UTF16PtrFromString(l.Domain + `\` + l.User)
	if err != nil {
		return l.User, l.Domain
	}
	out := make([]uint16, 1024)
	n := uint32(len(out))
	if r, _, _ := procTranslateNameW.Call(uintptr(unsafe.Pointer(sam)), nameSamCompatible, nameUserPrincipal, uintptr(unsafe.Pointer(&out[0])), uintptr(unsafe.Pointer(&n))); r != 0 {
		return windows.UTF16ToString(out[:n]), ""
	}
	return l.User, l.Domain
}

// passwordLogonToken logs l on with password through LogonUser and returns
// a primary token that carries network credentials. password is zeroed on
// every path, as is its UTF-16 copy.
func passwordLogonToken(l login, password []byte) (windows.Token, error) {
	defer clear(password)
	// Decoded byte by byte: string(password) would leave a copy no one can
	// clear.
	pw := make([]uint16, 0, 2*len(password)+1)
	defer func() { clear(pw[:cap(pw)]) }()
	for b := password; len(b) > 0; {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n <= 1 || r == 0 {
			return 0, fmt.Errorf("%w: the password is not valid UTF-8 text", errAccount)
		}
		pw = utf16.AppendRune(pw, r)
		b = b[n:]
	}
	pw = append(pw, 0)
	user, domain := l.User, l.Domain
	if l.UPN != "" {
		user, domain = l.UPN, ""
	} else if l.local() {
		domain = "."
	}
	u, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return 0, err
	}
	var d *uint16
	if domain != "" {
		if d, err = windows.UTF16PtrFromString(domain); err != nil {
			return 0, err
		}
	}
	var token windows.Token
	if r, _, e := procLogonUserW.Call(uintptr(unsafe.Pointer(u)), uintptr(unsafe.Pointer(d)), uintptr(unsafe.Pointer(&pw[0])),
		logon32NetworkCleartext, logon32ProviderDefault, uintptr(unsafe.Pointer(&token))); r == 0 {
		return 0, fmt.Errorf("%w: LogonUser: %w", errAccount, e)
	}
	return primaryToken(token)
}

// primaryToken duplicates t as a primary token and closes t.
func primaryToken(t windows.Token) (windows.Token, error) {
	defer t.Close()
	var p windows.Token
	if err := windows.DuplicateTokenEx(t, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &p); err != nil {
		return 0, fmt.Errorf("duplicate the logon token: %w", err)
	}
	return p, nil
}

// loadProfile loads the login's profile hive; unload releases it.
func loadProfile(token windows.Token, user string) (unload func(), err error) {
	name, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return nil, err
	}
	pi := profileInfo{Flags: piNoUI, UserName: name}
	pi.Size = uint32(unsafe.Sizeof(pi))
	if r, _, e := procLoadUserProfileW.Call(uintptr(token), uintptr(unsafe.Pointer(&pi))); r == 0 {
		return nil, fmt.Errorf("LoadUserProfile: %w", e)
	}
	return func() { procUnloadUserProfile.Call(uintptr(token), uintptr(pi.Profile)) }, nil
}

// enablePrivileges enables names on this process's token: the launcher
// service's required privileges list holds them disabled or enabled.
func enablePrivileges(names ...string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	for _, n := range names {
		var luid windows.LUID
		p, err := windows.UTF16PtrFromString(n)
		if err != nil {
			return err
		}
		if err := windows.LookupPrivilegeValue(nil, p, &luid); err != nil {
			return fmt.Errorf("look up %s: %w", n, err)
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		// A privilege the token lacks is not assigned without an error; the
		// call that needs it then fails and names it.
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			return fmt.Errorf("enable %s: %w", n, err)
		}
	}
	return nil
}

// errAccount is a logon the OS refused for the account: unknown, disabled,
// locked out, expired, or not allowed this logon.
var errAccount = errors.New("account refused")
