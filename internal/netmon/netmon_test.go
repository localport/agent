package netmon

import (
	"net"
	"testing"
)

// addrKey must include only routable global-unicast addresses, sorted and
// stable, so the same set always produces the same key and only a real change
// flips it. Loopback, link-local, and multicast are noise that must never fire
// a reconnect.
func TestAddrKeyFiltersNoise(t *testing.T) {
	ipnet := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("bad cidr %q: %v", s, err)
		}
		n.IP = ip
		return n
	}

	addrs := []net.Addr{
		ipnet("192.168.1.50/24"), // LAN, keep
		ipnet("127.0.0.1/8"),     // loopback, drop
		ipnet("169.254.10.2/16"), // link-local v4, drop
		ipnet("fe80::1/64"),      // link-local v6, drop
		ipnet("::1/128"),         // loopback v6, drop
		ipnet("2001:db8::5/64"),  // global v6, keep
		ipnet("10.0.0.8/8"),      // private, keep (still routable)
	}

	got := addrKey(addrs)
	want := "10.0.0.8,192.168.1.50,2001:db8::5" // sorted, only the three keepers
	if got != want {
		t.Fatalf("addrKey = %q, want %q", got, want)
	}
}

// The key must be order-independent: the same address set in any order yields
// the same key (a network change is a set change, not a list change).
func TestAddrKeyOrderIndependent(t *testing.T) {
	a := addrKey([]net.Addr{&net.IPAddr{IP: net.ParseIP("1.1.1.1")}, &net.IPAddr{IP: net.ParseIP("2.2.2.2")}})
	b := addrKey([]net.Addr{&net.IPAddr{IP: net.ParseIP("2.2.2.2")}, &net.IPAddr{IP: net.ParseIP("1.1.1.1")}})
	if a != b {
		t.Fatalf("order changed the key: %q vs %q", a, b)
	}
}

// An empty address set is a valid, stable key (host went fully offline), it
// must not panic and must equal itself.
func TestAddrKeyEmpty(t *testing.T) {
	if k := addrKey(nil); k != "" {
		t.Fatalf("empty set key = %q, want empty", k)
	}
}
