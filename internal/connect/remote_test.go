package connect

import "testing"

func TestParseRemote(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "https no port", in: "https://sub.eu.localport.dev", want: "sub.eu.localport.dev:443"},
		{name: "http no port", in: "http://sub.eu.localport.dev", want: "sub.eu.localport.dev:443"},
		{name: "https explicit port", in: "https://sub.eu.localport.dev:8443", want: "sub.eu.localport.dev:8443"},
		{name: "https trailing slash", in: "https://sub.eu.localport.dev/", want: "sub.eu.localport.dev:443"},
		{name: "https with path", in: "https://sub.eu.localport.dev/db?x=1", want: "sub.eu.localport.dev:443"},
		{name: "tcp with port", in: "tcp://sub.eu.localport.dev:11434", want: "sub.eu.localport.dev:11434"},
		{name: "tls with port", in: "tls://sub.eu.localport.dev:11434", want: "sub.eu.localport.dev:11434"},
		{name: "bare host port", in: "sub.eu.localport.dev:11434", want: "sub.eu.localport.dev:11434"},
		{name: "whitespace", in: "  https://sub.eu.localport.dev  ", want: "sub.eu.localport.dev:443"},
		{name: "uppercase scheme", in: "HTTPS://sub.eu.localport.dev", want: "sub.eu.localport.dev:443"},

		{name: "empty", in: "", wantErr: true},
		{name: "tcp no port", in: "tcp://sub.eu.localport.dev", wantErr: true},
		{name: "tls no port", in: "tls://sub.eu.localport.dev", wantErr: true},
		{name: "bare no port", in: "sub.eu.localport.dev", wantErr: true},
		{name: "unknown scheme", in: "ftp://sub.eu.localport.dev:21", wantErr: true},
		{name: "scheme no host", in: "https://", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRemote(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseRemote(%q) = %q, want error", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRemote(%q) unexpected error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("ParseRemote(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
