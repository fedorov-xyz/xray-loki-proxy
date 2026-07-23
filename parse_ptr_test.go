package main

import (
	"strings"
	"testing"
)

func TestLookupToAddrTimed_CloudflareGoogle(t *testing.T) {
	cases := []struct {
		ip   string
		want string // substring expected in some PTR name
	}{
		{ip: "1.1.1.1", want: "one.one.one.one"},
		{ip: "8.8.8.8", want: "dns.google"},
	}

	for _, tt := range cases {
		t.Run(tt.ip, func(t *testing.T) {
			names := lookupToAddrTimed(tt.ip)
			if len(names) == 0 {
				t.Skipf("lookupToAddrTimed(%s) returned no names (DNS unreachable?)", tt.ip)
			}
			found := false
			for _, n := range names {
				if strings.Contains(strings.ToLower(n), tt.want) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lookupToAddrTimed(%s)=%v, want a name containing %q", tt.ip, names, tt.want)
			}
		})
	}
}
