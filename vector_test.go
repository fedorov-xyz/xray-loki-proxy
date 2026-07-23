package main

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"
)

func TestProcessLinesParallel(t *testing.T) {
	prevRules := skipRules
	t.Cleanup(func() { skipRules = prevRules })

	lineA := `2026/07/23 10:11:12.100000 from 203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 1204`
	lineB := `2026/07/23 10:11:12.200000 from 198.51.100.14:29104 accepted tcp:probe.example-cdn.net:443 [PROXY_EDGE_42 -> DIRECT] email: 8831`
	lineC := `2026/07/23 10:11:12.300000 from 203.0.113.9:0 accepted udp:9.9.9.9:53 [IN_UDP_FAST_9 >> DIRECT] email: 7712`
	bad := `totally-not-an-xray-access-log`
	skippedByIP := `2026/07/23 10:11:12.400000 from 192.0.2.10:4444 accepted tcp:203.0.113.200:443 [EDGE_A >> DIRECT] email: 555`

	tests := []struct {
		name       string
		rules      []SkipRule
		in         []string
		wantEmails []string
		want       []LogEntryV2
	}{
		{
			name:       "empty input",
			in:         nil,
			wantEmails: []string{},
		},
		{
			name:       "preserves order for all valid lines",
			in:         []string{lineA, lineB, lineC},
			wantEmails: []string{"1204", "8831", "7712"},
			want: []LogEntryV2{
				{
					Datetime:  "2026-07-23 10:11:12.100000",
					FromIP:    "203.0.113.47",
					FromPort:  4821,
					Status:    "accepted",
					DestProto: "tcp",
					DestHost:  "198.51.100.88",
					DestPort:  443,
					Route:     "IN_TCP_XTLS_A7 - DIRECT",
					Email:     "1204",
					ToAddr:    []string{},
				},
				{
					Datetime:  "2026-07-23 10:11:12.200000",
					FromIP:    "198.51.100.14",
					FromPort:  29104,
					Status:    "accepted",
					DestProto: "tcp",
					DestHost:  "probe.example-cdn.net",
					DestPort:  443,
					Route:     "PROXY_EDGE_42 - DIRECT",
					Email:     "8831",
					ToAddr:    []string{},
				},
				{
					Datetime:  "2026-07-23 10:11:12.300000",
					FromIP:    "203.0.113.9",
					FromPort:  0,
					Status:    "accepted",
					DestProto: "udp",
					DestHost:  "9.9.9.9",
					DestPort:  53,
					Route:     "IN_UDP_FAST_9 - DIRECT",
					Email:     "7712",
					ToAddr:    []string{},
				},
			},
		},
		{
			name:       "drops unparsable and keeps dense ordered list",
			in:         []string{lineA, bad, lineB, bad, lineC},
			wantEmails: []string{"1204", "8831", "7712"},
		},
		{
			name: "drops skip-rule matches",
			rules: []SkipRule{
				{IP: []string{"203.0.113.200"}},
			},
			in:         []string{lineA, skippedByIP, lineB},
			wantEmails: []string{"1204", "8831"},
		},
		{
			name:       "all unparsable yields empty dense list",
			in:         []string{bad, bad},
			wantEmails: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipRules = tt.rules

			got := processLinesParallel(tt.in)
			for _, e := range got {
				if e == nil {
					t.Fatal("processLinesParallel returned nil entry in dense list")
				}
			}

			gotEmails := make([]string, 0, len(got))
			for _, e := range got {
				gotEmails = append(gotEmails, e.Email)
			}
			if !reflect.DeepEqual(gotEmails, tt.wantEmails) {
				t.Fatalf("emails order/content\n got: %#v\nwant: %#v", gotEmails, tt.wantEmails)
			}

			if tt.want == nil {
				return
			}
			gotNorm := make([]LogEntryV2, len(got))
			for i, e := range got {
				gotNorm[i] = *e
				// ToAddr comes from live PTR; do not assert on it.
				gotNorm[i].ToAddr = []string{}
			}
			if !reflect.DeepEqual(gotNorm, tt.want) {
				t.Fatalf("entries\n got: %+v\nwant: %+v", gotNorm, tt.want)
			}
		})
	}
}

func TestProcessLinesParallel_ConcurrencySmoke(t *testing.T) {
	prevRules := skipRules
	t.Cleanup(func() { skipRules = prevRules })
	skipRules = nil

	const n = 200
	in := make([]string, 0, n)
	wantEmails := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if i%5 == 0 {
			in = append(in, fmt.Sprintf("bad-line-%d", i))
			continue
		}
		email := 10000 + i
		in = append(in, formatTestAccessLine(email))
		wantEmails = append(wantEmails, strconv.Itoa(email))
	}

	got := processLinesParallel(in)
	if len(got) != len(wantEmails) {
		t.Fatalf("len(got)=%d want %d", len(got), len(wantEmails))
	}
	for i, e := range got {
		if e == nil {
			t.Fatalf("nil at %d", i)
		}
		if e.Email != wantEmails[i] {
			t.Fatalf("order broken at %d: got email %q want %q", i, e.Email, wantEmails[i])
		}
	}
}

func formatTestAccessLine(email int) string {
	return fmt.Sprintf(
		`2026/07/23 10:11:12.000000 from 203.0.113.50:1000 accepted tcp:198.51.100.10:443 [SMOKE_IN >> DIRECT] email: %d`,
		email,
	)
}

func TestHashBatch_Stable(t *testing.T) {
	a := []byte("line-one\nline-two\n")
	b := []byte("line-one\nline-two\n")
	c := []byte("line-one\nline-two\n ") // different

	ha := hashBatch(a)
	hb := hashBatch(b)
	hc := hashBatch(c)

	if ha != hb {
		t.Fatalf("same body must hash equal: %s vs %s", ha, hb)
	}
	if ha == hc {
		t.Fatalf("different body must hash different")
	}
	if len(ha) != 64 { // sha256 hex
		t.Fatalf("unexpected digest len %d", len(ha))
	}
}
