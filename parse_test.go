package main

import (
	"reflect"
	"testing"
)

func TestParseLog_AcceptedTrafficShapes(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntry
	}{
		{
			name: "tcp ip dest with >> route arrow",
			line: `2026/03/11 14:22:07.918304 from 203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 1204`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:07.918304",
				From:     "203.0.113.47:4821",
				Status:   "accepted",
				To:       "tcp:198.51.100.88:443",
				Route:    "IN_TCP_XTLS_A7 - DIRECT",
				Email:    "1204",
			},
		},
		{
			name: "tcp domain dest with -> route arrow",
			line: `2026/03/11 14:22:08.001122 from 198.51.100.14:29104 accepted tcp:probe.example-cdn.net:443 [PROXY_EDGE_42 -> DIRECT] email: 8831`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.001122",
				From:     "198.51.100.14:29104",
				Status:   "accepted",
				To:       "tcp:probe.example-cdn.net:443",
				Route:    "PROXY_EDGE_42 - DIRECT",
				Email:    "8831",
			},
		},
		{
			name: "tcp nested domain dest with >> route arrow",
			line: `2026/03/11 14:22:08.044901 from 203.0.113.201:61990 accepted tcp:edge.cdn.widgets.test:443 [GW_REALITY_NOFLOW >> DIRECT] email: 4410`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.044901",
				From:     "203.0.113.201:61990",
				Status:   "accepted",
				To:       "tcp:edge.cdn.widgets.test:443",
				Route:    "GW_REALITY_NOFLOW - DIRECT",
				Email:    "4410",
			},
		},
		{
			name: "tcp short domain with from port 0",
			line: `2026/03/11 14:22:08.102557 from 192.0.2.77:0 accepted tcp:alpha.example:443 [HU_PLAIN_IN >> DIRECT] email: 902`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.102557",
				From:     "192.0.2.77:0",
				Status:   "accepted",
				To:       "tcp:alpha.example:443",
				Route:    "HU_PLAIN_IN - DIRECT",
				Email:    "902",
			},
		},
		{
			name: "tcp long domain with from port 0",
			line: `2026/03/11 14:22:08.118430 from 192.0.2.77:0 accepted tcp:ads.tracker.media-lab.example:443 [HU_PLAIN_IN >> DIRECT] email: 902`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.118430",
				From:     "192.0.2.77:0",
				Status:   "accepted",
				To:       "tcp:ads.tracker.media-lab.example:443",
				Route:    "HU_PLAIN_IN - DIRECT",
				Email:    "902",
			},
		},
		{
			name: "udp dns ip dest with from port 0",
			line: `2026/03/11 14:22:08.155812 from 203.0.113.9:0 accepted udp:9.9.9.9:53 [IN_UDP_FAST_9 >> DIRECT] email: 7712`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.155812",
				From:     "203.0.113.9:0",
				Status:   "accepted",
				To:       "udp:9.9.9.9:53",
				Route:    "IN_UDP_FAST_9 - DIRECT",
				Email:    "7712",
			},
		},
		{
			name: "tcp ip dest high source port",
			line: `2026/03/11 14:22:08.188001 from 198.51.100.221:50441 accepted tcp:203.0.113.66:443 [NODE_B3_TLS >> DIRECT] email: 5560`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.188001",
				From:     "198.51.100.221:50441",
				Status:   "accepted",
				To:       "tcp:203.0.113.66:443",
				Route:    "NODE_B3_TLS - DIRECT",
				Email:    "5560",
			},
		},
		{
			name: "tcp subdomain with hyphenated labels",
			line: `2026/03/11 14:22:08.201774 from 192.0.2.19:13440 accepted tcp:metrics-stage.app-lab.io:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 3398`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.201774",
				From:     "192.0.2.19:13440",
				Status:   "accepted",
				To:       "tcp:metrics-stage.app-lab.io:443",
				Route:    "IN_TCP_XTLS_A7 - DIRECT",
				Email:    "3398",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLog(t, tt.line, tt.want)
		})
	}
}

func TestParseLog_OptionalFieldsAndVariants(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntry
	}{
		{
			name: "==> route arrow normalized to dash",
			line: `2026/05/02 09:11:33.401220 from 203.0.113.18:7712 accepted tcp:198.51.100.40:443 [IN_LEGACY_X1 ==> OUT_DIRECT] email: 6401`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.401220",
				From:     "203.0.113.18:7712",
				Status:   "accepted",
				To:       "tcp:198.51.100.40:443",
				Route:    "IN_LEGACY_X1 - OUT_DIRECT",
				Email:    "6401",
			},
		},
		{
			name: "route already uses dash left as-is",
			line: `2026/05/02 09:11:33.455100 from 192.0.2.44:2201 accepted tcp:cache.cdn.example:443 [IN_TCP_A - DIRECT] email: 218`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.455100",
				From:     "192.0.2.44:2201",
				Status:   "accepted",
				To:       "tcp:cache.cdn.example:443",
				Route:    "IN_TCP_A - DIRECT",
				Email:    "218",
			},
		},
		{
			name: "optional email omitted",
			line: `2026/05/02 09:11:33.501880 from 198.51.100.90:15002 accepted tcp:api.service.example:443 [PROXY_EDGE_7 >> DIRECT]`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.501880",
				From:     "198.51.100.90:15002",
				Status:   "accepted",
				To:       "tcp:api.service.example:443",
				Route:    "PROXY_EDGE_7 - DIRECT",
			},
		},
		{
			name: "optional route omitted",
			line: `2026/05/02 09:11:33.560014 from 203.0.113.61:4099 accepted tcp:alpha.example:443 email: 7740`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.560014",
				From:     "203.0.113.61:4099",
				Status:   "accepted",
				To:       "tcp:alpha.example:443",
				Email:    "7740",
			},
		},
		{
			name: "route and email both omitted",
			line: `2026/05/02 09:11:33.601102 from 192.0.2.5:8080 accepted tcp:beta.example:443`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.601102",
				From:     "192.0.2.5:8080",
				Status:   "accepted",
				To:       "tcp:beta.example:443",
			},
		},
		{
			name: "from keyword omitted",
			line: `2026/05/02 09:11:33.640330 198.51.100.33:9911 accepted tcp:gamma.example:443 [NODE_C9 >> DIRECT] email: 3555`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.640330",
				From:     "198.51.100.33:9911",
				Status:   "accepted",
				To:       "tcp:gamma.example:443",
				Route:    "NODE_C9 - DIRECT",
				Email:    "3555",
			},
		},
		{
			name: "rejected with destination shape",
			line: `2026/05/02 09:11:33.700441 from 203.0.113.77:0 rejected tcp:blocked.example:443 [IN_TCP_B >> DIRECT] email: 912`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.700441",
				From:     "203.0.113.77:0",
				Status:   "rejected",
				To:       "tcp:blocked.example:443",
				Route:    "IN_TCP_B - DIRECT",
				Email:    "912",
			},
		},
		{
			name: "email as address",
			line: `2026/05/02 09:11:33.755902 from 192.0.2.130:4433 accepted tcp:portal.example:443 [HU_PLAIN_IN >> DIRECT] email: robin@example.com`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.755902",
				From:     "192.0.2.130:4433",
				Status:   "accepted",
				To:       "tcp:portal.example:443",
				Route:    "HU_PLAIN_IN - DIRECT",
				Email:    "robin@example.com",
			},
		},
		{
			name: "ipv6 destination kept in to field",
			line: `2026/05/02 09:11:33.810227 from 198.51.100.8:12001 accepted tcp:[2001:db8::53]:443 [IN_V6_EDGE >> DIRECT] email: 4802`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.810227",
				From:     "198.51.100.8:12001",
				Status:   "accepted",
				To:       "tcp:[2001:db8::53]:443",
				Route:    "IN_V6_EDGE - DIRECT",
				Email:    "4802",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLog(t, tt.line, tt.want)
		})
	}
}

func TestParseLog_UnparseableRejectedWithoutDestination(t *testing.T) {
	// Current Xray rejection without a tcp/udp:host:port destination does not match.
	line := `2026/05/02 09:11:34.000001 from 192.0.2.10:0 rejected  proxy/vless/encoding: failed to read request version > websocket: close 1000 (normal)`
	if _, err := parseLog(line); err == nil {
		t.Fatal("parseLog() error = nil, want no match")
	}
}

func assertParseLog(t *testing.T, line string, want LogEntry) {
	t.Helper()

	got, err := parseLog(line)
	if err != nil {
		t.Fatalf("parseLog() error = %v", err)
	}

	// ToAddr comes from optional reverse DNS and is not part of the
	// structural parsing contract covered by these fixtures.
	got.ToAddr = nil

	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("parseLog()\n got: %+v\nwant: %+v", *got, want)
	}
}
