package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

// ---------------------------------------------------------------------------
// Legacy parseLog — raw from/to, datetime with slashes, omitempty optionals
// ---------------------------------------------------------------------------

func TestParseLog_AcceptedTrafficShapes(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntry
	}{
		{
			name: "tcp ipv4 dest with >> route arrow",
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
			name: "tcp short domain with from_port 0",
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
			name: "tcp long domain with from_port 0",
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
			name: "udp dns ipv4 dest with from_port 0",
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
			name: "tcp ipv4 dest high source port",
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
		{
			name: "udp domain dest",
			line: `2026/03/11 14:22:08.250001 from 203.0.113.40:53122 accepted udp:dns.resolver.example:53 [IN_UDP_A >> DIRECT] email: 1001`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.250001",
				From:     "203.0.113.40:53122",
				Status:   "accepted",
				To:       "udp:dns.resolver.example:53",
				Route:    "IN_UDP_A - DIRECT",
				Email:    "1001",
			},
		},
		{
			name: "dest_port 0 kept in to field",
			line: `2026/03/11 14:22:08.300112 from 192.0.2.11:9000 accepted tcp:alpha.example:0 [HU_PLAIN_IN >> DIRECT] email: 55`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.300112",
				From:     "192.0.2.11:9000",
				Status:   "accepted",
				To:       "tcp:alpha.example:0",
				Route:    "HU_PLAIN_IN - DIRECT",
				Email:    "55",
			},
		},
		{
			name: "tcp ipv4 dest on port 80",
			line: `2026/03/11 14:22:08.400001 from 198.51.100.205:49996 accepted tcp:203.0.113.32:80 [IN_REALITY_NOFLOW >> DIRECT] email: 50`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.400001",
				From:     "198.51.100.205:49996",
				Status:   "accepted",
				To:       "tcp:203.0.113.32:80",
				Route:    "IN_REALITY_NOFLOW - DIRECT",
				Email:    "50",
			},
		},
		{
			name: "tcp dest on push-style port 5223",
			line: `2026/03/11 14:22:08.400002 from 192.0.2.145:45042 accepted tcp:198.51.100.160:5223 [IN_REALITY_NOFLOW >> DIRECT] email: 1201`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.400002",
				From:     "192.0.2.145:45042",
				Status:   "accepted",
				To:       "tcp:198.51.100.160:5223",
				Route:    "IN_REALITY_NOFLOW - DIRECT",
				Email:    "1201",
			},
		},
		{
			name: "tcp domain dest on port 5228",
			line: `2026/03/11 14:22:08.400003 from 198.51.100.188:42621 accepted tcp:mtalk.example-cdn.net:5228 [IN_REALITY_NOFLOW >> DIRECT] email: 3952`,
			want: LogEntry{
				Datetime: "2026/03/11 14:22:08.400003",
				From:     "198.51.100.188:42621",
				Status:   "accepted",
				To:       "tcp:mtalk.example-cdn.net:5228",
				Route:    "IN_REALITY_NOFLOW - DIRECT",
				Email:    "3952",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLog(t, tt.line, tt.want)
		})
	}
}

func TestParseLog_RouteArrowNormalization(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntry
	}{
		{
			name: ">> arrow to dash",
			line: `2026/05/02 09:11:33.100001 from 203.0.113.1:1000 accepted tcp:alpha.example:443 [IN_A >> DIRECT] email: 1`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.100001",
				From:     "203.0.113.1:1000",
				Status:   "accepted",
				To:       "tcp:alpha.example:443",
				Route:    "IN_A - DIRECT",
				Email:    "1",
			},
		},
		{
			name: "-> arrow to dash",
			line: `2026/05/02 09:11:33.100002 from 203.0.113.1:1000 accepted tcp:alpha.example:443 [IN_A -> DIRECT] email: 1`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.100002",
				From:     "203.0.113.1:1000",
				Status:   "accepted",
				To:       "tcp:alpha.example:443",
				Route:    "IN_A - DIRECT",
				Email:    "1",
			},
		},
		{
			name: "==> arrow to dash",
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
			name: "route kept as whole string not split",
			line: `2026/05/02 09:11:33.500001 from 192.0.2.1:1 accepted tcp:x.example:443 [TAG_IN >> TAG_OUT] email: 9`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.500001",
				From:     "192.0.2.1:1",
				Status:   "accepted",
				To:       "tcp:x.example:443",
				Route:    "TAG_IN - TAG_OUT",
				Email:    "9",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLog(t, tt.line, tt.want)
		})
	}
}

func TestParseLog_OptionalFields(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntry
	}{
		{
			name: "email omitted, route present",
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
			name: "route omitted, email present",
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
			name: "from keyword omitted and optionals omitted",
			line: `2026/05/02 09:11:33.640331 198.51.100.33:9911 accepted tcp:gamma.example:443`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.640331",
				From:     "198.51.100.33:9911",
				Status:   "accepted",
				To:       "tcp:gamma.example:443",
			},
		},
		{
			name: "email as numeric string",
			line: `2026/05/02 09:11:33.700001 from 192.0.2.2:2 accepted tcp:x.example:443 [A >> B] email: 42`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.700001",
				From:     "192.0.2.2:2",
				Status:   "accepted",
				To:       "tcp:x.example:443",
				Route:    "A - B",
				Email:    "42",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLog(t, tt.line, tt.want)
		})
	}
}

func TestParseLog_StatusVariants(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntry
	}{
		{
			name: "accepted",
			line: `2026/05/02 09:11:33.010001 from 203.0.113.10:10 accepted tcp:ok.example:443 [IN >> DIRECT] email: 1`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.010001",
				From:     "203.0.113.10:10",
				Status:   "accepted",
				To:       "tcp:ok.example:443",
				Route:    "IN - DIRECT",
				Email:    "1",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLog(t, tt.line, tt.want)
		})
	}
}

func TestParseLog_FromAndToRawShapes(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntry
	}{
		{
			name: "from with tcp proto prefix kept raw",
			line: `2026/05/02 09:11:33.880001 from tcp:203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 1204`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.880001",
				From:     "tcp:203.0.113.47:4821",
				Status:   "accepted",
				To:       "tcp:198.51.100.88:443",
				Route:    "IN_TCP_XTLS_A7 - DIRECT",
				Email:    "1204",
			},
		},
		{
			name: "from with udp proto prefix kept raw",
			line: `2026/05/02 09:11:33.900112 from udp:192.0.2.77:0 accepted udp:9.9.9.9:53 [IN_UDP_FAST_9 >> DIRECT] email: 7712`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.900112",
				From:     "udp:192.0.2.77:0",
				Status:   "accepted",
				To:       "udp:9.9.9.9:53",
				Route:    "IN_UDP_FAST_9 - DIRECT",
				Email:    "7712",
			},
		},
		{
			name: "from tcp prefix with udp dest kept raw",
			line: `2026/05/02 09:11:33.910001 from tcp:203.0.113.45:44783 accepted udp:198.51.100.13:443 [IN_REALITY_NOFLOW >> DIRECT] email: 78`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.910001",
				From:     "tcp:203.0.113.45:44783",
				Status:   "accepted",
				To:       "udp:198.51.100.13:443",
				Route:    "IN_REALITY_NOFLOW - DIRECT",
				Email:    "78",
			},
		},
		{
			name: "from tcp prefix port 0 with udp dest kept raw",
			line: `2026/05/02 09:11:33.910002 from tcp:198.51.100.169:0 accepted udp:203.0.113.139:443 [IN_HU_DIRECT >> DIRECT] email: 851`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.910002",
				From:     "tcp:198.51.100.169:0",
				Status:   "accepted",
				To:       "udp:203.0.113.139:443",
				Route:    "IN_HU_DIRECT - DIRECT",
				Email:    "851",
			},
		},
		{
			name: "ipv6 destination brackets kept in to",
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
		{
			name: "ipv6 from brackets kept in from",
			line: `2026/05/02 09:11:33.820001 from [2001:db8::10]:4433 accepted tcp:alpha.example:443 [IN_V6 >> DIRECT] email: 77`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.820001",
				From:     "[2001:db8::10]:4433",
				Status:   "accepted",
				To:       "tcp:alpha.example:443",
				Route:    "IN_V6 - DIRECT",
				Email:    "77",
			},
		},
		{
			name: "from tcp proto plus ipv6 brackets kept raw",
			line: `2026/05/02 09:11:33.830001 from tcp:[2001:db8::10]:4433 accepted tcp:[2001:db8::53]:443 [IN_V6 >> DIRECT] email: 77`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.830001",
				From:     "tcp:[2001:db8::10]:4433",
				Status:   "accepted",
				To:       "tcp:[2001:db8::53]:443",
				Route:    "IN_V6 - DIRECT",
				Email:    "77",
			},
		},
		{
			name: "udp ipv6 destination brackets kept in to",
			line: `2026/05/02 09:11:33.840001 from 192.0.2.9:0 accepted udp:[2001:db8::53]:53 [IN_UDP_V6 >> DIRECT] email: 3`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.840001",
				From:     "192.0.2.9:0",
				Status:   "accepted",
				To:       "udp:[2001:db8::53]:53",
				Route:    "IN_UDP_V6 - DIRECT",
				Email:    "3",
			},
		},
		{
			name: "non-IP from kept raw (legacy does not validate IP)",
			line: `2026/05/02 09:11:34.100001 from not-an-ip:4433 accepted tcp:alpha.example:443 [IN >> DIRECT] email: 1`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:34.100001",
				From:     "not-an-ip:4433",
				Status:   "accepted",
				To:       "tcp:alpha.example:443",
				Route:    "IN - DIRECT",
				Email:    "1",
			},
		},
		{
			name: "dest without proto kept raw",
			line: `2026/05/02 09:11:33.910002 from 198.51.100.169:0 accepted 203.0.113.139:443 [IN_HU_DIRECT >> DIRECT] email: 851`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.910002",
				From:     "198.51.100.169:0",
				Status:   "accepted",
				To:       "203.0.113.139:443",
				Route:    "IN_HU_DIRECT - DIRECT",
				Email:    "851",
			},
		},
		{
			name: "from tcp prefix and dest without proto kept raw",
			line: `2026/05/02 09:11:33.910002 from tcp:198.51.100.169:0 accepted 203.0.113.139:443 [IN_HU_DIRECT >> DIRECT] email: 851`,
			want: LogEntry{
				Datetime: "2026/05/02 09:11:33.910002",
				From:     "tcp:198.51.100.169:0",
				Status:   "accepted",
				To:       "203.0.113.139:443",
				Route:    "IN_HU_DIRECT - DIRECT",
				Email:    "851",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLog(t, tt.line, tt.want)
		})
	}
}

func TestParseLog_DatetimeKeptRaw(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "slashes and microseconds preserved",
			line: `2026/05/02 09:11:33.918304 from 203.0.113.1:1 accepted tcp:a.example:443 email: 1`,
			want: "2026/05/02 09:11:33.918304",
		},
		{
			name: "trailing fractional zeros preserved",
			line: `2026/05/02 09:11:33.100000 from 203.0.113.1:1 accepted tcp:a.example:443 email: 1`,
			want: "2026/05/02 09:11:33.100000",
		},
		{
			name: "all-zero fractional seconds preserved",
			line: `2026/01/01 00:00:00.000000 from 203.0.113.1:1 accepted tcp:a.example:443 email: 1`,
			want: "2026/01/01 00:00:00.000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLog(tt.line)
			if err != nil {
				t.Fatalf("parseLog() error = %v", err)
			}
			if got.Datetime != tt.want {
				t.Fatalf("Datetime = %q, want %q", got.Datetime, tt.want)
			}
		})
	}
}

func TestParseLog_RejectsUnparseable(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{
			name: "rejected without tcp/udp destination",
			line: `2026/05/02 09:11:34.000001 from 192.0.2.10:0 rejected  proxy/vless/encoding: failed to read request version > websocket: close 1000 (normal)`,
		},
		{
			name: "empty line",
			line: ``,
		},
		{
			name: "garbage",
			line: `not an xray access log line`,
		},
		{
			name: "only datetime",
			line: `2026/05/02 09:11:34.000001`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseLog(tt.line); err == nil {
				t.Fatal("parseLog() error = nil, want no match")
			}
		})
	}
}

func TestParseLog_JSONContract(t *testing.T) {
	t.Run("full entry includes all populated fields", func(t *testing.T) {
		line := `2026/05/02 09:11:33.880001 from tcp:203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 1204`
		got, err := parseLog(line)
		if err != nil {
			t.Fatalf("parseLog() error = %v", err)
		}
		got.ToAddr = nil

		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}

		want := `{"datetime":"2026/05/02 09:11:33.880001","from":"tcp:203.0.113.47:4821","status":"accepted","to":"tcp:198.51.100.88:443","route":"IN_TCP_XTLS_A7 - DIRECT","email":"1204"}`
		if string(raw) != want {
			t.Fatalf("JSON contract\n got: %s\nwant: %s", raw, want)
		}
	})

	t.Run("omitted route and email use omitempty", func(t *testing.T) {
		line := `2026/05/02 09:11:33.601102 from 192.0.2.5:8080 accepted tcp:beta.example:443`
		got, err := parseLog(line)
		if err != nil {
			t.Fatalf("parseLog() error = %v", err)
		}
		got.ToAddr = nil

		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}

		want := `{"datetime":"2026/05/02 09:11:33.601102","from":"192.0.2.5:8080","status":"accepted","to":"tcp:beta.example:443"}`
		if string(raw) != want {
			t.Fatalf("JSON contract\n got: %s\nwant: %s", raw, want)
		}
	})
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
