package main

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestParseLogV2_AcceptedTrafficShapes(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntryV2
	}{
		{
			name: "tcp ipv4 dest with >> route arrow",
			line: `2026/03/11 14:22:07.918304 from 203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 1204`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:07.918304",
				FromProto: "",
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
		},
		{
			name: "tcp domain dest with -> route arrow",
			line: `2026/03/11 14:22:08.001122 from 198.51.100.14:29104 accepted tcp:probe.example-cdn.net:443 [PROXY_EDGE_42 -> DIRECT] email: 8831`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.001122",
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
		},
		{
			name: "tcp nested domain dest with >> route arrow",
			line: `2026/03/11 14:22:08.044901 from 203.0.113.201:61990 accepted tcp:edge.cdn.widgets.test:443 [GW_REALITY_NOFLOW >> DIRECT] email: 4410`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.044901",
				FromIP:    "203.0.113.201",
				FromPort:  61990,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "edge.cdn.widgets.test",
				DestPort:  443,
				Route:     "GW_REALITY_NOFLOW - DIRECT",
				Email:     "4410",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp short domain with from_port 0",
			line: `2026/03/11 14:22:08.102557 from 192.0.2.77:0 accepted tcp:alpha.example:443 [HU_PLAIN_IN >> DIRECT] email: 902`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.102557",
				FromIP:    "192.0.2.77",
				FromPort:  0,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "alpha.example",
				DestPort:  443,
				Route:     "HU_PLAIN_IN - DIRECT",
				Email:     "902",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp long domain with from_port 0",
			line: `2026/03/11 14:22:08.118430 from 192.0.2.77:0 accepted tcp:ads.tracker.media-lab.example:443 [HU_PLAIN_IN >> DIRECT] email: 902`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.118430",
				FromIP:    "192.0.2.77",
				FromPort:  0,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "ads.tracker.media-lab.example",
				DestPort:  443,
				Route:     "HU_PLAIN_IN - DIRECT",
				Email:     "902",
				ToAddr:    []string{},
			},
		},
		{
			name: "udp dns ipv4 dest with from_port 0",
			line: `2026/03/11 14:22:08.155812 from 203.0.113.9:0 accepted udp:9.9.9.9:53 [IN_UDP_FAST_9 >> DIRECT] email: 7712`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.155812",
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
		{
			name: "tcp ipv4 dest high source port",
			line: `2026/03/11 14:22:08.188001 from 198.51.100.221:50441 accepted tcp:203.0.113.66:443 [NODE_B3_TLS >> DIRECT] email: 5560`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.188001",
				FromIP:    "198.51.100.221",
				FromPort:  50441,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "203.0.113.66",
				DestPort:  443,
				Route:     "NODE_B3_TLS - DIRECT",
				Email:     "5560",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp subdomain with hyphenated labels",
			line: `2026/03/11 14:22:08.201774 from 192.0.2.19:13440 accepted tcp:metrics-stage.app-lab.io:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 3398`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.201774",
				FromIP:    "192.0.2.19",
				FromPort:  13440,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "metrics-stage.app-lab.io",
				DestPort:  443,
				Route:     "IN_TCP_XTLS_A7 - DIRECT",
				Email:     "3398",
				ToAddr:    []string{},
			},
		},
		{
			name: "udp domain dest",
			line: `2026/03/11 14:22:08.250001 from 203.0.113.40:53122 accepted udp:dns.resolver.example:53 [IN_UDP_A >> DIRECT] email: 1001`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.250001",
				FromIP:    "203.0.113.40",
				FromPort:  53122,
				Status:    "accepted",
				DestProto: "udp",
				DestHost:  "dns.resolver.example",
				DestPort:  53,
				Route:     "IN_UDP_A - DIRECT",
				Email:     "1001",
				ToAddr:    []string{},
			},
		},
		{
			name: "dest_port 0 is valid and kept",
			line: `2026/03/11 14:22:08.300112 from 192.0.2.11:9000 accepted tcp:alpha.example:0 [HU_PLAIN_IN >> DIRECT] email: 55`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.300112",
				FromIP:    "192.0.2.11",
				FromPort:  9000,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "alpha.example",
				DestPort:  0,
				Route:     "HU_PLAIN_IN - DIRECT",
				Email:     "55",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp ipv4 dest on port 80",
			line: `2026/03/11 14:22:08.400001 from 198.51.100.205:49996 accepted tcp:203.0.113.32:80 [IN_REALITY_NOFLOW >> DIRECT] email: 50`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.400001",
				FromIP:    "198.51.100.205",
				FromPort:  49996,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "203.0.113.32",
				DestPort:  80,
				Route:     "IN_REALITY_NOFLOW - DIRECT",
				Email:     "50",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp dest on push-style port 5223",
			line: `2026/03/11 14:22:08.400002 from 192.0.2.145:45042 accepted tcp:198.51.100.160:5223 [IN_REALITY_NOFLOW >> DIRECT] email: 1201`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.400002",
				FromIP:    "192.0.2.145",
				FromPort:  45042,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "198.51.100.160",
				DestPort:  5223,
				Route:     "IN_REALITY_NOFLOW - DIRECT",
				Email:     "1201",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp domain dest on port 5228",
			line: `2026/03/11 14:22:08.400003 from 198.51.100.188:42621 accepted tcp:mtalk.example-cdn.net:5228 [IN_REALITY_NOFLOW >> DIRECT] email: 3952`,
			want: LogEntryV2{
				Datetime:  "2026-03-11 14:22:08.400003",
				FromIP:    "198.51.100.188",
				FromPort:  42621,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "mtalk.example-cdn.net",
				DestPort:  5228,
				Route:     "IN_REALITY_NOFLOW - DIRECT",
				Email:     "3952",
				ToAddr:    []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLogV2(t, tt.line, tt.want)
		})
	}
}

func TestParseLogV2_DatetimeUTCBasicFormat(t *testing.T) {
	tests := []struct {
		name string
		line string
		want string
	}{
		{
			name: "slashes become dashes, microseconds kept",
			line: `2026/05/02 09:11:33.918304 from 203.0.113.1:1 accepted tcp:a.example:443 email: 1`,
			want: "2026-05-02 09:11:33.918304",
		},
		{
			name: "trailing fractional zeros padded to 6 digits",
			line: `2026/05/02 09:11:33.100000 from 203.0.113.1:1 accepted tcp:a.example:443 email: 1`,
			want: "2026-05-02 09:11:33.100000",
		},
		{
			name: "all-zero fractional seconds padded to 6 digits",
			line: `2026/01/01 00:00:00.000000 from 203.0.113.1:1 accepted tcp:a.example:443 email: 1`,
			want: "2026-01-01 00:00:00.000000",
		},
		{
			name: "space separator between date and time preserved",
			line: `2026/12/31 23:59:59.999999 from 203.0.113.1:1 accepted tcp:a.example:443 email: 1`,
			want: "2026-12-31 23:59:59.999999",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLogV2(tt.line)
			if err != nil {
				t.Fatalf("parseLogV2() error = %v", err)
			}
			if got.Datetime != tt.want {
				t.Fatalf("Datetime = %q, want %q", got.Datetime, tt.want)
			}
		})
	}
}

func TestParseLogV2_RouteArrowNormalization(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntryV2
	}{
		{
			name: ">> arrow to dash",
			line: `2026/05/02 09:11:33.100001 from 203.0.113.1:1000 accepted tcp:alpha.example:443 [IN_A >> DIRECT] email: 1`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.100001",
				FromIP:    "203.0.113.1",
				FromPort:  1000,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "alpha.example",
				DestPort:  443,
				Route:     "IN_A - DIRECT",
				Email:     "1",
				ToAddr:    []string{},
			},
		},
		{
			name: "-> arrow to dash",
			line: `2026/05/02 09:11:33.100002 from 203.0.113.1:1000 accepted tcp:alpha.example:443 [IN_A -> DIRECT] email: 1`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.100002",
				FromIP:    "203.0.113.1",
				FromPort:  1000,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "alpha.example",
				DestPort:  443,
				Route:     "IN_A - DIRECT",
				Email:     "1",
				ToAddr:    []string{},
			},
		},
		{
			name: "==> arrow to dash",
			line: `2026/05/02 09:11:33.401220 from 203.0.113.18:7712 accepted tcp:198.51.100.40:443 [IN_LEGACY_X1 ==> OUT_DIRECT] email: 6401`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.401220",
				FromIP:    "203.0.113.18",
				FromPort:  7712,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "198.51.100.40",
				DestPort:  443,
				Route:     "IN_LEGACY_X1 - OUT_DIRECT",
				Email:     "6401",
				ToAddr:    []string{},
			},
		},
		{
			name: "route already uses dash left as-is",
			line: `2026/05/02 09:11:33.455100 from 192.0.2.44:2201 accepted tcp:cache.cdn.example:443 [IN_TCP_A - DIRECT] email: 218`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.455100",
				FromIP:    "192.0.2.44",
				FromPort:  2201,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "cache.cdn.example",
				DestPort:  443,
				Route:     "IN_TCP_A - DIRECT",
				Email:     "218",
				ToAddr:    []string{},
			},
		},
		{
			name: "route kept as whole string for later splitByString",
			line: `2026/05/02 09:11:33.500001 from 192.0.2.1:1 accepted tcp:x.example:443 [TAG_IN >> TAG_OUT] email: 9`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.500001",
				FromIP:    "192.0.2.1",
				FromPort:  1,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "x.example",
				DestPort:  443,
				Route:     "TAG_IN - TAG_OUT",
				Email:     "9",
				ToAddr:    []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLogV2(t, tt.line, tt.want)
		})
	}
}

func TestParseLogV2_OptionalFields(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntryV2
	}{
		{
			name: "email omitted becomes empty string",
			line: `2026/05/02 09:11:33.501880 from 198.51.100.90:15002 accepted tcp:api.service.example:443 [PROXY_EDGE_7 >> DIRECT]`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.501880",
				FromIP:    "198.51.100.90",
				FromPort:  15002,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "api.service.example",
				DestPort:  443,
				Route:     "PROXY_EDGE_7 - DIRECT",
				Email:     "",
				ToAddr:    []string{},
			},
		},
		{
			name: "route omitted becomes empty string",
			line: `2026/05/02 09:11:33.560014 from 203.0.113.61:4099 accepted tcp:alpha.example:443 email: 7740`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.560014",
				FromIP:    "203.0.113.61",
				FromPort:  4099,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "alpha.example",
				DestPort:  443,
				Route:     "",
				Email:     "7740",
				ToAddr:    []string{},
			},
		},
		{
			name: "route and email both omitted become empty strings",
			line: `2026/05/02 09:11:33.601102 from 192.0.2.5:8080 accepted tcp:beta.example:443`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.601102",
				FromIP:    "192.0.2.5",
				FromPort:  8080,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "beta.example",
				DestPort:  443,
				Route:     "",
				Email:     "",
				ToAddr:    []string{},
			},
		},
		{
			name: "from keyword omitted",
			line: `2026/05/02 09:11:33.640330 198.51.100.33:9911 accepted tcp:gamma.example:443 [NODE_C9 >> DIRECT] email: 3555`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.640330",
				FromIP:    "198.51.100.33",
				FromPort:  9911,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "gamma.example",
				DestPort:  443,
				Route:     "NODE_C9 - DIRECT",
				Email:     "3555",
				ToAddr:    []string{},
			},
		},
		{
			name: "from keyword omitted and optionals omitted",
			line: `2026/05/02 09:11:33.640331 198.51.100.33:9911 accepted tcp:gamma.example:443`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.640331",
				FromIP:    "198.51.100.33",
				FromPort:  9911,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "gamma.example",
				DestPort:  443,
				Route:     "",
				Email:     "",
				ToAddr:    []string{},
			},
		},
		{
			name: "email as numeric string",
			line: `2026/05/02 09:11:33.700001 from 192.0.2.2:2 accepted tcp:x.example:443 [A >> B] email: 42`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.700001",
				FromIP:    "192.0.2.2",
				FromPort:  2,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "x.example",
				DestPort:  443,
				Route:     "A - B",
				Email:     "42",
				ToAddr:    []string{},
			},
		},
		{
			name: "email as address",
			line: `2026/05/02 09:11:33.755902 from 192.0.2.130:4433 accepted tcp:portal.example:443 [HU_PLAIN_IN >> DIRECT] email: robin@example.com`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.755902",
				FromIP:    "192.0.2.130",
				FromPort:  4433,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "portal.example",
				DestPort:  443,
				Route:     "HU_PLAIN_IN - DIRECT",
				Email:     "robin@example.com",
				ToAddr:    []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLogV2(t, tt.line, tt.want)
		})
	}
}

func TestParseLogV2_StatusVariants(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntryV2
	}{
		{
			name: "accepted",
			line: `2026/05/02 09:11:33.010001 from 203.0.113.10:10 accepted tcp:ok.example:443 [IN >> DIRECT] email: 1`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.010001",
				FromIP:    "203.0.113.10",
				FromPort:  10,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "ok.example",
				DestPort:  443,
				Route:     "IN - DIRECT",
				Email:     "1",
				ToAddr:    []string{},
			},
		},
		{
			name: "rejected with destination shape",
			line: `2026/05/02 09:11:33.700441 from 203.0.113.77:0 rejected tcp:blocked.example:443 [IN_TCP_B >> DIRECT] email: 912`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.700441",
				FromIP:    "203.0.113.77",
				FromPort:  0,
				Status:    "rejected",
				DestProto: "tcp",
				DestHost:  "blocked.example",
				DestPort:  443,
				Route:     "IN_TCP_B - DIRECT",
				Email:     "912",
				ToAddr:    []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLogV2(t, tt.line, tt.want)
		})
	}
}

func TestParseLogV2_FromEndpointSplit(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntryV2
	}{
		{
			name: "no proto prefix → empty from_proto",
			line: `2026/05/02 09:11:33.880000 from 203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN >> DIRECT] email: 1`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.880000",
				FromProto: "",
				FromIP:    "203.0.113.47",
				FromPort:  4821,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "198.51.100.88",
				DestPort:  443,
				Route:     "IN - DIRECT",
				Email:     "1",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp proto prefix stripped into from_proto",
			line: `2026/05/02 09:11:33.880001 from tcp:203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 1204`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.880001",
				FromProto: "tcp",
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
		},
		{
			name: "udp proto prefix stripped into from_proto with from_port 0",
			line: `2026/05/02 09:11:33.900112 from udp:192.0.2.77:0 accepted udp:9.9.9.9:53 [IN_UDP_FAST_9 >> DIRECT] email: 7712`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.900112",
				FromProto: "udp",
				FromIP:    "192.0.2.77",
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
		{
			name: "from tcp prefix with udp dest",
			line: `2026/05/02 09:11:33.910001 from tcp:203.0.113.45:44783 accepted udp:198.51.100.13:443 [IN_REALITY_NOFLOW >> DIRECT] email: 78`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.910001",
				FromProto: "tcp",
				FromIP:    "203.0.113.45",
				FromPort:  44783,
				Status:    "accepted",
				DestProto: "udp",
				DestHost:  "198.51.100.13",
				DestPort:  443,
				Route:     "IN_REALITY_NOFLOW - DIRECT",
				Email:     "78",
				ToAddr:    []string{},
			},
		},
		{
			name: "from tcp prefix port 0 with udp dest",
			line: `2026/05/02 09:11:33.910002 from tcp:198.51.100.169:0 accepted udp:203.0.113.139:443 [IN_HU_DIRECT >> DIRECT] email: 851`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.910002",
				FromProto: "tcp",
				FromIP:    "198.51.100.169",
				FromPort:  0,
				Status:    "accepted",
				DestProto: "udp",
				DestHost:  "203.0.113.139",
				DestPort:  443,
				Route:     "IN_HU_DIRECT - DIRECT",
				Email:     "851",
				ToAddr:    []string{},
			},
		},
		{
			name: "ipv6 from brackets stripped from from_ip",
			line: `2026/05/02 09:11:33.820001 from [2001:db8::10]:4433 accepted tcp:alpha.example:443 [IN_V6 >> DIRECT] email: 77`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.820001",
				FromProto: "",
				FromIP:    "2001:db8::10",
				FromPort:  4433,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "alpha.example",
				DestPort:  443,
				Route:     "IN_V6 - DIRECT",
				Email:     "77",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp proto plus ipv6 from",
			line: `2026/05/02 09:11:33.830001 from tcp:[2001:db8::10]:4433 accepted tcp:[2001:db8::53]:443 [IN_V6 >> DIRECT] email: 77`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.830001",
				FromProto: "tcp",
				FromIP:    "2001:db8::10",
				FromPort:  4433,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "2001:db8::53",
				DestPort:  443,
				Route:     "IN_V6 - DIRECT",
				Email:     "77",
				ToAddr:    []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLogV2(t, tt.line, tt.want)
		})
	}
}

func TestParseLogV2_ToEndpointSplit(t *testing.T) {
	tests := []struct {
		name string
		line string
		want LogEntryV2
	}{
		{
			name: "tcp ipv4 dest",
			line: `2026/05/02 09:11:33.010001 from 203.0.113.1:1 accepted tcp:198.51.100.88:443 [IN >> DIRECT] email: 1`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.010001",
				FromIP:    "203.0.113.1",
				FromPort:  1,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "198.51.100.88",
				DestPort:  443,
				Route:     "IN - DIRECT",
				Email:     "1",
				ToAddr:    []string{},
			},
		},
		{
			name: "udp ipv4 dest",
			line: `2026/05/02 09:11:33.010002 from 203.0.113.1:1 accepted udp:9.9.9.9:53 [IN >> DIRECT] email: 1`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.010002",
				FromIP:    "203.0.113.1",
				FromPort:  1,
				Status:    "accepted",
				DestProto: "udp",
				DestHost:  "9.9.9.9",
				DestPort:  53,
				Route:     "IN - DIRECT",
				Email:     "1",
				ToAddr:    []string{},
			},
		},
		{
			name: "tcp domain dest",
			line: `2026/05/02 09:11:33.010003 from 203.0.113.1:1 accepted tcp:probe.example-cdn.net:443 [IN >> DIRECT] email: 1`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.010003",
				FromIP:    "203.0.113.1",
				FromPort:  1,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "probe.example-cdn.net",
				DestPort:  443,
				Route:     "IN - DIRECT",
				Email:     "1",
				ToAddr:    []string{},
			},
		},
		{
			name: "ipv6 destination brackets stripped from dest_host",
			line: `2026/05/02 09:11:33.810227 from 198.51.100.8:12001 accepted tcp:[2001:db8::53]:443 [IN_V6_EDGE >> DIRECT] email: 4802`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.810227",
				FromIP:    "198.51.100.8",
				FromPort:  12001,
				Status:    "accepted",
				DestProto: "tcp",
				DestHost:  "2001:db8::53",
				DestPort:  443,
				Route:     "IN_V6_EDGE - DIRECT",
				Email:     "4802",
				ToAddr:    []string{},
			},
		},
		{
			name: "udp ipv6 destination brackets stripped",
			line: `2026/05/02 09:11:33.840001 from 192.0.2.9:0 accepted udp:[2001:db8::53]:53 [IN_UDP_V6 >> DIRECT] email: 3`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.840001",
				FromIP:    "192.0.2.9",
				FromPort:  0,
				Status:    "accepted",
				DestProto: "udp",
				DestHost:  "2001:db8::53",
				DestPort:  53,
				Route:     "IN_UDP_V6 - DIRECT",
				Email:     "3",
				ToAddr:    []string{},
			},
		},
		{
			name: "dest without proto → empty dest_proto",
			line: `2026/05/02 09:11:33.910002 from 198.51.100.169:0 accepted 203.0.113.139:443 [IN_HU_DIRECT >> DIRECT] email: 851`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.910002",
				FromProto: "",
				FromIP:    "198.51.100.169",
				FromPort:  0,
				Status:    "accepted",
				DestProto: "",
				DestHost:  "203.0.113.139",
				DestPort:  443,
				Route:     "IN_HU_DIRECT - DIRECT",
				Email:     "851",
				ToAddr:    []string{},
			},
		},
		{
			name: "from tcp prefix and dest without proto",
			line: `2026/05/02 09:11:33.910002 from tcp:198.51.100.169:0 accepted 203.0.113.139:443 [IN_HU_DIRECT >> DIRECT] email: 851`,
			want: LogEntryV2{
				Datetime:  "2026-05-02 09:11:33.910002",
				FromProto: "tcp",
				FromIP:    "198.51.100.169",
				FromPort:  0,
				Status:    "accepted",
				DestProto: "",
				DestHost:  "203.0.113.139",
				DestPort:  443,
				Route:     "IN_HU_DIRECT - DIRECT",
				Email:     "851",
				ToAddr:    []string{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertParseLogV2(t, tt.line, tt.want)
		})
	}
}

func TestParseLogV2_RejectsUnparseable(t *testing.T) {
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
		{
			name: "from_ip is not a valid IP",
			line: `2026/05/02 09:11:34.100001 from not-an-ip:4433 accepted tcp:alpha.example:443 [IN >> DIRECT] email: 1`,
		},
		{
			name: "from_ip hostname with tcp prefix still invalid",
			line: `2026/05/02 09:11:34.100002 from tcp:client.example:4433 accepted tcp:alpha.example:443 [IN >> DIRECT] email: 1`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseLogV2(tt.line); err == nil {
				t.Fatal("parseLogV2() error = nil, want rejection")
			}
		})
	}
}

func TestParseLogV2_JSONContract(t *testing.T) {
	t.Run("ports are numbers and all keys present", func(t *testing.T) {
		line := `2026/05/02 09:11:33.880001 from tcp:203.0.113.47:4821 accepted tcp:198.51.100.88:443 [IN_TCP_XTLS_A7 >> DIRECT] email: 1204`
		got, err := parseLogV2(line)
		if err != nil {
			t.Fatalf("parseLogV2() error = %v", err)
		}
		got.ToAddr = []string{}

		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}

		want := `{"datetime":"2026-05-02 09:11:33.880001","email":"1204","from_proto":"tcp","from_ip":"203.0.113.47","from_port":4821,"dest_proto":"tcp","dest_host":"198.51.100.88","dest_port":443,"status":"accepted","route":"IN_TCP_XTLS_A7 - DIRECT","to_addr":[]}`
		if string(raw) != want {
			t.Fatalf("JSON contract\n got: %s\nwant: %s", raw, want)
		}
	})

	t.Run("empty optionals emit type defaults never null", func(t *testing.T) {
		line := `2026/05/02 09:11:33.601102 from 192.0.2.5:8080 accepted tcp:beta.example:443`
		got, err := parseLogV2(line)
		if err != nil {
			t.Fatalf("parseLogV2() error = %v", err)
		}
		got.ToAddr = []string{}

		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}

		want := `{"datetime":"2026-05-02 09:11:33.601102","email":"","from_proto":"","from_ip":"192.0.2.5","from_port":8080,"dest_proto":"tcp","dest_host":"beta.example","dest_port":443,"status":"accepted","route":"","to_addr":[]}`
		if string(raw) != want {
			t.Fatalf("JSON contract\n got: %s\nwant: %s", raw, want)
		}

		var asMap map[string]any
		if err := json.Unmarshal(raw, &asMap); err != nil {
			t.Fatalf("json.Unmarshal() error = %v", err)
		}
		for _, key := range []string{"email", "from_proto", "route", "to_addr"} {
			if asMap[key] == nil {
				t.Fatalf("key %q must not be null", key)
			}
		}
		if _, ok := asMap["from_port"].(float64); !ok {
			t.Fatalf("from_port must be a JSON number, got %T", asMap["from_port"])
		}
		if _, ok := asMap["dest_port"].(float64); !ok {
			t.Fatalf("dest_port must be a JSON number, got %T", asMap["dest_port"])
		}
		if _, ok := asMap["hostname"]; ok {
			t.Fatal("hostname must not be set by the parser")
		}
	})

	t.Run("from_port 0 and dest_port 0 serialized as numbers", func(t *testing.T) {
		line := `2026/05/02 09:11:33.700000 from 192.0.2.77:0 accepted tcp:alpha.example:0 [HU >> DIRECT] email: 1`
		got, err := parseLogV2(line)
		if err != nil {
			t.Fatalf("parseLogV2() error = %v", err)
		}
		got.ToAddr = []string{}

		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}

		want := `{"datetime":"2026-05-02 09:11:33.700000","email":"1","from_proto":"","from_ip":"192.0.2.77","from_port":0,"dest_proto":"tcp","dest_host":"alpha.example","dest_port":0,"status":"accepted","route":"HU - DIRECT","to_addr":[]}`
		if string(raw) != want {
			t.Fatalf("JSON contract\n got: %s\nwant: %s", raw, want)
		}
	})
}

func assertParseLogV2(t *testing.T, line string, want LogEntryV2) {
	t.Helper()

	got, err := parseLogV2(line)
	if err != nil {
		t.Fatalf("parseLogV2() error = %v", err)
	}

	// ToAddr comes from optional reverse DNS and is not part of the
	// structural parsing contract covered by these fixtures.
	got.ToAddr = []string{}
	if want.ToAddr == nil {
		want.ToAddr = []string{}
	}

	if !reflect.DeepEqual(*got, want) {
		t.Fatalf("parseLogV2()\n got: %+v\nwant: %+v", *got, want)
	}
}
