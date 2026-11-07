package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestApplySkipRules(t *testing.T) {
	newEntry := func() *LogEntry {
		return &LogEntry{
			Email:    "4417",
			DestHost: "198.51.100.73",
			Route:    "IN_TCP_EDGE_3 - DIRECT",
			ToAddr:   []string{"host-73.cdn-example.net"},
		}
	}

	drop := SkipRule{Action: ActionDrop, IP: []string{"198.51.100.0/24"}}
	noise := SkipRule{Action: ActionNoise, Email: []string{"4417"}}

	tests := []struct {
		name     string
		rules    []SkipRule
		wantDrop bool
		wantSink string
	}{
		{"no rules", nil, false, ""},
		{"rule without action drops", []SkipRule{{IP: []string{"198.51.100.73"}}}, true, ""},
		{"drop before noise", []SkipRule{drop, noise}, true, ""},
		{"noise before drop", []SkipRule{noise, drop}, true, ""},
		{"noise by email", []SkipRule{noise}, false, ActionNoise},
		{"email is exact match", []SkipRule{{Action: ActionNoise, Email: []string{"441"}}}, false, ""},
		{"noise by route substring", []SkipRule{{Action: ActionNoise, Route: []string{"EDGE_3 - DIRECT"}}}, false, ActionNoise},
		{"drop by route", []SkipRule{{Route: []string{"IN_TCP_EDGE"}}}, true, ""},
		{"noise by domain via PTR", []SkipRule{{Action: ActionNoise, Domain: []string{"domain:cdn-example.net"}}}, false, ActionNoise},
		{"no matcher hits", []SkipRule{{Action: ActionNoise, Email: []string{"9999"}, Route: []string{"BLOCK"}}}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := newEntry()
			if got := applySkipRules(e, tt.rules); got != tt.wantDrop {
				t.Fatalf("drop = %v, want %v", got, tt.wantDrop)
			}
			if !tt.wantDrop && e.Sink != tt.wantSink {
				t.Fatalf("sink = %q, want %q", e.Sink, tt.wantSink)
			}
		})
	}
}

func TestProcessLine_NoiseSinkJSON(t *testing.T) {
	prevRules, prevEnabled := skipRules, skipRulesEnabled
	t.Cleanup(func() { skipRules, skipRulesEnabled = prevRules, prevEnabled })

	line := `2026/07/23 10:11:12.100000 from 203.0.113.61:5120 accepted tcp:192.0.2.44:443 [IN_NOISE_5 >> DIRECT] email: 3381`
	skipRules = []SkipRule{{Action: ActionNoise, Email: []string{"3381"}}}

	tests := []struct {
		name    string
		enabled bool
		rules   []SkipRule
		want    string // substring expected in JSON, or "" for no sink field
	}{
		{"noise line has sink", true, skipRules, `"sink":"noise"`},
		{"unmatched line has no sink", true, []SkipRule{{Action: ActionNoise, Email: []string{"1"}}}, ""},
		{"disabled rules leave no sink", false, skipRules, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			skipRules, skipRulesEnabled = tt.rules, tt.enabled
			e, err := processLine(line)
			if err != nil || e == nil {
				t.Fatalf("processLine = %v, %v", e, err)
			}
			b, _ := json.Marshal(e)
			if tt.want == "" && strings.Contains(string(b), `"sink"`) {
				t.Fatalf("unexpected sink field: %s", b)
			}
			if tt.want != "" && !strings.Contains(string(b), tt.want) {
				t.Fatalf("want %s in %s", tt.want, b)
			}
		})
	}
}
