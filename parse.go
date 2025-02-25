package main

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// TODO: `2025/02/01 22:33:25 from 92.62.56.223:0 rejected  proxy/vless/encoding: failed to read request version > websocket: close 1000 (normal)`

type LogEntry struct {
	Datetime string   `json:"datetime"`
	From     string   `json:"from"`
	Status   string   `json:"status"`
	To       string   `json:"to"`
	Route    string   `json:"route,omitempty"`
	Email    string   `json:"email,omitempty"`
	ToAddr   []string `json:"to_addr,omitempty"`
}

var routeArrowRegex = regexp.MustCompile(`(?:==>|->|>>)`)

func parseLog(logLine string) (*LogEntry, error) {
	match := xrayLogFormat.FindStringSubmatch(logLine)
	if match == nil {
		logWarn("Failed to parse log line: %s", logLine)
		return nil, fmt.Errorf("no match")
	}

	groups := make(map[string]string)
	for i, name := range xrayLogFormat.SubexpNames() {
		if i > 0 && name != "" {
			groups[name] = match[i]
		}
	}

	entry := &LogEntry{
		Datetime: groups["datetime"],
		From:     groups["from"],
		Status:   groups["status"],
		To:       groups["to"],
		Route:    routeArrowRegex.ReplaceAllString(groups["route"], "-"),
		Email:    groups["email"],
	}

	if dest, err := parseDestination(groups["to"]); err == nil {
		if ip := net.ParseIP(dest.Host); ip != nil {
			names, err := net.LookupAddr(ip.String())
			if err == nil && len(names) > 0 {
				for i := range names {
					names[i] = strings.TrimSuffix(names[i], ".")
				}
				entry.ToAddr = names
			}
		}
	}

	return entry, nil
}
