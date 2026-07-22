package main

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TODO: `2025/02/01 22:33:25 from 92.62.56.223:0 rejected  proxy/vless/encoding: failed to read request version > websocket: close 1000 (normal)`

// LogEntry is the legacy NDJSON shape written to OUTPUT_FILE.
type LogEntry struct {
	Datetime string   `json:"datetime"`
	From     string   `json:"from"`
	Status   string   `json:"status"`
	To       string   `json:"to"`
	Route    string   `json:"route,omitempty"`
	Email    string   `json:"email,omitempty"`
	ToAddr   []string `json:"to_addr,omitempty"`
}

type LogEntryV2 struct {
	Datetime  string   `json:"datetime"`
	Email     string   `json:"email"`
	FromProto string   `json:"from_proto"`
	FromIP    string   `json:"from_ip"`
	FromPort  uint16   `json:"from_port"`
	DestProto string   `json:"dest_proto"`
	DestHost  string   `json:"dest_host"`
	DestPort  uint16   `json:"dest_port"`
	Status    string   `json:"status"`
	Route     string   `json:"route"`
	ToAddr    []string `json:"to_addr"`
}

const (
	xrayTimeLayout   = "2006/01/02 15:04:05.000000"
	outputTimeLayout = "2006-01-02 15:04:05.000000"
)

var routeArrowRegex = regexp.MustCompile(`\s*(?:==>|->|>>)\s*`)

func parseLog(logLine string) (*LogEntry, error) {
	groups, err := matchXrayLog(logLine)
	if err != nil {
		return nil, err
	}

	entry := &LogEntry{
		Datetime: groups["datetime"],
		From:     groups["from"],
		Status:   groups["status"],
		To:       groups["to"],
		Route:    normalizeRoute(groups["route"]),
		Email:    groups["email"],
	}

	if dest, err := parseDestination(groups["to"]); err == nil {
		entry.ToAddr = lookupToAddr(dest.Host)
	}
	return entry, nil
}

func parseLogV2(logLine string) (*LogEntryV2, error) {
	groups, err := matchXrayLog(logLine)
	if err != nil {
		return nil, err
	}

	datetime, err := formatDatetimeUTC(groups["datetime"])
	if err != nil {
		logWarn("Failed to parse datetime %q: %v", groups["datetime"], err)
		return nil, err
	}

	fromProto, fromIP, fromPort, err := parseFromEndpoint(groups["from"])
	if err != nil {
		logWarn("Failed to parse from endpoint %q: %v", groups["from"], err)
		return nil, err
	}

	destProto, destHost, destPort, err := parseToEndpoint(groups["to"])
	if err != nil {
		logWarn("Failed to parse to endpoint %q: %v", groups["to"], err)
		return nil, err
	}

	toAddr := lookupToAddr(destHost)
	if toAddr == nil {
		toAddr = []string{}
	}

	return &LogEntryV2{
		Datetime:  datetime,
		Email:     groups["email"],
		FromProto: fromProto,
		FromIP:    fromIP,
		FromPort:  fromPort,
		DestProto: destProto,
		DestHost:  destHost,
		DestPort:  destPort,
		Status:    groups["status"],
		Route:     normalizeRoute(groups["route"]),
		ToAddr:    toAddr,
	}, nil
}

func matchXrayLog(logLine string) (map[string]string, error) {
	match := xrayLogFormat.FindStringSubmatch(logLine)
	if match == nil {
		logWarn("Failed to parse log line: %s", logLine)
		return nil, fmt.Errorf("no match")
	}

	groups := make(map[string]string, len(xrayLogFormat.SubexpNames()))
	for i, name := range xrayLogFormat.SubexpNames() {
		if i > 0 && name != "" {
			groups[name] = match[i]
		}
	}
	return groups, nil
}

func normalizeRoute(route string) string {
	if route == "" {
		return ""
	}
	return routeArrowRegex.ReplaceAllString(route, " - ")
}

func formatDatetimeUTC(raw string) (string, error) {
	t, err := time.Parse(xrayTimeLayout, raw)
	if err != nil {
		return "", err
	}
	return t.UTC().Format(outputTimeLayout), nil
}

// parseFromEndpoint parses [tcp:|udp:]?<ip>:<port>.
// from_ip must be a valid IP; otherwise the line is rejected for v2.
func parseFromEndpoint(from string) (proto, ip string, port uint16, err error) {
	rest := from
	switch {
	case strings.HasPrefix(from, "tcp:"):
		proto = "tcp"
		rest = strings.TrimPrefix(from, "tcp:")
	case strings.HasPrefix(from, "udp:"):
		proto = "udp"
		rest = strings.TrimPrefix(from, "udp:")
	}

	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		return "", "", 0, fmt.Errorf("split host port: %w", err)
	}
	if net.ParseIP(host) == nil {
		return "", "", 0, fmt.Errorf("from_ip is not a valid IP: %s", host)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", "", 0, fmt.Errorf("from_port: %w", err)
	}
	return proto, host, uint16(p), nil
}

// parseToEndpoint parses [tcp:|udp:]?<host>:<port>.
// Missing proto prefix yields empty dest_proto (same as from).
func parseToEndpoint(to string) (proto, host string, port uint16, err error) {
	rest := to
	switch {
	case strings.HasPrefix(to, "tcp:"):
		proto = "tcp"
		rest = strings.TrimPrefix(to, "tcp:")
	case strings.HasPrefix(to, "udp:"):
		proto = "udp"
		rest = strings.TrimPrefix(to, "udp:")
	}

	host, portStr, err := net.SplitHostPort(rest)
	if err != nil {
		return "", "", 0, fmt.Errorf("split host port: %w", err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", "", 0, fmt.Errorf("dest_port: %w", err)
	}
	return proto, host, uint16(p), nil
}

func lookupToAddr(host string) []string {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return nil
	}
	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}
	return names
}
