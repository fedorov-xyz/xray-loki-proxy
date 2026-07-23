package main

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TODO: `2025/02/01 22:33:25 from 92.62.56.223:0 rejected  proxy/vless/encoding: failed to read request version > websocket: close 1000 (normal)`

type LogEntry struct {
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
	// maxToAddrNames caps PTR results; CDN IPs often return dozens of names.
	maxToAddrNames = 5
	// ptrLookupTimeout bounds reverse DNS on the ingest path only.
	ptrLookupTimeout = 500 * time.Millisecond
)

// ptrDNSServers used by the reverse-DNS path (Cloudflare, Google).
var ptrDNSServers = []string{
	"1.1.1.1:53",
	"1.0.0.1:53",
	"8.8.8.8:53",
	"8.8.4.4:53",
}

// ptrResolver performs PTR lookups via ptrDNSServers (not the system resolver).
var ptrResolver = newPTRResolver(ptrDNSServers)

var routeArrowRegex = regexp.MustCompile(`\s*(?:==>|->|>>)\s*`)

func newPTRResolver(servers []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: ptrLookupTimeout}
			var lastErr error
			for _, server := range servers {
				conn, err := d.DialContext(ctx, network, server)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, lastErr
		},
	}
}

func parseLog(logLine string) (*LogEntry, error) {
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

	toAddr := lookupToAddrTimed(destHost)
	if toAddr == nil {
		toAddr = []string{}
	}

	return &LogEntry{
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
// from_ip must be a valid IP; otherwise the line is rejected.
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

// lookupToAddrTimed is used by the ingest path so a slow resolver cannot
// stall an HTTP ingest batch indefinitely.
func lookupToAddrTimed(host string) []string {
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), ptrLookupTimeout)
	defer cancel()

	names, err := ptrResolver.LookupAddr(ctx, ip.String())
	if err != nil || len(names) == 0 {
		return nil
	}
	return normalizeToAddr(names)
}

func normalizeToAddr(names []string) []string {
	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}
	if len(names) > maxToAddrNames {
		names = names[:maxToAddrNames]
	}
	return names
}
