package main

import (
	"net"
	"strings"
)

const (
	ActionDrop  = "drop"
	ActionNoise = "noise"
)

type SkipRule struct {
	// Action is "drop" (default when empty) or "noise"
	Action string   `json:"action,omitempty"`
	Domain []string `json:"domain,omitempty"`
	IP     []string `json:"ip,omitempty"`
	Email  []string `json:"email,omitempty"`
	Route  []string `json:"route,omitempty"`
}

func isIPInRange(ip net.IP, pattern string) bool {
	if !strings.Contains(pattern, "/") {
		return ip.String() == pattern
	}
	_, ipnet, err := net.ParseCIDR(pattern)
	if err != nil {
		logError("Error parsing CIDR %s: %v", pattern, err)
		return false
	}
	return ipnet.Contains(ip)
}

func matchDomain(pattern, domain string) bool {
	pattern = strings.ToLower(pattern)
	domain = strings.ToLower(domain)

	if strings.HasPrefix(pattern, "full:") {
		return domain == strings.TrimPrefix(pattern, "full:")
	}

	if strings.HasPrefix(pattern, "domain:") {
		targetDomain := strings.TrimPrefix(pattern, "domain:")
		return domain == targetDomain || strings.HasSuffix(domain, "."+targetDomain)
	}

	return strings.Contains(domain, pattern)
}

// applySkipRules reports whether entry must be dropped. Any matching drop rule
// wins regardless of order; otherwise a matching noise rule sets Sink="noise".
func applySkipRules(entry *LogEntry, rules []SkipRule) bool {
	noise := ""
	for _, rule := range rules {
		reason := matchRule(entry, rule)
		if reason == "" {
			continue
		}
		if rule.Action == ActionNoise {
			if noise == "" {
				noise = reason
			}
			continue
		}
		logInfo("Skipping %s: %s", entry.DestHost, reason)
		return true
	}
	if noise != "" {
		// noise matches ~half of the traffic; keep it out of info logs.
		logDebug("Marking %s as noise: %s", entry.DestHost, noise)
		entry.Sink = ActionNoise
	}
	return false
}

// matchRule returns a description of the first matcher of rule that hits entry, or "".
func matchRule(entry *LogEntry, rule SkipRule) string {
	// cheap string matchers first
	for _, email := range rule.Email {
		if entry.Email == email {
			return "matched email rule: " + email
		}
	}

	for _, route := range rule.Route {
		if strings.Contains(entry.Route, route) {
			return "matched route rule: " + route
		}
	}

	if len(rule.IP) > 0 {
		if ip := net.ParseIP(entry.DestHost); ip != nil {
			for _, pattern := range rule.IP {
				if isIPInRange(ip, pattern) {
					return "matched IP rule: " + pattern
				}
			}
		}
	}

	for _, pattern := range rule.Domain {
		if matchDomain(pattern, entry.DestHost) {
			return "matched domain rule: " + pattern
		}
	}
	for _, address := range entry.ToAddr {
		for _, pattern := range rule.Domain {
			if matchDomain(pattern, address) {
				return "matched domain rule " + pattern + " via PTR " + address
			}
		}
	}

	return ""
}
