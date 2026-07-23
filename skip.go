package main

import (
	"net"
	"strings"
)

type SkipRule struct {
	Domain []string `json:"domain,omitempty"`
	IP     []string `json:"ip,omitempty"`
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

func isSkipped(entry *LogEntry, rules []SkipRule) bool {
	return matchSkipRules(entry.DestHost, entry.DestHost, entry.ToAddr, rules)
}

func matchSkipRules(label, host string, toAddr []string, rules []SkipRule) bool {
	for _, rule := range rules {
		if len(rule.IP) > 0 {
			if ip := net.ParseIP(host); ip != nil {
				for _, pattern := range rule.IP {
					if isIPInRange(ip, pattern) {
						logInfo("Skipping %s: matched IP rule: %s", label, pattern)
						return true
					}
				}
			}
		}

		if len(rule.Domain) > 0 {
			for _, pattern := range rule.Domain {
				if matchDomain(pattern, host) {
					logInfo("Skipping %s: matched domain rule: %s", label, pattern)
					return true
				}
			}

			for _, address := range toAddr {
				for _, pattern := range rule.Domain {
					if matchDomain(pattern, address) {
						logInfo("Skipping %s: matched domain rule %s via PTR %s", label, pattern, address)
						return true
					}
				}
			}
		}
	}

	return false
}
