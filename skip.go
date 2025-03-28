package main

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

type Destination struct {
	Protocol string // tcp/udp
	Host     string // domain or IP
	Port     string // port number
}

func parseDestination(to string) (*Destination, error) {
	if u, err := url.Parse(to); err == nil && u.Host != "" {
		return &Destination{
			Protocol: "tcp",
			Host:     u.Hostname(),
			Port:     "443",
		}, nil
	}

	// Check IPv6 format: protocol:[ipv6]:port
	ipv6Regex := regexp.MustCompile(`^([^:]+):\[([^\]]+)\]:(.+)$`)
	if matches := ipv6Regex.FindStringSubmatch(to); matches != nil {
		return &Destination{
			Protocol: matches[1],
			Host:     matches[2],
			Port:     matches[3],
		}, nil
	}

	parts := strings.SplitN(to, ":", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid destination format: %s", to)
	}
	return &Destination{
		Protocol: parts[0],
		Host:     parts[1],
		Port:     parts[2],
	}, nil
}

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
	dest, err := parseDestination(entry.To)
	if err != nil {
		logWarn("Error parsing destination %s: %v", entry.To, err)
		return false
	}

	for _, rule := range rules {
		if len(rule.IP) > 0 {
			if ip := net.ParseIP(dest.Host); ip != nil {
				for _, pattern := range rule.IP {
					if isIPInRange(ip, pattern) {
						logInfo("Skipping %s: matched IP rule: %s", entry.To, pattern)
						return true
					}
				}
			}
		}

		if len(rule.Domain) > 0 {
			for _, pattern := range rule.Domain {
				if matchDomain(pattern, dest.Host) {
					logInfo("Skipping %s: matched domain rule: %s", entry.To, pattern)
					return true
				}
			}

			for _, address := range entry.ToAddr {
				for _, pattern := range rule.Domain {
					if matchDomain(pattern, address) {
						logInfo("Skipping %s: matched domain rule %s via PTR %s", entry.To, pattern, address)
						return true
					}
				}
			}
		}
	}

	return false
}
