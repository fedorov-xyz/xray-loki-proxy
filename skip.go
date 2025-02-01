package main

import (
	"fmt"
	"log"
	"net"
	"strings"
)

type Destination struct {
	Protocol string // tcp/udp
	Host     string // domain or IP
	Port     string // port number
}

func parseDestination(to string) (*Destination, error) {
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
		log.Printf("Error parsing CIDR %s: %v\n", pattern, err)
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

func isSkipped(to string, rules []SkipRule) bool {
	dest, err := parseDestination(to)
	if err != nil {
		log.Printf("Error parsing destination %s: %v\n", to, err)
		return false
	}

	for _, rule := range rules {
		if len(rule.IP) > 0 {
			if ip := net.ParseIP(dest.Host); ip != nil {
				for _, pattern := range rule.IP {
					if isIPInRange(ip, pattern) {
						log.Printf("Skipping %s: matched IP rule: %s\n", to, pattern)
						return true
					}
				}
			}
		}

		if len(rule.Domain) > 0 {
			for _, pattern := range rule.Domain {
				if matchDomain(pattern, dest.Host) {
					log.Printf("Skipping %s: matched domain rule: %s\n", to, pattern)
					return true
				}
			}
		}
	}

	return false
}
