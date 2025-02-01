package main

import (
	"fmt"
	"log"
	"regexp"
	"strings"
)

type LogEntry struct {
	Datetime string `json:"datetime"`
	From     string `json:"from"`
	Status   string `json:"status"`
	To       string `json:"to"`
	Route    string `json:"route,omitempty"`
	ID       string `json:"id,omitempty"`
	Username string `json:"username,omitempty"`
}

var routeArrowRegex = regexp.MustCompile(`(?:==>|->|>>)`)

func parseLog(logLine string) (*LogEntry, error) {
	match := xrayLogFormat.FindStringSubmatch(logLine)
	if match == nil {
		log.Printf("Failed to parse log line: %s\n", logLine)
		return nil, fmt.Errorf("no match")
	}

	groups := make(map[string]string)
	for i, name := range xrayLogFormat.SubexpNames() {
		if i > 0 && name != "" {
			groups[name] = match[i]
		}
	}

	emailParts := strings.SplitN(groups["email"], ".", 2)
	id, username := "", ""
	if len(emailParts) == 2 {
		id, username = emailParts[0], emailParts[1]
	}

	return &LogEntry{
		Datetime: groups["datetime"],
		From:     groups["from"],
		Status:   groups["status"],
		To:       groups["to"],
		Route:    routeArrowRegex.ReplaceAllString(groups["route"], "-"),
		ID:       id,
		Username: username,
	}, nil
}
