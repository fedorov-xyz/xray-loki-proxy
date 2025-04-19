package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/grafana/loki/pkg/logproto"
)

var LOKI_ENDPOINT = getEnv("LOKI_ENDPOINT", "")
var LOKI_USERNAME = getEnv("LOKI_USERNAME", "")
var LOKI_PASSWORD = getEnv("LOKI_PASSWORD", "")
var LISTEN_HOST = getEnv("LISTEN_HOST", "0.0.0.0")
var LISTEN_PORT = getEnv("LISTEN_PORT", "8080")
var OUTPUT_FILE = getEnv("OUTPUT_FILE", "")

const SKIP_RULES_PATH = "/etc/xray-loki-proxy/skip-rules.json"

/* https://github.com/XTLS/Xray-core/blob/main/common/log/access.go */
var xrayLogFormat = regexp.MustCompile(`^(?P<datetime>\S+\s+\S+)\s*?(from\s)?(?P<from>\S+)\s+(?P<status>\S+)\s+(?P<to>\S+)(?:\s+\[(?P<route>.*?)\])?(?:\s+email:\s+(?P<email>\S+))?$`)

var skipRules []SkipRule

func loadSkipRules() error {
	data, err := os.ReadFile(SKIP_RULES_PATH)
	if err != nil {
		if os.IsNotExist(err) {
			logInfo("Skip rules file not found at %s, continuing without rules", SKIP_RULES_PATH)
			return nil
		}
		return fmt.Errorf("error reading skip rules file: %v", err)
	}

	if err := json.Unmarshal(data, &skipRules); err != nil {
		return fmt.Errorf("error parsing skip rules: %v", err)
	}

	logInfo("Loaded skip rules from %s", SKIP_RULES_PATH)
	return nil
}

func writeToFile(entry *LogEntry) {
	if OUTPUT_FILE == "" {
		logError("OUTPUT_FILE environment variable is not set")
		return
	}

	f, err := os.OpenFile(OUTPUT_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logError("Error opening file: %v", err)
		return
	}
	defer f.Close()

	jsonData, err := json.Marshal(entry)
	if err != nil {
		logError("Error marshaling log entry: %v", err)
		return
	}

	if _, err := f.WriteString(string(jsonData) + "\n"); err != nil {
		logError("Error writing to file: %v", err)
		return
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		logError("Error reading body: %v", err)
		http.Error(w, "Error reading body", http.StatusBadRequest)
		return
	}

	if r.Header.Get("Content-Type") != "application/x-protobuf" {
		logWarn("Only protobuf requests are supported")
		http.Error(w, "Only protobuf requests are supported", http.StatusNotImplemented)
		return
	}

	decoded, err := snappy.Decode(nil, body)
	if err != nil {
		logError("Error decoding snappy: %v", err)
		http.Error(w, "Error decoding snappy", http.StatusBadRequest)
		return
	}

	var req logproto.PushRequest
	if err := proto.Unmarshal(decoded, &req); err != nil {
		logError("Error unmarshaling protobuf: %v", err)
		http.Error(w, "Error unmarshaling protobuf", http.StatusBadRequest)
		return
	}

	for _, stream := range req.Streams {
		for _, entry := range stream.Entries {
			logEntry, err := parseLog(entry.Line)
			if err != nil {
				logWarn("Skipping unparsable log: %s", entry.Line)
				continue
			}

			notifyTorrentIfNeeded(logEntry)

			if !isSkipped(logEntry, skipRules) {
				writeToFile(logEntry)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	if err := loadSkipRules(); err != nil {
		logError("Failed to load skip rules: %v", err)
		os.Exit(1)
	}

	addr := fmt.Sprintf("%s:%s", LISTEN_HOST, LISTEN_PORT)

	http.HandleFunc("/loki/api/v1/push", handler)

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/healthy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	logInfo("Server started on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		logError("Server failed: %v", err)
		os.Exit(1)
	}
}
