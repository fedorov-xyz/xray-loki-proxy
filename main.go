package main

import (
	"bytes"
	"encoding/base64"
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

func sendPushRequest(req *logproto.PushRequest) {
	data, err := proto.Marshal(req)
	if err != nil {
		logError("Error marshaling protobuf: %v", err)
		return
	}

	compressed := snappy.Encode(nil, data)

	client := &http.Client{}
	httpReq, err := http.NewRequest("POST", LOKI_ENDPOINT, bytes.NewReader(compressed))
	if err != nil {
		logError("Error creating request: %v", err)
		return
	}

	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	if LOKI_USERNAME != "" && LOKI_PASSWORD != "" {
		auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(LOKI_USERNAME+":"+LOKI_PASSWORD))
		httpReq.Header.Set("Authorization", auth)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		logError("Error forwarding logs: %v", err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	logInfo("Loki response: %s - %s", resp.Status, string(body))
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

	var streams []logproto.Stream

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
		var entries []logproto.Entry
		for _, entry := range stream.Entries {
			logEntry, err := parseLog(entry.Line)
			if err != nil {
				logWarn("Skipping unparsable log: %s", entry.Line)
				continue
			}

			if !isSkipped(logEntry, skipRules) {
				jsonData, err := json.Marshal(logEntry)
				if err != nil {
					logError("Error marshaling log entry: %v", err)
					continue
				}

				entries = append(entries, logproto.Entry{
					Timestamp: entry.Timestamp,
					Line:      string(jsonData),
				})
			}
		}

		if len(entries) > 0 {
			streams = append(streams, logproto.Stream{
				Labels:  stream.Labels,
				Entries: entries,
			})
		}
	}

	if len(streams) > 0 {
		req.Streams = streams
		sendPushRequest(&req)
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
