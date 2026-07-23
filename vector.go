package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

var VECTOR_ENDPOINT = getEnv("VECTOR_ENDPOINT", "http://vector:8080")

const (
	// vectorScannerMaxLine caps a single raw log line at ~1 MB.
	vectorScannerMaxLine = 1 << 20
	vectorContentType    = "application/x-ndjson"
)

var vectorHTTPClient = &http.Client{Timeout: 30 * time.Second}

// processLine parses a raw Xray access log line into a v2 event.
// The bool reports whether the event should be forwarded (false → skip/filter).
func processLine(line string) (*LogEntryV2, bool, error) {
	legacy, err := parseLog(line)
	if err != nil {
		return nil, false, err
	}

	notifyTorrentIfNeeded(legacy)

	if isSkipped(legacy, skipRules) {
		return nil, false, nil
	}

	entryV2, err := parseLogV2(line)
	if err != nil {
		return nil, false, err
	}

	return entryV2, true, nil
}

// vectorIngestHandler reads a newline-delimited batch of raw Xray log lines,
// processes each one, and forwards the surviving v2 events to Vector as NDJSON.
func vectorIngestHandler(w http.ResponseWriter, r *http.Request) {
	scanner := bufio.NewScanner(r.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), vectorScannerMaxLine)

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)

	forwarded := 0
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		entryV2, keep, err := processLine(line)
		if err != nil {
			logWarn("Skipping unparsable log: %s", line)
			continue
		}
		if !keep {
			continue
		}

		if err := encoder.Encode(entryV2); err != nil {
			logError("Error encoding event: %v", err)
			http.Error(w, "Error encoding event", http.StatusInternalServerError)
			return
		}
		forwarded++
	}

	if err := scanner.Err(); err != nil {
		logError("Error reading request body: %v", err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	if forwarded > 0 {
		if err := forwardToVector(buf.Bytes()); err != nil {
			logError("Error forwarding to Vector: %v", err)
			http.Error(w, "Error forwarding to Vector", http.StatusBadGateway)
			return
		}
	}

	w.WriteHeader(http.StatusOK)
}

func forwardToVector(payload []byte) error {
	req, err := http.NewRequest(http.MethodPost, VECTOR_ENDPOINT, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", vectorContentType)

	resp, err := vectorHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("post to vector: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("vector returned status %d", resp.StatusCode)
	}
	return nil
}
