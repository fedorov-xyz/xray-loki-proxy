package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const (
	// vectorScannerMaxLine caps a single raw log line at ~1 MB.
	vectorScannerMaxLine = 1 << 20
	// vectorMaxBodyBytes caps an entire ingest request body (NDJSON batch).
	vectorMaxBodyBytes = 32 << 20
	// vectorParseConcurrency limits parallel line parsers (PTR-bound).
	vectorParseConcurrency = 32
	vectorContentType      = "application/x-ndjson"
)

var vectorHTTPClient = &http.Client{Timeout: 30 * time.Second}

// forwardedBatches remembers sha256 of bodies already emitted successfully.
var forwardedBatches sync.Map // batchID(string) -> struct{}

// processLine parses a raw Xray access log line into a structured event.
// Returns nil when the line should be skipped/filtered.
func processLine(line string) (*LogEntry, error) {
	entry, err := parseLog(line)
	if err != nil {
		return nil, err
	}

	notifyTorrentIfNeeded(entry)

	if isSkipped(entry, skipRules) {
		return nil, nil
	}

	return entry, nil
}

// processLinesParallel parses lines concurrently (bounded) and returns a dense
// list of events to forward, preserving input order.
func processLinesParallel(rawLines []string) []*LogEntry {
	slots := make([]*LogEntry, len(rawLines))
	sem := make(chan struct{}, vectorParseConcurrency)
	var wg sync.WaitGroup

	for i, line := range rawLines {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, line string) {
			defer wg.Done()
			defer func() { <-sem }()

			entry, err := processLine(line)
			if err != nil {
				logWarn("Skipping unparsable log: %s", line)
				return
			}
			if entry != nil {
				slots[i] = entry
			}
		}(i, line)
	}
	wg.Wait()

	out := make([]*LogEntry, 0, len(rawLines))
	for _, entry := range slots {
		if entry != nil {
			out = append(out, entry)
		}
	}
	return out
}

// hashBatch returns a stable content id for the raw HTTP body.
func hashBatch(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func emitBatch(entries []*LogEntry) error {
	if len(entries) == 0 {
		return nil
	}

	if OUTPUT_FILE != "" {
		for _, entry := range entries {
			if err := appendJSONLine(OUTPUT_FILE, entry); err != nil {
				return fmt.Errorf("write file: %w", err)
			}
		}
		return nil
	}

	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	for _, entry := range entries {
		if err := encoder.Encode(entry); err != nil {
			return fmt.Errorf("encode: %w", err)
		}
	}
	if err := forwardToVector(buf.Bytes()); err != nil {
		return fmt.Errorf("forward: %w", err)
	}
	return nil
}

// vectorIngestHandler reads a newline-delimited batch of raw Xray log lines,
// processes each one, and emits the surviving events to the configured sink.
func vectorIngestHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	r.Body = http.MaxBytesReader(w, r.Body, vectorMaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		status := http.StatusInternalServerError
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			status = http.StatusRequestEntityTooLarge
		}
		logError("vector_ingest batch=- status=%d total=%s err=body: %v", status, time.Since(start), err)
		http.Error(w, "Error reading request body", status)
		return
	}

	batchID := hashBatch(body)
	if _, ok := forwardedBatches.Load(batchID); ok {
		w.WriteHeader(http.StatusOK)
		logDebug("vector_ingest batch=%s status=%d dedup=1 total=%s",
			batchID, http.StatusOK, time.Since(start))
		return
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 64*1024), vectorScannerMaxLine)
	rawLines := make([]string, 0, 256)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		rawLines = append(rawLines, line)
	}
	if err := scanner.Err(); err != nil {
		logError("vector_ingest batch=%s status=%d total=%s err=scan: %v",
			batchID, http.StatusInternalServerError, time.Since(start), err)
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	parseStart := time.Now()
	parsed := processLinesParallel(rawLines)
	parseDur := time.Since(parseStart)
	forwarded := len(parsed)
	skipped := len(rawLines) - forwarded

	var emitDur time.Duration
	if forwarded > 0 {
		t0 := time.Now()
		if err := emitBatch(parsed); err != nil {
			emitDur = time.Since(t0)
			status := http.StatusBadGateway
			if OUTPUT_FILE != "" {
				status = http.StatusInternalServerError
			}
			logError("vector_ingest batch=%s status=%d lines=%d skipped=%d forwarded=%d parse=%s emit=%s total=%s err=emit: %v",
				batchID, status, len(rawLines), skipped, forwarded, parseDur, emitDur, time.Since(start), err)
			http.Error(w, "Error emitting events", status)
			return
		}
		emitDur = time.Since(t0)
		forwardedBatches.Store(batchID, struct{}{})
	}

	w.WriteHeader(http.StatusOK)
	logDebug("vector_ingest batch=%s status=%d lines=%d skipped=%d forwarded=%d parse=%s emit=%s total=%s",
		batchID, http.StatusOK, len(rawLines), skipped, forwarded, parseDur, emitDur, time.Since(start))
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
