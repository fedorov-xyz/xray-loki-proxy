package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"
)

var LISTEN_HOST = getEnv("LISTEN_HOST", "0.0.0.0")
var LISTEN_PORT = getEnv("LISTEN_PORT", "8080")
var OUTPUT_FILE = getEnv("OUTPUT_FILE", "")
var VECTOR_ENDPOINT = getEnv("VECTOR_ENDPOINT", "")

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

func validateSinkConfig() error {
	hasFile := OUTPUT_FILE != ""
	hasVector := VECTOR_ENDPOINT != ""
	switch {
	case hasFile && hasVector:
		return fmt.Errorf("set exactly one of OUTPUT_FILE or VECTOR_ENDPOINT, not both")
	case !hasFile && !hasVector:
		return fmt.Errorf("set exactly one of OUTPUT_FILE or VECTOR_ENDPOINT")
	default:
		return nil
	}
}

func appendJSONLine(path string, entry any) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	jsonData, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	if _, err := f.WriteString(string(jsonData) + "\n"); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func main() {
	if err := validateSinkConfig(); err != nil {
		logError("%v", err)
		os.Exit(1)
	}

	if err := loadSkipRules(); err != nil {
		logError("Failed to load skip rules: %v", err)
		os.Exit(1)
	}

	startTorrentNotifier()

	addr := fmt.Sprintf("%s:%s", LISTEN_HOST, LISTEN_PORT)

	http.HandleFunc("/vector/ingest", vectorIngestHandler)

	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/healthy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if OUTPUT_FILE != "" {
		logInfo("Server started on %s (sink=file path=%s)", addr, OUTPUT_FILE)
	} else {
		logInfo("Server started on %s (sink=vector endpoint=%s)", addr, VECTOR_ENDPOINT)
	}

	if err := srv.ListenAndServe(); err != nil {
		logError("Server failed: %v", err)
		os.Exit(1)
	}
}
