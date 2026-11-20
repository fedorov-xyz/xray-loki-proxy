package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sync"
	"syscall"
	"time"
)

var LISTEN_HOST = getEnv("LISTEN_HOST", "0.0.0.0")
var LISTEN_PORT = getEnv("LISTEN_PORT", "8080")
var OUTPUT_FILE = getEnv("OUTPUT_FILE", "")
var VECTOR_ENDPOINT = getEnv("VECTOR_ENDPOINT", "")
var skipRulesEnabled = getEnvBool("SKIP_RULES_ENABLED", true)

const SKIP_RULES_PATH = "/etc/xray-loki-proxy/skip-rules.json"

/* https://github.com/XTLS/Xray-core/blob/main/common/log/access.go */
var xrayLogFormat = regexp.MustCompile(`^(?P<datetime>\S+\s+\S+)\s*?(from\s)?(?P<from>\S+)\s+(?P<status>\S+)\s+(?P<to>\S+)(?:\s+\[(?P<route>.*?)\])?(?:\s+email:\s+(?P<email>\S+))?$`)

var skipRules []SkipRule
var skipRulesMu sync.RWMutex // guards skipRules against SIGHUP reloads

func currentSkipRules() []SkipRule {
	skipRulesMu.RLock()
	defer skipRulesMu.RUnlock()
	return skipRules
}

// loadSkipRules (re)reads SKIP_RULES_PATH; on error the current rules stay in place.
func loadSkipRules() error {
	if !skipRulesEnabled {
		logInfo("Skip rules disabled (SKIP_RULES_ENABLED=false)")
		return nil
	}

	data, err := os.ReadFile(SKIP_RULES_PATH)
	if err != nil {
		if os.IsNotExist(err) {
			logInfo("Skip rules file not found at %s, continuing without rules", SKIP_RULES_PATH)
			setSkipRules(nil)
			return nil
		}
		return fmt.Errorf("error reading skip rules file: %v", err)
	}

	var rules []SkipRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return fmt.Errorf("error parsing skip rules: %v", err)
	}
	for i, rule := range rules {
		if rule.Action != "" && rule.Action != ActionDrop && rule.Action != ActionNoise {
			return fmt.Errorf("skip rule #%d: unknown action %q (want %q or %q)", i, rule.Action, ActionDrop, ActionNoise)
		}
	}

	setSkipRules(rules)
	logInfo("Loaded %d skip rules from %s", len(rules), SKIP_RULES_PATH)
	return nil
}

func setSkipRules(rules []SkipRule) {
	skipRulesMu.Lock()
	skipRules = rules
	skipRulesMu.Unlock()
}

func reloadOnSIGHUP() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			logInfo("SIGHUP received, reloading skip rules")
			if err := loadSkipRules(); err != nil {
				logError("Skip rules reload failed, keeping previous rules: %v", err)
			}
		}
	}()
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
	reloadOnSIGHUP()

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
