package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

var TORRENT_TAG = getEnv("TORRENT_TAG", "")
var TORRENT_NOTIFY_URL = getEnv("TORRENT_NOTIFY_URL", "")

func notifyTorrentIfNeeded(entry *LogEntry) {
	if TORRENT_TAG == "" || TORRENT_NOTIFY_URL == "" {
		return
	}

	if !strings.Contains(entry.Route, TORRENT_TAG) {
		return
	}

	if _, err := url.ParseRequestURI(TORRENT_NOTIFY_URL); err != nil {
		logError("Invalid TORRENT_NOTIFY_URL: %v", err)
		return
	}

	jsonData, err := json.Marshal(entry)
	if err != nil {
		logError("Error marshaling torrent notification: %v", err)
		return
	}

	resp, err := http.Post(TORRENT_NOTIFY_URL, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		logError("Error sending torrent notification: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logError("Torrent notification failed with status: %s", resp.Status)
	} else {
		logInfo("Torrent notification sent for %s", entry.To)
	}
}
