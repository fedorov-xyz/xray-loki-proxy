package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var TORRENT_TAG = getEnv("TORRENT_TAG", "")
var TORRENT_NOTIFY_URL = getEnv("TORRENT_NOTIFY_URL", "")

const torrentBatchMax = 1000
const torrentBatchInterval = 20 * time.Second

type torrentBatcher struct {
	notifyURL string
	client    *http.Client

	mu    sync.Mutex
	queue []LogEntry
}

var torrentNotifier *torrentBatcher

func startTorrentNotifier() {
	if TORRENT_TAG == "" || TORRENT_NOTIFY_URL == "" {
		return
	}

	if _, err := url.ParseRequestURI(TORRENT_NOTIFY_URL); err != nil {
		logError("Invalid TORRENT_NOTIFY_URL: %v", err)
		return
	}

	torrentNotifier = &torrentBatcher{
		notifyURL: TORRENT_NOTIFY_URL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		queue: make([]LogEntry, 0, torrentBatchMax),
	}

	go torrentNotifier.run()
}

func (b *torrentBatcher) run() {
	ticker := time.NewTicker(torrentBatchInterval)
	defer ticker.Stop()
	for range ticker.C {
		b.flush()
	}
}

func (b *torrentBatcher) enqueue(entry *LogEntry) {
	var batch []LogEntry

	b.mu.Lock()
	b.queue = append(b.queue, *entry)
	if len(b.queue) >= torrentBatchMax {
		batch = b.queue
		b.queue = make([]LogEntry, 0, torrentBatchMax)
	}
	b.mu.Unlock()

	if len(batch) > 0 {
		go b.send(batch)
	}
}

func (b *torrentBatcher) flush() {
	b.mu.Lock()
	if len(b.queue) == 0 {
		b.mu.Unlock()
		return
	}
	batch := b.queue
	b.queue = make([]LogEntry, 0, torrentBatchMax)
	b.mu.Unlock()

	b.send(batch)
}

func (b *torrentBatcher) send(batch []LogEntry) {
	jsonData, err := json.Marshal(batch)
	if err != nil {
		logError("Error marshaling torrent batch: %v", err)
		return
	}

	resp, err := b.client.Post(b.notifyURL, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		logError("Error sending torrent batch: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logError("Torrent batch notification failed with status: %s", resp.Status)
		return
	}

	logInfo("Torrent batch notification sent: %d entries", len(batch))
}

func notifyTorrentIfNeeded(entry *LogEntry) {
	if torrentNotifier == nil {
		return
	}

	if !strings.Contains(entry.Route, TORRENT_TAG) {
		return
	}

	torrentNotifier.enqueue(entry)
}
