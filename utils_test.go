package main

import (
	"testing"
)

func TestGetEnvBool(t *testing.T) {
	const key = "TEST_GET_ENV_BOOL"

	t.Run("unset uses fallback", func(t *testing.T) {
		// Unique key never set in the process.
		unsetKey := key + "_UNSET"
		if getEnvBool(unsetKey, true) != true {
			t.Fatal("expected fallback true")
		}
		if getEnvBool(unsetKey, false) != false {
			t.Fatal("expected fallback false")
		}
	})

	tests := []struct {
		value    string
		fallback bool
		want     bool
	}{
		{"true", false, true},
		{"TRUE", false, true},
		{"1", false, true},
		{"yes", false, true},
		{"on", false, true},
		{"false", true, false},
		{"0", true, false},
		{"no", true, false},
		{"off", true, false},
		{"  false  ", true, false},
		{"maybe", true, true},
		{"maybe", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			t.Setenv(key, tt.value)
			if got := getEnvBool(key, tt.fallback); got != tt.want {
				t.Fatalf("getEnvBool(%q, %v) = %v, want %v", tt.value, tt.fallback, got, tt.want)
			}
		})
	}
}
