package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaskNeverRevealsWholeValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"ab", "**"},
		{"abcd", "****"},
		{"static-poc-key-001", "stat**************"},
	}
	for _, c := range cases {
		got := mask(c.in)
		if got != c.want {
			t.Errorf("mask(%q) = %q, want %q", c.in, got, c.want)
		}
		if len(c.in) > 4 && strings.Contains(got, c.in[4:]) {
			t.Errorf("mask(%q) leaked the tail of the value", c.in)
		}
	}
}

func TestLoadConfigRequiresBothVars(t *testing.T) {
	cases := []struct {
		name     string
		greeting string
		apiKey   string
		wantErr  bool
	}{
		{"both set", "hello", "key", false},
		{"greeting missing", "", "key", true},
		{"api key missing", "hello", "", true},
		{"both missing", "", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(greetingEnv, c.greeting)
			t.Setenv(apiKeyEnv, c.apiKey)

			_, err := loadConfig()
			if (err != nil) != c.wantErr {
				t.Fatalf("loadConfig() err = %v, wantErr = %v", err, c.wantErr)
			}
			// A failure message that quotes the value would defeat the point.
			if err != nil && (strings.Contains(err.Error(), c.apiKey) && c.apiKey != "") {
				t.Errorf("error message leaked the api key: %v", err)
			}
		})
	}
}

// The /secret response is the demo surface. It must never carry the raw key.
func TestSecretHandlerMasksAPIKey(t *testing.T) {
	const rawKey = "static-poc-key-001"
	t.Setenv(greetingEnv, "hello from the platform")
	t.Setenv(apiKeyEnv, rawKey)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}

	rec := httptest.NewRecorder()
	writeJSON(rec, map[string]any{
		"greeting":       cfg.greeting,
		"api_key_masked": mask(cfg.apiKey),
		"api_key_len":    len(cfg.apiKey),
	})

	body := rec.Body.String()
	if strings.Contains(body, rawKey) {
		t.Fatalf("/secret response contained the raw api key: %s", body)
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got["api_key_masked"] != "stat**************" {
		t.Errorf("unexpected mask: %v", got["api_key_masked"])
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d", rec.Code)
	}
}
