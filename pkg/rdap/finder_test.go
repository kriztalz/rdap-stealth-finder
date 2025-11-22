package rdap

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test data based on real RDAP responses

const mockRDAPBootstrap = `{
  "description": "RDAP bootstrap file for DNS",
  "publication": "2024-01-01T00:00:00Z",
  "services": [
    [
      ["com", "net"],
      ["https://rdap.verisign.com/com/v1/"]
    ],
    [
      ["org"],
      ["https://rdap.publicinterestregistry.org/rdap/"]
    ]
  ]
}`

const mockTLDList = `# Version 2025112200, Last Updated Sat Nov 22 07:07:01 2025 UTC
AAA
AARP
ABB
ABBOTT
ABBVIE`

// TestNewFinder tests Finder creation
func TestNewFinder(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name        string
		concurrency int
		timeout     int
		logger      *slog.Logger
	}{
		{
			name:        "valid config",
			concurrency: 5,
			timeout:     10,
			logger:      logger,
		},
		{
			name:        "with defaults",
			concurrency: 0,
			timeout:     0,
			logger:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finder := NewFinder(tt.concurrency, tt.timeout, tt.logger)

			if finder == nil {
				t.Errorf("NewFinder() returned nil finder")
				return
			}

			// Check defaults were applied
			if finder.concurrency <= 0 {
				t.Errorf("concurrency not set properly: %d", finder.concurrency)
			}
			if finder.timeoutSeconds <= 0 {
				t.Errorf("timeoutSeconds not set properly: %d", finder.timeoutSeconds)
			}
			if finder.logger == nil {
				t.Errorf("logger not set")
			}
			if finder.httpClient == nil {
				t.Errorf("httpClient not set")
			}
		})
	}
}

// TestFinderWithMockServer tests Finder with mock HTTP server
func TestFinderWithMockServer(t *testing.T) {
	// Create a mock server that emulates RDAP responses
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/tlds-alpha-by-domain.txt"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockTLDList))
		case strings.Contains(r.URL.Path, "/rdap/dns.json"):
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mockRDAPBootstrap))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockServer.Close()

	logger := slog.Default()

	t.Run("basic HTTP request", func(t *testing.T) {
		finder := NewFinder(1, 10, logger)
		if finder == nil {
			t.Fatalf("NewFinder() returned nil")
		}

		// Test fetching TLDs
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, mockServer.URL+"/tlds-alpha-by-domain.txt", nil)
		if err != nil {
			t.Fatalf("NewRequest error: %v", err)
		}

		resp, err := finder.httpClient.Do(req)
		if err != nil {
			t.Fatalf("httpClient.Do() error: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status 200, got %d", resp.StatusCode)
		}
	})
}

// BenchmarkNewFinder benchmarks Finder creation
func BenchmarkNewFinder(b *testing.B) {
	logger := slog.Default()

	for b.Loop() {
		NewFinder(10, 10, logger)
	}
}
