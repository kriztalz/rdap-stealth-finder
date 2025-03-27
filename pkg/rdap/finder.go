package rdap

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

const (
	tldsURL      = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
	bootstrapURL = "https://data.iana.org/rdap/dns.json"
	ianaRDAPURL  = "https://rdap.iana.org/domain/%s"
)

// Finder is responsible for discovering stealth RDAP servers
type Finder struct {
	concurrency    int
	timeoutSeconds int
	httpClient     *http.Client
}

// NewFinder creates a new finder with the specified concurrency and timeout
func NewFinder(concurrency, timeoutSeconds int) *Finder {
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}

	return &Finder{
		concurrency:    concurrency,
		timeoutSeconds: timeoutSeconds,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSeconds) * time.Second,
			// Configure transport for better performance
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

// IANAResponse represents the response from RDAP IANA server
type IANAResponse struct {
	Port43 string `json:"port43,omitempty"`
}

// RDAPBootstrap represents the RDAP bootstrap file
type RDAPBootstrap struct {
	Description string       `json:"description"`
	Publication string       `json:"publication"`
	Services    [][][]string `json:"services"`
}

// RDAPStats contains statistics about the RDAP server discovery process
type RDAPStats struct {
	TotalTLDs        int
	PublishedServers int
	StealthServers   int
	UnknownServers   int
}

// RDAPServer represents a discovered RDAP server
type RDAPServer struct {
	Host     string
	Endpoint string
}

// CheckKnownRDAPServer checks if a TLD has a known RDAP server in the bootstrap file
func (f *Finder) CheckKnownRDAPServer(tld string) (bool, []RDAPServer, error) {
	tld = strings.ToUpper(tld)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(f.timeoutSeconds)*time.Second)
	defer cancel()

	// Download RDAP bootstrap file
	bootstrap, err := f.fetchRDAPBootstrap(ctx)
	if err != nil {
		return false, nil, fmt.Errorf("fetching RDAP bootstrap: %w", err)
	}

	// Find the TLD in the bootstrap file
	for _, service := range bootstrap.Services {
		if len(service) >= 2 {
			for _, serviceTLD := range service[0] {
				if strings.ToUpper(serviceTLD) == tld {
					servers := make([]RDAPServer, 0, len(service[1]))
					for _, serverURL := range service[1] {
						u, err := url.Parse(serverURL)
						if err != nil {
							slog.Debug("Error parsing server URL", "url", serverURL, "error", err)
							continue
						}
						servers = append(servers, RDAPServer{
							Host:     u.Host,
							Endpoint: serverURL,
						})
					}
					return true, servers, nil
				}
			}
		}
	}

	return false, nil, nil
}

// FindSingleStealthServer attempts to find a stealth RDAP server for a single TLD
func (f *Finder) FindSingleStealthServer(tld string) (RDAPServer, bool, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(f.timeoutSeconds)*time.Second)
	defer cancel()

	// Try to find a stealth RDAP server
	server, found := f.checkStealthRDAP(ctx, tld)
	return server, found, nil
}

// FindStealthServers discovers stealth RDAP servers
func (f *Finder) FindStealthServers() (map[string]RDAPServer, RDAPStats, error) {
	// Create a context with timeout for the entire operation
	// Increase the timeout to 5 minutes for full runs
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Download TLDs list
	slog.Info("Fetching TLDs list")
	tlds, err := f.fetchTLDs(ctx)
	if err != nil {
		return nil, RDAPStats{}, fmt.Errorf("fetching TLDs: %w", err)
	}
	slog.Info("Fetched TLDs list", "count", len(tlds))

	// Download RDAP bootstrap file
	slog.Info("Fetching RDAP bootstrap file")
	bootstrap, err := f.fetchRDAPBootstrap(ctx)
	if err != nil {
		return nil, RDAPStats{}, fmt.Errorf("fetching RDAP bootstrap: %w", err)
	}

	// Extract TLDs with known RDAP servers
	knownRDAPTLDs := make(map[string]bool)
	for _, service := range bootstrap.Services {
		if len(service) >= 1 {
			for _, tld := range service[0] {
				knownRDAPTLDs[strings.ToUpper(tld)] = true
			}
		}
	}
	slog.Info("Found known RDAP servers", "count", len(knownRDAPTLDs))

	// Find TLDs without known RDAP servers
	unknownTLDs := make([]string, 0)
	for _, tld := range tlds {
		if !knownRDAPTLDs[tld] {
			unknownTLDs = append(unknownTLDs, tld)
		}
	}
	slog.Info("Found TLDs without known RDAP servers", "count", len(unknownTLDs))

	// Discover stealth RDAP servers
	results := make(map[string]RDAPServer)
	resultsMu := sync.Mutex{}

	// Create a worker pool to process TLDs concurrently
	g, ctx := errgroup.WithContext(ctx)
	tldCh := make(chan string, f.concurrency)

	// Start workers
	for i := 0; i < f.concurrency; i++ {
		g.Go(func() error {
			for tld := range tldCh {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					// Create a new context with timeout for each TLD check
					tldCtx, tldCancel := context.WithTimeout(ctx, time.Duration(f.timeoutSeconds)*time.Second)
					if server, found := f.checkStealthRDAP(tldCtx, tld); found {
						resultsMu.Lock()
						results[tld] = server
						resultsMu.Unlock()
						slog.Info("Found stealth RDAP server",
							"tld", tld,
							"host", server.Host,
							"endpoint", server.Endpoint)
					}
					tldCancel()
				}
			}
			return nil
		})
	}

	// Feed TLDs to workers
	for _, tld := range unknownTLDs {
		select {
		case <-ctx.Done():
			slog.Warn("Context cancelled, stopping TLD processing", "processed", len(results), "remaining", len(unknownTLDs)-len(results))
			break
		case tldCh <- tld:
			// TLD sent to worker
		}
	}
	close(tldCh)

	// Wait for all workers to complete
	if err := g.Wait(); err != nil {
		if err == context.DeadlineExceeded {
			slog.Warn("Operation timed out",
				"processed_tlds", len(results),
				"total_tlds", len(unknownTLDs),
				"remaining_tlds", len(unknownTLDs)-len(results))
		} else if err == context.Canceled {
			slog.Warn("Operation cancelled",
				"processed_tlds", len(results),
				"total_tlds", len(unknownTLDs),
				"remaining_tlds", len(unknownTLDs)-len(results))
		} else {
			slog.Warn("Some workers encountered errors",
				"error", err,
				"processed_tlds", len(results),
				"total_tlds", len(unknownTLDs),
				"remaining_tlds", len(unknownTLDs)-len(results))
		}
	}

	// Calculate statistics
	stats := RDAPStats{
		TotalTLDs:        len(tlds),
		PublishedServers: len(knownRDAPTLDs),
		StealthServers:   len(results),
		UnknownServers:   len(unknownTLDs) - len(results),
	}

	return results, stats, nil
}

// fetchTLDs downloads the list of TLDs
func (f *Finder) fetchTLDs(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tldsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching TLDs: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var tlds []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tlds = append(tlds, strings.ToUpper(line))
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading TLDs: %w", err)
	}

	return tlds, nil
}

// fetchRDAPBootstrap downloads the RDAP bootstrap file
func (f *Finder) fetchRDAPBootstrap(ctx context.Context) (*RDAPBootstrap, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching RDAP bootstrap: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var bootstrap RDAPBootstrap
	if err := json.NewDecoder(resp.Body).Decode(&bootstrap); err != nil {
		return nil, fmt.Errorf("decoding bootstrap file: %w", err)
	}

	return &bootstrap, nil
}

// checkStealthRDAP attempts to discover a stealth RDAP server for a TLD
func (f *Finder) checkStealthRDAP(ctx context.Context, tld string) (RDAPServer, bool) {
	tld = strings.ToLower(tld)
	slog.Debug("Starting stealth RDAP server discovery", "tld", tld)

	// First, try to get information from IANA's RDAP server
	ianaURL := fmt.Sprintf(ianaRDAPURL, tld)
	slog.Debug("Querying IANA RDAP server", "url", ianaURL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ianaURL, nil)
	if err != nil {
		slog.Debug("Error creating IANA request", "tld", tld, "error", err)
		return RDAPServer{}, false
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		slog.Debug("Error fetching from IANA", "tld", tld, "error", err)
		return RDAPServer{}, false
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		slog.Debug("Error reading IANA response body", "tld", tld, "error", err)
		return RDAPServer{}, false
	}

	if resp.StatusCode != http.StatusOK {
		slog.Debug("Unexpected status code from IANA", "tld", tld, "status", resp.StatusCode)
		return RDAPServer{}, false
	}

	slog.Debug("Received IANA response", "tld", tld, "status", resp.StatusCode)

	// Look for port43 in the response
	var ianaResp IANAResponse
	if err := json.Unmarshal(body, &ianaResp); err != nil {
		slog.Debug("Error unmarshaling IANA response", "tld", tld, "error", err)
		return RDAPServer{}, false
	}

	if ianaResp.Port43 == "" {
		slog.Debug("No port43 in IANA response", "tld", tld)
		return RDAPServer{}, false
	}

	slog.Debug("Found port43 in IANA response", "tld", tld, "port43", ianaResp.Port43)

	// Try common patterns for RDAP servers
	potentialURLs := []string{
		// Replace whois. with rdap.
		fmt.Sprintf("https://%s/domain/example.%s", strings.Replace(ianaResp.Port43, "whois.", "rdap.", 1), tld),
		// Try with nic.tld
		fmt.Sprintf("https://rdap.nic.%s/domain/example.%s", tld, tld),
		// Try without domain path
		fmt.Sprintf("https://%s", strings.Replace(ianaResp.Port43, "whois.", "rdap.", 1)),
		// Try without domain path but with nic.tld
		fmt.Sprintf("https://rdap.nic.%s", tld),
		// Try registry/domain path with nic.tld
		fmt.Sprintf("https://rdap.nic.%s/registry/domain/example.%s", tld, tld),
		// Try registry/domain path with nic.tld (without example)
		fmt.Sprintf("https://rdap.nic.%s/registry/domain/%s", tld, tld),
		// Try nic.tld/rdap/domain pattern
		fmt.Sprintf("https://nic.%s/rdap/domain.%s", tld, tld),
		// Try rdap.nic.tld/rdap/v1/domain pattern
		fmt.Sprintf("https://rdap.nic.%s/rdap/v1/domain.%s", tld, tld),
		// Try nic.tld/rdap/v1/domain pattern
		fmt.Sprintf("https://nic.%s/rdap/v1/domain.%s", tld, tld),
		// Try rdap.nic.tld/v1/domain pattern
		fmt.Sprintf("https://rdap.nic.%s/v1/domain.%s", tld, tld),
		// Try rdap.nic.tld/dbs/rdap-api/v1/domain pattern
		fmt.Sprintf("https://rdap.nic.%s/dbs/rdap-api/v1/domain.%s", tld, tld),
		// Try whois.nic.tld/rdap/domain pattern
		fmt.Sprintf("https://whois.nic.%s/rdap/domain.%s", tld, tld),
		// Try rdap.nic.tld/api/domain pattern
		fmt.Sprintf("https://rdap.nic.%s/api/%s", tld, tld),
	}

	slog.Debug("Generated potential RDAP URLs", "tld", tld, "urls", potentialURLs)

	// Check each potential URL
	for _, urlStr := range potentialURLs {
		slog.Debug("Checking potential RDAP URL", "tld", tld, "url", urlStr)
		if f.isRDAPServer(ctx, urlStr) {
			// Extract the base URL and host
			u, err := url.Parse(urlStr)
			if err != nil {
				slog.Debug("Error parsing URL", "url", urlStr, "error", err)
				continue
			}

			// Extract the endpoint path
			endpoint := urlStr
			if strings.Contains(urlStr, "/domain/") {
				endpoint = urlStr[:strings.Index(urlStr, "/domain/")+len("/domain/")]
			} else if strings.Contains(urlStr, "/registry/") {
				endpoint = urlStr[:strings.Index(urlStr, "/registry/")+len("/registry/")]
			} else if strings.Contains(urlStr, "/rdap/") {
				endpoint = urlStr[:strings.Index(urlStr, "/rdap/")+len("/rdap/")]
			} else if strings.Contains(urlStr, "/v1/") {
				endpoint = urlStr[:strings.Index(urlStr, "/v1/")+len("/v1/")]
			} else if strings.Contains(urlStr, "/dbs/") {
				endpoint = urlStr[:strings.Index(urlStr, "/dbs/")+len("/dbs/")]
			}

			server := RDAPServer{
				Host:     u.Host,
				Endpoint: endpoint,
			}

			slog.Debug("Found valid RDAP server",
				"tld", tld,
				"host", server.Host,
				"endpoint", server.Endpoint)
			return server, true
		}
	}

	slog.Debug("No valid RDAP server found for any potential URL", "tld", tld)
	return RDAPServer{}, false
}

// isRDAPServer checks if a URL is an RDAP server
func (f *Finder) isRDAPServer(ctx context.Context, url string) bool {
	slog.Debug("Validating potential RDAP server", "url", url)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		slog.Debug("Error creating validation request", "url", url, "error", err)
		return false
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		slog.Debug("Error during RDAP server validation", "url", url, "error", err)
		return false
	}
	defer resp.Body.Close()

	slog.Debug("Received response from potential RDAP server",
		"url", url,
		"status", resp.StatusCode,
		"content_type", resp.Header.Get("Content-Type"))

	// Check if the response has the correct content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/rdap+json") &&
		!strings.Contains(contentType, "application/json") {
		slog.Debug("Invalid content type for RDAP server",
			"url", url,
			"content_type", contentType)
		return false
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Debug("Error reading RDAP server response", "url", url, "error", err)
		return false
	}

	// Check if the response is a valid RDAP response
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		slog.Debug("Error unmarshaling RDAP response", "url", url, "error", err)
		return false
	}

	// Check for RDAP conformance
	if conformance, ok := data["rdapConformance"].([]interface{}); ok && len(conformance) > 0 {
		slog.Debug("Found valid RDAP conformance",
			"url", url,
			"conformance", conformance)
		return true
	}

	slog.Debug("No RDAP conformance found in response", "url", url)
	return false
}
