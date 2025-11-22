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
	logger         *slog.Logger
}

// NewFinder creates a new finder with the specified concurrency and timeout
func NewFinder(concurrency, timeoutSeconds int, logger *slog.Logger) *Finder {
	if concurrency <= 0 {
		concurrency = runtime.NumCPU()
	}
	if timeoutSeconds <= 0 {
		timeoutSeconds = 10
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &Finder{
		concurrency:    concurrency,
		timeoutSeconds: timeoutSeconds,
		logger:         logger,
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
							f.logger.DebugContext(ctx, "Error parsing server URL", slog.String("url", serverURL), slog.Any("error", err))
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
	f.logger.InfoContext(ctx, "Fetching TLDs list")
	tlds, err := f.fetchTLDs(ctx)
	if err != nil {
		return nil, RDAPStats{}, fmt.Errorf("fetching TLDs: %w", err)
	}
	f.logger.InfoContext(ctx, "Fetched TLDs list", slog.Int("count", len(tlds)))

	// Download RDAP bootstrap file
	f.logger.InfoContext(ctx, "Fetching RDAP bootstrap file")
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
	f.logger.InfoContext(ctx, "Found known RDAP servers", slog.Int("count", len(knownRDAPTLDs)))

	// Find TLDs without known RDAP servers
	unknownTLDs := make([]string, 0)
	for _, tld := range tlds {
		if !knownRDAPTLDs[tld] {
			unknownTLDs = append(unknownTLDs, tld)
		}
	}
	f.logger.InfoContext(ctx, "Found TLDs without known RDAP servers", slog.Int("count", len(unknownTLDs)))

	// Discover stealth RDAP servers
	results := make(map[string]RDAPServer)
	resultsMu := sync.Mutex{}

	// Create a worker pool to process TLDs concurrently
	g, ctx := errgroup.WithContext(ctx)
	tldCh := make(chan string, f.concurrency)

	// Start workers
	for range f.concurrency {
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
						f.logger.InfoContext(tldCtx, "Found stealth RDAP server",
							slog.String("tld", tld),
							slog.String("host", server.Host),
							slog.String("endpoint", server.Endpoint))
					}
					tldCancel()
				}
			}
			return nil
		})
	}

	// Feed TLDs to workers
feedLoop:
	for _, tld := range unknownTLDs {
		select {
		case <-ctx.Done():
			f.logger.WarnContext(ctx, "Context cancelled, stopping TLD processing", slog.Int("processed", len(results)), slog.Int("remaining", len(unknownTLDs)-len(results)))
			break feedLoop
		case tldCh <- tld:
			// TLD sent to worker
		}
	}
	close(tldCh)

	// Wait for all workers to complete
	if err := g.Wait(); err != nil {
		switch err {
		case context.DeadlineExceeded:
			f.logger.WarnContext(ctx, "Operation timed out",
				slog.Int("processed_tlds", len(results)),
				slog.Int("total_tlds", len(unknownTLDs)),
				slog.Int("remaining_tlds", len(unknownTLDs)-len(results)))
		case context.Canceled:
			f.logger.WarnContext(ctx, "Operation cancelled",
				slog.Int("processed_tlds", len(results)),
				slog.Int("total_tlds", len(unknownTLDs)),
				slog.Int("remaining_tlds", len(unknownTLDs)-len(results)))
		default:
			f.logger.WarnContext(ctx, "Some workers encountered errors",
				slog.Any("error", err),
				slog.Int("processed_tlds", len(results)),
				slog.Int("total_tlds", len(unknownTLDs)),
				slog.Int("remaining_tlds", len(unknownTLDs)-len(results)))
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
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			f.logger.DebugContext(ctx, "Error closing response body", slog.Any("error", closeErr))
		}
	}()

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
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			f.logger.DebugContext(ctx, "Error closing response body", slog.Any("error", closeErr))
		}
	}()

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
	f.logger.DebugContext(ctx, "Starting stealth RDAP server discovery", slog.String("tld", tld))

	// First, try to get information from IANA's RDAP server
	ianaURL := fmt.Sprintf(ianaRDAPURL, tld)
	f.logger.DebugContext(ctx, "Querying IANA RDAP server", slog.String("url", ianaURL))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ianaURL, nil)
	if err != nil {
		f.logger.DebugContext(ctx, "Error creating IANA request", slog.String("tld", tld), slog.Any("error", err))
		return RDAPServer{}, false
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		f.logger.DebugContext(ctx, "Error fetching from IANA", slog.String("tld", tld), slog.Any("error", err))
		return RDAPServer{}, false
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			f.logger.DebugContext(ctx, "Error closing IANA response body", slog.String("tld", tld), slog.Any("error", closeErr))
		}
	}()

	if resp.StatusCode != http.StatusOK {
		f.logger.DebugContext(ctx, "Unexpected status code from IANA", slog.String("tld", tld), slog.Int("status", resp.StatusCode))
		return RDAPServer{}, false
	}

	f.logger.DebugContext(ctx, "Received IANA response for TLD", slog.String("tld", tld), slog.Int("status", resp.StatusCode))

	// Try common RDAP URL patterns based on TLD (port43 is no longer in bootstrap)
	potentialURLs := []string{
		// Try with nic.tld
		fmt.Sprintf("https://rdap.nic.%s/domain/example.%s", tld, tld),
		// Try without domain path but with nic.tld
		"https://rdap.nic." + tld,
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

	f.logger.DebugContext(ctx, "Generated potential RDAP URLs", slog.String("tld", tld), slog.Any("urls", potentialURLs))

	// Check each potential URL
	for _, urlStr := range potentialURLs {
		f.logger.DebugContext(ctx, "Checking potential RDAP URL", slog.String("tld", tld), slog.String("url", urlStr))
		if f.isRDAPServer(ctx, urlStr) {
			// Extract the base URL and host
			u, err := url.Parse(urlStr)
			if err != nil {
				f.logger.DebugContext(ctx, "Error parsing URL", slog.String("url", urlStr), slog.Any("error", err))
				continue
			}

			// Extract the endpoint path
			endpoint := urlStr
			switch {
			case strings.Contains(urlStr, "/domain/"):
				endpoint = urlStr[:strings.Index(urlStr, "/domain/")+len("/domain/")]
			case strings.Contains(urlStr, "/registry/"):
				endpoint = urlStr[:strings.Index(urlStr, "/registry/")+len("/registry/")]
			case strings.Contains(urlStr, "/rdap/"):
				endpoint = urlStr[:strings.Index(urlStr, "/rdap/")+len("/rdap/")]
			case strings.Contains(urlStr, "/v1/"):
				endpoint = urlStr[:strings.Index(urlStr, "/v1/")+len("/v1/")]
			case strings.Contains(urlStr, "/dbs/"):
				endpoint = urlStr[:strings.Index(urlStr, "/dbs/")+len("/dbs/")]
			}

			server := RDAPServer{
				Host:     u.Host,
				Endpoint: endpoint,
			}

			f.logger.DebugContext(ctx, "Found valid RDAP server",
				slog.String("tld", tld),
				slog.String("host", server.Host),
				slog.String("endpoint", server.Endpoint))
			return server, true
		}
	}

	f.logger.DebugContext(ctx, "No valid RDAP server found for any potential URL", slog.String("tld", tld))
	return RDAPServer{}, false
}

// isRDAPServer checks if a URL is an RDAP server
func (f *Finder) isRDAPServer(ctx context.Context, url string) bool {
	f.logger.DebugContext(ctx, "Validating potential RDAP server", slog.String("url", url))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		f.logger.DebugContext(ctx, "Error creating validation request", slog.String("url", url), slog.Any("error", err))
		return false
	}
	req.Header.Set("Accept", "application/rdap+json")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		f.logger.DebugContext(ctx, "Error during RDAP server validation", slog.String("url", url), slog.Any("error", err))
		return false
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			f.logger.DebugContext(ctx, "Error closing response body", slog.String("url", url), slog.Any("error", closeErr))
		}
	}()

	f.logger.DebugContext(ctx, "Received response from potential RDAP server",
		slog.String("url", url),
		slog.Int("status", resp.StatusCode),
		slog.String("content_type", resp.Header.Get("Content-Type")))

	// Check if the response has the correct content type
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/rdap+json") &&
		!strings.Contains(contentType, "application/json") {
		f.logger.DebugContext(ctx, "Invalid content type for RDAP server",
			slog.String("url", url),
			slog.String("content_type", contentType))
		return false
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		f.logger.DebugContext(ctx, "Error reading RDAP server response", slog.String("url", url), slog.Any("error", err))
		return false
	}

	// Check if the response is a valid RDAP response
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		f.logger.DebugContext(ctx, "Error unmarshaling RDAP response", slog.String("url", url), slog.Any("error", err))
		return false
	}

	// Check for RDAP conformance
	if conformance, ok := data["rdapConformance"].([]any); ok && len(conformance) > 0 {
		f.logger.DebugContext(ctx, "Found valid RDAP conformance",
			slog.String("url", url),
			slog.Any("conformance", conformance))
		return true
	}

	f.logger.DebugContext(ctx, "No RDAP conformance found in response", slog.String("url", url))
	return false
}
