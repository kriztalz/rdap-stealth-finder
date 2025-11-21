package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/kriztalz/rdap-stealth-finder/pkg/rdap"
	"github.com/spf13/cobra"
)

func main() {
	// Configure structured logging with JSON output
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	// Define the root command
	rootCmd := &cobra.Command{
		Use:   "rdap-stealth-finder",
		Short: "A tool to discover stealth RDAP servers",
		Long: `RDAP Stealth Finder is a tool that discovers RDAP servers 
that are not publicly advertised in the IANA bootstrap files.

It works by comparing the list of all TLDs with the list of available RDAP servers,
then attempts to discover hidden RDAP servers using common patterns.`,
		Run: func(cmd *cobra.Command, args []string) {
			concurrency, _ := cmd.Flags().GetInt("concurrency")
			timeoutSeconds, _ := cmd.Flags().GetInt("timeout")
			verbose, _ := cmd.Flags().GetBool("verbose")
			singleTLD, _ := cmd.Flags().GetString("tld")

			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}
			logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				Level: level,
			}))
			slog.SetDefault(logger)

			finder := rdap.NewFinder(concurrency, timeoutSeconds, logger)

			// Check if a single TLD was specified
			if singleTLD != "" {
				// Clean up TLD input (remove leading dot if present, convert to uppercase)
				singleTLD = strings.TrimPrefix(singleTLD, ".")
				singleTLD = strings.ToUpper(singleTLD)

				fmt.Printf("Checking TLD: %s\n", singleTLD)

				// First check if it's in the bootstrap file
				isKnown, servers, err := finder.CheckKnownRDAPServer(singleTLD)
				if err != nil {
					fmt.Printf("Error checking bootstrap file: %v\n", err)
					os.Exit(1)
				}

				if isKnown {
					fmt.Printf("Found published RDAP server(s) for %s:\n", singleTLD)
					for _, server := range servers {
						fmt.Printf("- Host: %s\n  Endpoint: %s\n", server.Host, server.Endpoint)
					}
					return
				}

				// If not in bootstrap, try to find a stealth server
				server, found, err := finder.FindSingleStealthServer(singleTLD)
				if err != nil {
					fmt.Printf("Error checking for stealth RDAP server: %v\n", err)
					os.Exit(1)
				}

				if found {
					fmt.Printf("Found stealth RDAP server for %s:\n", singleTLD)
					fmt.Printf("- Host: %s\n  Endpoint: %s\n", server.Host, server.Endpoint)
				} else {
					fmt.Printf("No RDAP server found for %s\n", singleTLD)
				}
				return
			}

			// If no single TLD was specified, search for all stealth servers
			fmt.Println("Starting full RDAP server discovery...")
			results, stats, err := finder.FindStealthServers()
			if err != nil {
				fmt.Printf("Error finding stealth servers: %v\n", err)
				os.Exit(1)
			}

			// Print summary
			fmt.Println("\n=== RDAP Server Discovery Summary ===")
			fmt.Printf("Total TLDs: %d\n", stats.TotalTLDs)
			fmt.Printf("Published RDAP servers: %d\n", stats.PublishedServers)
			fmt.Printf("Stealth RDAP servers: %d\n", stats.StealthServers)
			fmt.Printf("Unknown RDAP servers: %d\n", stats.UnknownServers)
			fmt.Println("\n=== Stealth RDAP Servers Found ===")
			for tld, server := range results {
				fmt.Printf("%s:\n  Host: %s\n  Endpoint: %s\n", tld, server.Host, server.Endpoint)
			}
		},
	}

	// Add flags
	rootCmd.Flags().IntP("concurrency", "c", 10, "Number of concurrent workers")
	rootCmd.Flags().IntP("timeout", "t", 10, "HTTP request timeout in seconds")
	rootCmd.Flags().BoolP("verbose", "v", false, "Enable verbose logging")
	rootCmd.Flags().StringP("tld", "", "", "Check a specific TLD (e.g., 'ch' or 'com')")

	// Execute the command
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Command execution failed: %v\n", err)
		os.Exit(1)
	}
}
