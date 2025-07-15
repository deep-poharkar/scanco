package main

import (
	"flag"
	"fmt"
	"log"

	"scanco/pkg/scanner/container"
	"scanco/pkg/vulnerability"
	"scanco/pkg/vulnerability/nvd"
)

func main() {
	// Parse command line flags
	apiKey := flag.String("api-key", "", "NVD API key (optional)")
	minSeverity := flag.String("min-severity", "LOW", "Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW, NONE)")
	pageSize := flag.Int("page-size", 5, "Number of vulnerabilities to show per page")
	pageNum := flag.Int("page", 1, "Page number to show")
	quickScan := flag.Bool("quick", true, "Perform quick scan first")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Usage: scanco [--api-key KEY] [--min-severity LEVEL] [--page-size N] [--page N] [--quick=false] <image-name>")
	}

	imageName := flag.Arg(0)
	fmt.Printf("Scanning image: %s\n", imageName)

	// Create container scanner
	containerScanner := container.NewImageScanner()
	packages, err := containerScanner.ScanImage(imageName)
	if err != nil {
		log.Fatalf("Failed to scan image: %v", err)
	}

	if len(packages) == 0 {
		fmt.Println("\nNo packages found in the image")
		return
	}

	fmt.Printf("\nFound %d packages:\n", len(packages))
	for _, pkg := range packages {
		fmt.Printf("- %s v%s (%s) [%s]\n", pkg.Name, pkg.Version, pkg.Architecture, pkg.Source)
	}

	// Create NVD client and vulnerability scanner
	nvdConfig := nvd.DefaultConfig()
	if *apiKey != "" {
		nvdConfig.APIKey = *apiKey
	}

	vulnScanner := vulnerability.NewScanner(
		nvd.NewClient(nvdConfig),
	)

	// Create scan options
	options := &vulnerability.ScanOptions{
		MinSeverity: vulnerability.Severity(*minSeverity),
		PageSize:    *pageSize,
		PageNumber:  *pageNum,
		QuickScan:   *quickScan,
	}

	// Scan for vulnerabilities
	fmt.Println("\nScanning for vulnerabilities...")
	result, err := vulnScanner.ScanPackages(packages, options)
	if err != nil {
		log.Fatalf("Failed to scan for vulnerabilities: %v", err)
	}

	// Print results
	if result.TotalResults == 0 {
		fmt.Printf("\nNo vulnerabilities found with minimum severity of %s\n", options.MinSeverity)
		return
	}

	fmt.Printf("\nFound %d vulnerabilities (showing page %d, %d per page):\n",
		result.TotalResults, result.CurrentPage, options.PageSize)

	// Group results by package
	grouped := vulnScanner.GroupResultsByPackage(result.Results)
	for pkgKey, vulns := range grouped {
		fmt.Printf("\n%s:\n", pkgKey)
		for _, v := range vulns {
			fmt.Printf("  - [%s] %s (CVSS: %.1f)\n", v.Vulnerability.Severity, v.Vulnerability.ID, v.Vulnerability.CVSS)
			fmt.Printf("    %s\n", v.Vulnerability.Description)
			if len(v.Vulnerability.References) > 0 {
				fmt.Printf("    References:\n")
				for _, ref := range v.Vulnerability.References {
					fmt.Printf("    - %s\n", ref)
				}
			}
		}
	}

	// Show pagination info
	if result.QuickScan {
		fmt.Printf("\nQuick scan completed. %d packages left to scan.\n", result.PackagesLeft)
		fmt.Println("To scan more packages, run again with --quick=false")
	}

	if result.HasMorePages {
		fmt.Printf("\nShowing page %d of %d. ",
			result.CurrentPage,
			(result.TotalResults+options.PageSize-1)/options.PageSize)
		fmt.Printf("To see more results, run again with --page=%d\n", result.CurrentPage+1)
	}
}
