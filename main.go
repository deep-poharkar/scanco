package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"text/tabwriter"

	"scanco/pkg/policy"
	"scanco/pkg/scanner/container"
	"scanco/pkg/vulnerability"
	"scanco/pkg/vulnerability/nvd"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
)

func getSeverityColor(severity vulnerability.Severity) string {
	switch severity {
	case vulnerability.SeverityCritical:
		return colorRed
	case vulnerability.SeverityHigh:
		return colorRed
	case vulnerability.SeverityMedium:
		return colorYellow
	case vulnerability.SeverityLow:
		return colorCyan
	default:
		return colorGreen
	}
}

func main() {
	// Parse command line flags
	apiKey := flag.String("api-key", "", "NVD API key (optional)")
	minSeverity := flag.String("min-severity", "LOW", "Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW, NONE)")
	minCVSS := flag.Float64("min-cvss", 0.0, "Minimum CVSS score (0-10)")
	pageSize := flag.Int("page-size", 5, "Number of vulnerabilities to show per page")
	pageNum := flag.Int("page", 1, "Page number to show")
	quickScan := flag.Bool("quick", true, "Perform quick scan first")
	noColor := flag.Bool("no-color", false, "Disable color output")
	policyDir := flag.String("policy-dir", "", "Directory containing security policies")
	policyFile := flag.String("policy", "", "Path to security policy file")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Usage: scanco [--api-key KEY] [--min-severity LEVEL] [--min-cvss SCORE] [--page-size N] [--page N] [--quick=false] [--no-color] [--policy-dir DIR] [--policy FILE] <image-name>")
	}

	imageName := flag.Arg(0)
	fmt.Printf("Scanning image: %s\n", imageName)

	// Load security policies
	var policies []*policy.Policy
	var err error

	if *policyFile != "" {
		// Load single policy file
		parser := policy.NewParser()
		p, err := parser.ParseFile(*policyFile)
		if err != nil {
			log.Fatalf("Failed to load policy file: %v", err)
		}
		policies = append(policies, p)
	} else if *policyDir != "" {
		// Load all policies from directory
		parser := policy.NewParser()
		policies, err = parser.ParseFiles(*policyDir)
		if err != nil {
			log.Fatalf("Failed to load policies from directory: %v", err)
		}
	}

	// Create policy evaluator
	evaluator := policy.NewEvaluator(policies)

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

	// Print packages in a table
	fmt.Printf("\nFound %d packages:\n", len(packages))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PACKAGE\tVERSION\tARCHITECTURE\tSOURCE")
	fmt.Fprintln(w, "-------\t-------\t------------\t------")
	for _, pkg := range packages {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", pkg.Name, pkg.Version, pkg.Architecture, pkg.Source)
	}
	w.Flush()

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
		MinCVSS:     *minCVSS,
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
		fmt.Printf("\nNo vulnerabilities found with minimum severity of %s and minimum CVSS score of %.1f\n",
			options.MinSeverity, options.MinCVSS)
		return
	}

	fmt.Printf("\nFound %d vulnerabilities (showing page %d, %d per page):\n",
		result.TotalResults, result.CurrentPage, options.PageSize)

	// Evaluate against policies
	evalResult := evaluator.EvaluateImage(imageName, result.Results)
	if !evalResult.Allowed {
		fmt.Printf("\n%sPolicy Violations (%s):%s\n", colorRed, evalResult.PolicyName, colorReset)
		for _, violation := range evalResult.Violations {
			fmt.Printf("  - %s: %s\n", violation.Type, violation.Description)
			if details, ok := violation.Details["package"]; ok {
				fmt.Printf("    Package: %v\n", details)
			}
			if details, ok := violation.Details["version"]; ok {
				fmt.Printf("    Version: %v\n", details)
			}
		}
		fmt.Println()
	}

	// Group results by package
	grouped := vulnScanner.GroupResultsByPackage(result.Results)
	for pkgKey, vulns := range grouped {
		fmt.Printf("\n%s:\n", pkgKey)

		// Create table writer for vulnerabilities
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "SEVERITY\tCVSS\tCVE ID\tPUBLISHED\tDESCRIPTION")
		fmt.Fprintln(w, "--------\t----\t------\t---------\t-----------")

		for _, v := range vulns {
			severity := string(v.Vulnerability.Severity)
			if !*noColor {
				severity = getSeverityColor(v.Vulnerability.Severity) + severity + colorReset
			}

			// Add policy violation indicator
			cveID := v.Vulnerability.ID
			if !evalResult.Allowed {
				for _, violation := range evalResult.Violations {
					if id, ok := violation.Details["cve_id"]; ok && id == cveID {
						cveID = fmt.Sprintf("%s%s (blocked)%s", colorRed, cveID, colorReset)
						break
					}
				}
			}

			// Truncate description if too long
			desc := v.Vulnerability.Description
			if len(desc) > 100 {
				desc = desc[:97] + "..."
			}

			fmt.Fprintf(w, "%s\t%.1f\t%s\t%s\t%s\n",
				severity,
				v.Vulnerability.CVSS,
				cveID,
				v.Vulnerability.Published.Format("2006-01-02"),
				strings.ReplaceAll(desc, "\n", " "))
		}
		w.Flush()

		// Print references in a more compact format
		for _, v := range vulns {
			if len(v.Vulnerability.References) > 0 {
				fmt.Printf("\nReferences for %s:\n", v.Vulnerability.ID)
				for _, ref := range v.Vulnerability.References {
					fmt.Printf("  - %s\n", ref)
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

	// Exit with error code if policy violations found
	if !evalResult.Allowed {
		os.Exit(1)
	}
}
