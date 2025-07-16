package apk

import (
	"bufio"
	"strings"

	"scanco/pkg/scanner"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Name() string {
	return "apk"
}

func (s *Scanner) ScanPackages(content []byte) ([]scanner.Package, error) {
	var packages []scanner.Package
	reader := bufio.NewScanner(strings.NewReader(string(content)))

	var currentPkg *scanner.Package
	for reader.Scan() {
		line := reader.Text()
		if strings.HasPrefix(line, "P:") {
			// Start a new package
			if currentPkg != nil {
				packages = append(packages, *currentPkg)
			}
			currentPkg = &scanner.Package{
				Name:   strings.TrimSpace(strings.TrimPrefix(line, "P:")),
				Source: "apk",
			}
		} else if currentPkg != nil {
			if strings.HasPrefix(line, "V:") {
				// Version
				currentPkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "V:"))
			} else if strings.HasPrefix(line, "A:") {
				// Architecture
				currentPkg.Architecture = strings.TrimSpace(strings.TrimPrefix(line, "A:"))
			}
		}
	}

	// Add the last package if exists
	if currentPkg != nil {
		packages = append(packages, *currentPkg)
	}

	return packages, reader.Err()
}
 