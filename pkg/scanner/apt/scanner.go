package apt

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
	return "apt"
}

func (s *Scanner) ScanPackages(content []byte) ([]scanner.Package, error) {
	var packages []scanner.Package
	reader := bufio.NewScanner(strings.NewReader(string(content)))

	var currentPkg *scanner.Package
	for reader.Scan() {
		line := reader.Text()

		// Empty line marks end of package entry
		if line == "" && currentPkg != nil {
			packages = append(packages, *currentPkg)
			currentPkg = nil
			continue
		}

		// Skip lines that don't start with key fields
		if !strings.Contains(line, ": ") {
			continue
		}

		parts := strings.SplitN(line, ": ", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := strings.TrimSpace(parts[1])

		switch key {
		case "Package":
			// Start a new package
			currentPkg = &scanner.Package{
				Name:   value,
				Source: "apt",
			}
		case "Version":
			if currentPkg != nil {
				currentPkg.Version = value
			}
		case "Architecture":
			if currentPkg != nil {
				currentPkg.Architecture = value
			}
		}
	}

	// Add the last package if exists
	if currentPkg != nil {
		packages = append(packages, *currentPkg)
	}

	return packages, reader.Err()
}
