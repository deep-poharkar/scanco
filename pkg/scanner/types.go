package scanner

// Package represents a software package found in a container image
type Package struct {
	Name         string
	Version      string
	Architecture string
	Source       string // e.g., "apk", "apt", etc.
}

// Scanner interface defines methods for scanning container images
type Scanner interface {
	// ScanImage scans a container image and returns found packages
	ScanImage(imageName string) ([]Package, error)
}

// PackageScanner interface defines methods for extracting packages from different formats
type PackageScanner interface {
	// Name returns the name of the package manager (e.g., "apk", "apt")
	Name() string
	// ScanPackages extracts packages from a given file path or content
	ScanPackages(content []byte) ([]Package, error)
}
