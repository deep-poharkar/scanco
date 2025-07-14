package container

import (
	"archive/tar"
	"fmt"
	"io"

	"github.com/google/go-containerregistry/pkg/crane"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"

	"scanco/pkg/scanner"
	"scanco/pkg/scanner/apk"
	"scanco/pkg/scanner/apt"
)

type ImageScanner struct {
	packageScanners []scanner.PackageScanner
	// Map of package database paths to their corresponding scanner
	dbPaths map[string]scanner.PackageScanner
}

func NewImageScanner() *ImageScanner {
	// Create scanners
	apkScanner := apk.NewScanner()
	aptScanner := apt.NewScanner()

	// Map package database paths to their scanners
	dbPaths := map[string]scanner.PackageScanner{
		"lib/apk/db/installed":  apkScanner,
		"var/lib/dpkg/status":   aptScanner,
		"/lib/apk/db/installed": apkScanner, // Handle absolute paths
		"/var/lib/dpkg/status":  aptScanner, // Handle absolute paths
	}

	return &ImageScanner{
		packageScanners: []scanner.PackageScanner{
			apkScanner,
			aptScanner,
		},
		dbPaths: dbPaths,
	}
}

func (s *ImageScanner) ScanImage(imageName string) ([]scanner.Package, error) {
	// Pull the container image
	img, err := crane.Pull(imageName)
	if err != nil {
		return nil, fmt.Errorf("pulling image: %w", err)
	}

	var allPackages []scanner.Package

	// First try scanning individual layers
	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting layers: %w", err)
	}

	for _, layer := range layers {
		pkgs, err := s.scanLayer(layer)
		if err != nil {
			// Log error but continue with other layers
			fmt.Printf("Warning: error scanning layer: %v\n", err)
			continue
		}
		allPackages = append(allPackages, pkgs...)
	}

	// If no packages found, try filesystem view
	if len(allPackages) == 0 {
		reader := mutate.Extract(img)
		pkgs, err := s.scanFilesystem(reader)
		if err != nil {
			return nil, fmt.Errorf("scanning filesystem: %w", err)
		}
		allPackages = append(allPackages, pkgs...)
	}

	return allPackages, nil
}

func (s *ImageScanner) scanLayer(layer v1.Layer) ([]scanner.Package, error) {
	rc, err := layer.Uncompressed()
	if err != nil {
		return nil, fmt.Errorf("getting layer contents: %w", err)
	}
	defer rc.Close()

	return s.scanTarReader(rc)
}

func (s *ImageScanner) scanFilesystem(reader io.ReadCloser) ([]scanner.Package, error) {
	defer reader.Close()
	return s.scanTarReader(reader)
}

func (s *ImageScanner) scanTarReader(reader io.Reader) ([]scanner.Package, error) {
	var allPackages []scanner.Package
	tr := tar.NewReader(reader)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar: %w", err)
		}

		// Check if this file is a known package database
		if scanner, ok := s.dbPaths[header.Name]; ok {
			content, err := io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("reading package database: %w", err)
			}

			pkgs, err := scanner.ScanPackages(content)
			if err != nil {
				// Log error but continue
				fmt.Printf("Warning: error with %s scanner: %v\n", scanner.Name(), err)
				continue
			}
			allPackages = append(allPackages, pkgs...)
		}
	}

	return allPackages, nil
}
