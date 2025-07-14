package main

import (
	"fmt"
	"log"
	"os"

	"scanco/pkg/scanner/container"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("Usage: scanco <image-name>")
	}

	imageName := os.Args[1]
	fmt.Printf("Scanning image: %s\n", imageName)

	scanner := container.NewImageScanner()
	packages, err := scanner.ScanImage(imageName)
	if err != nil {
		log.Fatalf("Failed to scan image: %v", err)
	}

	if len(packages) == 0 {
		fmt.Println("\nNo packages found in the image")
	} else {
		fmt.Printf("\nFound %d packages:\n", len(packages))
		for _, pkg := range packages {
			fmt.Printf("- %s v%s (%s) [%s]\n", pkg.Name, pkg.Version, pkg.Architecture, pkg.Source)
		}
	}
}
