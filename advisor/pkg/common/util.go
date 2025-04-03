package common

import (
	"fmt"
	"os"
	"path/filepath"

	log "github.com/rs/zerolog/log"
)

// FileIO is an interface for file operations, allows for easier testing
type FileIO interface {
	MkdirAll(path string, perm os.FileMode) error
	WriteFile(filename string, data []byte, perm os.FileMode) error
	Stat(path string) (os.FileInfo, error)
}

// RealFileIO implements FileIO with real filesystem operations
type RealFileIO struct{}

// MkdirAll creates directories
func (f RealFileIO) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// WriteFile writes a file
func (f RealFileIO) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

// Stat gets file info
func (f RealFileIO) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// defaultFileIO is the default implementation
var defaultFileIO FileIO = RealFileIO{}

// SetFileIO sets the file IO implementation, mainly for testing
func SetFileIO(fileIO FileIO) {
	defaultFileIO = fileIO
}

// Function variables for mocking util functions in tests
// Exported variables allow mocking from other packages
var (
	EnsureOutputDirFunc    = ensureOutputDirInternal
	SaveToFileFunc         = saveToFileInternal
	HandleOutputDirFunc    = handleOutputDirInternal
	PrintDryRunMessageFunc = printDryRunMessageInternal
)

// EnsureOutputDir ensures the output directory exists
func EnsureOutputDir(outputDir string) error {
	return EnsureOutputDirFunc(outputDir)
}

// SaveToFile saves resource to a file in the specified output directory
func SaveToFile(outputDir, resourceType, namespace, name string, content []byte) (string, error) {
	return SaveToFileFunc(outputDir, resourceType, namespace, name, content)
}

// HandleOutputDir handles output directory setup for different resource types
func HandleOutputDir(outputDir, resourceTypePlural string) error {
	return HandleOutputDirFunc(outputDir, resourceTypePlural)
}

// PrintDryRunMessage prints a dry run message for a resource
func PrintDryRunMessage(resourceType, name string, content []byte, outputDir string) {
	PrintDryRunMessageFunc(resourceType, name, content, outputDir)
}

// --- Internal Implementations ---

func ensureOutputDirInternal(outputDir string) error {
	if outputDir == "" {
		return nil
	}

	// Check if directory exists
	_, err := defaultFileIO.Stat(outputDir)
	if os.IsNotExist(err) {
		// Create directory
		log.Info().Msgf("Creating output directory: %s", outputDir)
		if err := defaultFileIO.MkdirAll(outputDir, 0755); err != nil {
			log.Error().Err(err).Msgf("Failed to create output directory: %s", outputDir)
			return err
		}
	} else if err != nil {
		log.Error().Err(err).Msgf("Error checking output directory: %s", outputDir)
		return err
	}

	return nil
}

func saveToFileInternal(outputDir, resourceType, namespace, name string, content []byte) (string, error) {
	if err := EnsureOutputDir(outputDir); err != nil { // Use the exported func which uses the mockable var
		return "", err
	}

	// Create filename: <namespace>-<pod-name>-<resource-type>.yaml
	filename := filepath.Join(outputDir, fmt.Sprintf("%s-%s-%s.yaml", namespace, name, resourceType))

	// Write to file
	if err := defaultFileIO.WriteFile(filename, content, 0644); err != nil {
		log.Error().Err(err).Msgf("Failed to write %s to file: %s", resourceType, filename)
		return "", err
	}

	return filename, nil
}

func handleOutputDirInternal(outputDir, resourceTypePlural string) error {
	if outputDir == "" {
		log.Info().Msgf("%s will not be saved to disk as no output directory was specified", resourceTypePlural)
		return nil
	}

	if err := EnsureOutputDir(outputDir); err != nil { // Use the exported func
		log.Error().Err(err).Msgf("Failed to create output directory for %s", resourceTypePlural)
		return err
	}

	log.Info().Msgf("%s will be saved to: %s", resourceTypePlural, outputDir)
	return nil
}

func printDryRunMessageInternal(resourceType, name string, content []byte, outputDir string) {
	if outputDir != "" {
		log.Info().Msgf("Dry run: Would apply the %s for %s (saved to file instead)", resourceType, name)
	} else {
		log.Info().Msgf("Dry run: Would apply the following %s for %s:", resourceType, name)
		fmt.Println(string(content))
	}
}
