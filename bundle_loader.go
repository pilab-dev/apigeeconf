package apigeeconf

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// BundleLoader handles loading API proxy bundles from directories or zip files
type BundleLoader struct {
	basePath  string
	bundleZip string
}

// NewBundleLoader creates a new bundle loader
func NewBundleLoader(basePath, bundleZip string) *BundleLoader {
	return &BundleLoader{
		basePath:  basePath,
		bundleZip: bundleZip,
	}
}

// LoadBundle loads a bundle from either a zip file or directory
func (l *BundleLoader) LoadBundle() (*APIProxyBundle, error) {
	if l.bundleZip != "" {
		return l.loadFromZip(l.bundleZip)
	}
	return l.loadFromDirectory(l.basePath)
}

// LoadBundleFromPath is a convenience function to load a bundle from a path
func LoadBundleFromPath(path string) (*APIProxyBundle, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		loader := NewBundleLoader(path, "")
		return loader.LoadBundle()
	} else if strings.HasSuffix(path, ".zip") {
		loader := NewBundleLoader("", path)
		return loader.LoadBundle()
	}
	return nil, fmt.Errorf("unsupported file type: %s", path)
}

// LoadBundle is a convenience wrapper for LoadBundleFromPath
func LoadBundle(path string) (*APIProxyBundle, error) {
	return LoadBundleFromPath(path)
}

// loadFromZip extracts a zip file and parses the bundle
func (l *BundleLoader) loadFromZip(zipPath string) (*APIProxyBundle, error) {
	tempDir, err := extractZipToTemp(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract zip: %w", err)
	}

	apiproxyDir, err := findApiproxyDir(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to find apiproxy directory: %w", err)
	}

	parser := NewXMLParser(apiproxyDir)
	bundle, err := parser.ParseBundle()
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	bundle.BasePath = apiproxyDir
	return bundle, nil
}

// loadFromDirectory loads a bundle from a directory
func (l *BundleLoader) loadFromDirectory(dirPath string) (*APIProxyBundle, error) {
	// Check if there's a YAML file in the directory
	yamlFiles, err := filepath.Glob(filepath.Join(dirPath, "*.yaml"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob YAML files: %w", err)
	}
	ymlFiles, err := filepath.Glob(filepath.Join(dirPath, "*.yml"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob YML files: %w", err)
	}
	yamlFiles = append(yamlFiles, ymlFiles...)

	if len(yamlFiles) > 0 {
		// Use YAML loader
		loader := NewYAMLLoader(dirPath)
		bundle, err := loader.LoadBundle(yamlFiles[0])
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML bundle: %w", err)
		}
		bundle.BasePath = dirPath
		return bundle, nil
	}

	// Fall back to XML parsing
	apiproxyDir, err := resolveApiproxyDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve apiproxy directory: %w", err)
	}

	parser := NewXMLParser(apiproxyDir)
	bundle, err := parser.ParseBundle()
	if err != nil {
		return nil, fmt.Errorf("failed to parse bundle: %w", err)
	}

	bundle.BasePath = apiproxyDir
	return bundle, nil
}

// extractZipToTemp extracts a zip file to a temporary directory
func extractZipToTemp(zipPath string) (string, error) {
	info, err := os.Stat(zipPath)
	if err != nil {
		return "", fmt.Errorf("zip file not found: %w", err)
	}
	if info.IsDir() {
		return zipPath, nil
	}

	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	tempDir, err := os.MkdirTemp("", "apigee-bundle-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}

		targetPath := filepath.Join(tempDir, f.Name)

		if err := os.MkdirAll(filepath.Dir(targetPath), 0755); err != nil {
			return "", fmt.Errorf("failed to create directory: %w", err)
		}

		rc, err := f.Open()
		if err != nil {
			return "", fmt.Errorf("failed to open zip file: %w", err)
		}

		outFile, err := os.Create(targetPath)
		if err != nil {
			rc.Close()
			return "", fmt.Errorf("failed to create file: %w", err)
		}

		if _, err := io.Copy(outFile, rc); err != nil {
			outFile.Close()
			rc.Close()
			return "", fmt.Errorf("failed to copy file contents: %w", err)
		}

		outFile.Close()
		rc.Close()
	}

	return tempDir, nil
}

// findApiproxyDir walks a directory to find the apiproxy root (where apiproxy.xml lives)
func findApiproxyDir(baseDir string) (string, error) {
	var apiproxyDir string

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.Name() == "apiproxy.xml" {
			apiproxyDir = filepath.Dir(path)
			return filepath.SkipAll
		}

		return nil
	})

	if err != nil && err != filepath.SkipAll {
		return "", fmt.Errorf("failed to walk directory: %w", err)
	}

	if apiproxyDir != "" {
		return apiproxyDir, nil
	}

	if hasApiproxyStructure(baseDir) {
		return baseDir, nil
	}

	apiproxyDir = filepath.Join(baseDir, "apiproxy")
	if hasApiproxyStructure(apiproxyDir) {
		return apiproxyDir, nil
	}

	return "", fmt.Errorf("could not find apiproxy bundle structure")
}

// resolveApiproxyDir resolves the apiproxy directory from a given path
func resolveApiproxyDir(dirPath string) (string, error) {
	if hasApiproxyStructure(dirPath) {
		return dirPath, nil
	}

	apiproxyDir := filepath.Join(dirPath, "apiproxy")
	if hasApiproxyStructure(apiproxyDir) {
		return apiproxyDir, nil
	}

	return findApiproxyDir(dirPath)
}

// hasApiproxyStructure checks if a directory has the expected apiproxy subdirectories
func hasApiproxyStructure(dir string) bool {
	expectedDirs := []string{"proxies", "targets", "policies"}
	for _, subdir := range expectedDirs {
		if _, err := os.Stat(filepath.Join(dir, subdir)); err == nil {
			return true
		}
	}
	return false
}

// DiscoverBundles discovers all bundles in a directory (YAML files, zip files or directories)
func DiscoverBundles(dirPath string) ([]BundleInfo, error) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var bundles []BundleInfo

	for _, entry := range entries {
		name := entry.Name()
		fullPath := filepath.Join(dirPath, name)

		if entry.IsDir() {
			// Check if directory has apiproxy structure or contains YAML files
			if hasApiproxyStructure(fullPath) {
				bundles = append(bundles, BundleInfo{
					Name:   name,
					Source: fullPath,
					Type:   "directory",
				})
			} else {
				// Check for YAML files in the directory
				yamlFiles, _ := filepath.Glob(filepath.Join(fullPath, "*.yaml"))
				ymlFiles, _ := filepath.Glob(filepath.Join(fullPath, "*.yml"))
				if len(yamlFiles)+len(ymlFiles) > 0 {
					bundles = append(bundles, BundleInfo{
						Name:   name,
						Source: fullPath,
						Type:   "yaml-directory",
					})
				}
			}
		} else if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			bundles = append(bundles, BundleInfo{
				Name:   strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml"),
				Source: fullPath,
				Type:   "yaml-file",
			})
		} else if strings.HasSuffix(name, ".zip") {
			bundles = append(bundles, BundleInfo{
				Name:   strings.TrimSuffix(name, ".zip"),
				Source: fullPath,
				Type:   "zip",
			})
		}
	}

	return bundles, nil
}

// BundleInfo contains information about a discovered bundle
type BundleInfo struct {
	Name   string
	Source string
	Type   string // "zip" or "directory"
}

// LoadBundleFromInfo loads a bundle from BundleInfo
func LoadBundleFromInfo(info BundleInfo) (*APIProxyBundle, error) {
	switch info.Type {
	case "yaml-file":
		loader := NewYAMLLoader(filepath.Dir(info.Source))
		return loader.LoadBundle(filepath.Base(info.Source))
	case "yaml-directory":
		loader := NewYAMLLoader(info.Source)
		// Find the YAML file in the directory
		yamlFiles, _ := filepath.Glob(filepath.Join(info.Source, "*.yaml"))
		ymlFiles, _ := filepath.Glob(filepath.Join(info.Source, "*.yml"))
		allYamlFiles := append(yamlFiles, ymlFiles...)
		if len(allYamlFiles) == 0 {
			return nil, fmt.Errorf("no YAML file found in directory %s", info.Source)
		}
		return loader.LoadBundle(filepath.Base(allYamlFiles[0]))
	case "zip":
		loader := NewBundleLoader("", info.Source)
		return loader.LoadBundle()
	case "directory":
		loader := NewBundleLoader(info.Source, "")
		return loader.LoadBundle()
	default:
		return nil, fmt.Errorf("unknown bundle type: %s", info.Type)
	}
}

// LoadAllBundles loads all bundles discovered in a directory
func LoadAllBundles(dirPath string) (map[string]*APIProxyBundle, error) {
	return LoadAllBundlesWithSharedFlows(dirPath, "")
}

// LoadAllBundlesWithSharedFlows loads all bundles and optionally inlines shared flows
func LoadAllBundlesWithSharedFlows(dirPath, sharedFlowDir string) (map[string]*APIProxyBundle, error) {
	return LoadAllBundlesWithOptions(dirPath, sharedFlowDir, true)
}

// LoadAllBundlesWithOptions loads all bundles with full control over shared flow inlining
func LoadAllBundlesWithOptions(dirPath, sharedFlowDir string, inlineSharedFlows bool) (map[string]*APIProxyBundle, error) {
	infos, err := DiscoverBundles(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to discover bundles: %w", err)
	}

	// Load shared flows if directory is provided
	var sharedFlows map[string]*SharedFlowBundle
	if sharedFlowDir != "" {
		if _, err := os.Stat(sharedFlowDir); err == nil {
			sharedFlows, err = LoadAllSharedFlows(sharedFlowDir)
			if err != nil {
				return nil, fmt.Errorf("failed to load shared flows: %w", err)
			}
			fmt.Fprintf(os.Stderr, "Loaded %d shared flows from %s\n", len(sharedFlows), sharedFlowDir)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: shared flow directory not found: %s\n", sharedFlowDir)
		}
	}

	result := make(map[string]*APIProxyBundle)

	for _, info := range infos {
		bundle, err := LoadBundleFromInfo(info)
		if err != nil {
			return nil, fmt.Errorf("failed to load bundle %s: %w", info.Name, err)
		}

		// Inline shared flows if requested
		InlineSharedFlows(bundle, sharedFlows, inlineSharedFlows)

		result[info.Name] = bundle
	}

	return result, nil
}
