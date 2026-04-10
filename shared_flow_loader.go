package apigeeconf

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
)

// SharedFlowBundle represents a parsed Apigee shared flow bundle
type SharedFlowBundle struct {
	Name        string
	BasePath    string
	SharedFlows map[string]*SharedFlowDefinition
	PoliciesMap map[string]*Policy
}

// SharedFlowDefinition represents a single shared flow definition (like default.xml)
type SharedFlowDefinition struct {
	Name          string
	RequestSteps  []FlowStep
	ResponseSteps []FlowStep
}

// LoadAllSharedFlows loads all shared flow bundles from the given directory
func LoadAllSharedFlows(dirPath string) (map[string]*SharedFlowBundle, error) {
	sharedFlows := make(map[string]*SharedFlowBundle)

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read shared flows directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		sfDir := filepath.Join(dirPath, entry.Name(), "sharedflowbundle")
		if _, err := os.Stat(sfDir); err != nil {
			continue
		}

		sfBundle, err := loadSingleSharedFlow(sfDir, entry.Name())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to load shared flow %s: %v\n", entry.Name(), err)
			continue
		}

		sharedFlows[entry.Name()] = sfBundle
	}

	return sharedFlows, nil
}

func loadSingleSharedFlow(sfDir, name string) (*SharedFlowBundle, error) {
	parser := NewXMLParser(sfDir)
	bundle, err := parser.ParseBundle()
	if err != nil {
		return nil, fmt.Errorf("failed to parse shared flow bundle: %w", err)
	}

	sfBundle := &SharedFlowBundle{
		Name:        name,
		BasePath:    sfDir,
		SharedFlows: make(map[string]*SharedFlowDefinition),
		PoliciesMap: bundle.PoliciesMap,
	}

	// Parse shared flow definitions from sharedflows/ directory
	sfDirPath := filepath.Join(sfDir, "sharedflows")
	sfEntries, err := os.ReadDir(sfDirPath)
	if err != nil {
		return sfBundle, nil
	}

	for _, sfEntry := range sfEntries {
		if sfEntry.IsDir() || filepath.Ext(sfEntry.Name()) != ".xml" {
			continue
		}

		sfPath := filepath.Join(sfDirPath, sfEntry.Name())
		sfDef, err := parseSharedFlowDefinition(sfPath)
		if err != nil {
			continue
		}

		sfBundle.SharedFlows[sfDef.Name] = sfDef
	}

	return sfBundle, nil
}

// SharedFlowXML represents the raw XML structure of a shared flow definition
type SharedFlowXML struct {
	XMLName xml.Name `xml:"SharedFlow"`
	Name    string   `xml:"name,attr"`
	Steps   []struct {
		Name      string `xml:"Name"`
		Condition string `xml:"Condition"`
	} `xml:"Step"`
}

func parseSharedFlowDefinition(path string) (*SharedFlowDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var sfXML SharedFlowXML
	if err := xml.Unmarshal(data, &sfXML); err != nil {
		return nil, err
	}

	sfDef := &SharedFlowDefinition{
		Name: sfXML.Name,
	}

	for _, step := range sfXML.Steps {
		sfDef.RequestSteps = append(sfDef.RequestSteps, FlowStep{
			PolicyName: step.Name,
			Condition:  step.Condition,
		})
	}

	return sfDef, nil
}
