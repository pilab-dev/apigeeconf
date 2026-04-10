package apigeeconf

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	bundle, err := parser.ParseSharedFlowBundle()
	if err != nil {
		return nil, fmt.Errorf("failed to parse shared flow bundle: %w", err)
	}

	sfBundle := &SharedFlowBundle{
		Name:        name,
		BasePath:    sfDir,
		SharedFlows: make(map[string]*SharedFlowDefinition),
		PoliciesMap: bundle.PoliciesMap,
	}

	sfDirPath := filepath.Join(sfDir, "sharedflows")
	if _, err := os.Stat(sfDirPath); err != nil {
		sfDirPath = filepath.Join(sfDir, "sharedflowbundle", "sharedflows")
		if _, err := os.Stat(sfDirPath); err != nil {
			return sfBundle, nil
		}
	}
	sfEntries, err := os.ReadDir(sfDirPath)
	if err != nil {
		return sfBundle, nil
	}

	for _, sfEntry := range sfEntries {
		if sfEntry.IsDir() || filepath.Ext(sfEntry.Name()) != ".xml" {
			continue
		}

		sfDef, err := parseSharedFlowDefinitionXML(filepath.Join(sfDirPath, sfEntry.Name()), name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse shared flow %s: %v\n", sfEntry.Name(), err)
			continue
		}

		sfBundle.SharedFlows[sfDef.Name] = sfDef
	}

	return sfBundle, nil
}

func parseSharedFlowDefinitionXML(path, flowName string) (*SharedFlowDefinition, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	sfDef := &SharedFlowDefinition{
		Name: flowName,
	}

	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	var currentSide string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "SharedFlow":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						sfDef.Name = attr.Value
					}
				}
			case "Request":
				currentSide = "Request"
			case "Response":
				currentSide = "Response"
			case "Step":
				var stepName string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						stepName = attr.Value
					}
				}
				if stepName != "" {
					if currentSide == "Request" {
						sfDef.RequestSteps = append(sfDef.RequestSteps, FlowStep{PolicyName: stepName})
					} else if currentSide == "Response" {
						sfDef.ResponseSteps = append(sfDef.ResponseSteps, FlowStep{PolicyName: stepName})
					}
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "Request" || elem.Name.Local == "Response" {
				currentSide = ""
			}
		}
	}

	return sfDef, nil
}
