package apigeeconf

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// XMLParser parses Apigee API proxy XML configurations
type XMLParser struct {
	basePath string
}

// NewXMLParser creates a new XML parser
func NewXMLParser(basePath string) *XMLParser {
	return &XMLParser{basePath: basePath}
}

// ParseBundle parses the entire API proxy bundle
func (p *XMLParser) ParseBundle() (*APIProxyBundle, error) {
	bundle := &APIProxyBundle{
		ProxyEndpoints:  make(map[string]*ProxyEndpoint),
		TargetEndpoints: make(map[string]*TargetEndpoint),
		Policies:        make(map[string]*JavaScriptPolicy),
		PoliciesMap:     make(map[string]*Policy),
		BasePath:        p.basePath,
	}

	// Parse apiproxy.xml (or SAP.xml for some bundles)
	// Also handles bundles like AgreementManagementAPI.xml, etc.
	possibleFiles := []string{"apiproxy.xml", "SAP.xml", "APIProxy.xml"}
	var apiproxyData []byte
	for _, name := range possibleFiles {
		apiproxyXML := filepath.Join(p.basePath, name)
		if data, err := os.ReadFile(apiproxyXML); err == nil {
			apiproxyData = data
			break
		}
	}
	// If no match, look for any XML file in basePath that looks like the proxy definition
	if apiproxyData == nil {
		if files, err := os.ReadDir(p.basePath); err == nil {
			for _, f := range files {
				if strings.HasSuffix(f.Name(), ".xml") {
					if data, err := os.ReadFile(filepath.Join(p.basePath, f.Name())); err == nil {
						apiproxyData = data
						break
					}
				}
			}
		}
	}
	if apiproxyData != nil {
		if err := p.parseApiproxyXML(apiproxyData, bundle); err != nil {
			return nil, fmt.Errorf("failed to parse apiproxy.xml: %w", err)
		}
		if bundle.Name == "" {
			bundle.Name = filepath.Base(p.basePath)
		}
	}

	// Parse policies
	policiesDir := filepath.Join(p.basePath, "policies")
	if files, err := os.ReadDir(policiesDir); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xml") {
				jsPolicy, genericPolicy, err := p.parsePolicyFile(filepath.Join(policiesDir, f.Name()))
				if err != nil {
					return nil, fmt.Errorf("failed to parse policy %s: %w", f.Name(), err)
				}
				if jsPolicy != nil && genericPolicy != nil {
					// Store in both maps for compatibility
					bundle.Policies[jsPolicy.Name] = jsPolicy
					bundle.PoliciesMap[genericPolicy.Name] = genericPolicy
				}
			}
		}
	}

	// Parse proxy endpoints
	proxiesDir := filepath.Join(p.basePath, "proxies")
	if files, err := os.ReadDir(proxiesDir); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xml") {
				proxy, err := p.parseProxyEndpointFile(filepath.Join(proxiesDir, f.Name()))
				if err != nil {
					return nil, fmt.Errorf("failed to parse proxy %s: %w", f.Name(), err)
				}
				if proxy != nil {
					bundle.ProxyEndpoints[proxy.Name] = proxy
				}
			}
		}
	}

	// Parse target endpoints
	targetsDir := filepath.Join(p.basePath, "targets")
	if files, err := os.ReadDir(targetsDir); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xml") {
				target, err := p.parseTargetEndpointFile(filepath.Join(targetsDir, f.Name()))
				if err != nil {
					return nil, fmt.Errorf("failed to parse target %s: %w", f.Name(), err)
				}
				if target != nil {
					bundle.TargetEndpoints[target.Name] = target
				}
			}
		}
	}

	// Parse embedded shared flows (bundled with proxy)
	sharedFlowsDir := filepath.Join(p.basePath, "sharedflows")
	if files, err := os.ReadDir(sharedFlowsDir); err == nil {
		bundle.SharedFlows = make(map[string]*SharedFlowDefinition)
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xml") {
				sfDef, err := p.parseSharedFlowFile(filepath.Join(sharedFlowsDir, f.Name()))
				if err != nil {
					return nil, fmt.Errorf("failed to parse shared flow %s: %w", f.Name(), err)
				}
				if sfDef != nil {
					bundle.SharedFlows[sfDef.Name] = sfDef
				}
			}
		}
	}

	return bundle, nil
}

// toGenericPolicy converts JavaScriptPolicy to generic Policy
func (p *XMLParser) toGenericPolicy(jp *JavaScriptPolicy) *Policy {
	return &Policy{
		Type:       PolicyTypeJavaScript,
		Name:       jp.Name,
		Source:     jp.Source,
		ScriptURL:  jp.ScriptURL,
		Properties: jp.Properties,
		TimeLimit:  jp.TimeLimit,
		Includes:   jp.Includes,
	}
}

// ResolveJSCPath converts jsc:// path to filesystem path
func (p *XMLParser) ResolveJSCPath(jscPath string) string {
	name := strings.TrimPrefix(jscPath, "jsc://")
	return filepath.Join(p.basePath, "resources", "jsc", name)
}

func (p *XMLParser) readCharData(decoder *xml.Decoder) (string, error) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			return "", err
		}
		if char, ok := tok.(xml.CharData); ok {
			return strings.TrimSpace(string(char)), nil
		}
		if _, ok := tok.(xml.EndElement); ok {
			return "", nil
		}
	}
}

// parseSharedFlowFile parses a shared flow XML file and returns SharedFlowDefinition
func (p *XMLParser) parseSharedFlowFile(path string) (*SharedFlowDefinition, error) {
	flowName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	return parseSharedFlowDefinitionXML(path, flowName)
}

// ParseSharedFlowBundle parses a shared flow bundle (SharedFlowBundle format)
func (p *XMLParser) ParseSharedFlowBundle() (*APIProxyBundle, error) {
	bundle := &APIProxyBundle{
		ProxyEndpoints:  make(map[string]*ProxyEndpoint),
		TargetEndpoints: make(map[string]*TargetEndpoint),
		Policies:        make(map[string]*JavaScriptPolicy),
		PoliciesMap:     make(map[string]*Policy),
		BasePath:        p.basePath,
	}

	// Find and parse sharedflowbundle.xml
	var sfData []byte
	sfFiles := []string{"sharedflowbundle.xml", "sharedflow.xml"}
	for _, name := range sfFiles {
		sfXML := filepath.Join(p.basePath, name)
		if data, err := os.ReadFile(sfXML); err == nil {
			sfData = data
			break
		}
	}
	// If no match, look for any XML file
	if sfData == nil {
		if files, err := os.ReadDir(p.basePath); err == nil {
			for _, f := range files {
				if strings.HasSuffix(f.Name(), ".xml") {
					if data, err := os.ReadFile(filepath.Join(p.basePath, f.Name())); err == nil {
						sfData = data
						break
					}
				}
			}
		}
	}

	if sfData != nil {
		var root struct {
			XMLName     xml.Name `xml:"SharedFlowBundle"`
			Name        string   `xml:"name,attr"`
			Revision    string   `xml:"revision,attr"`
			SharedFlows []struct {
				Name string `xml:"name,attr"`
			} `xml:"SharedFlows>SharedFlow"`
			Policies []string `xml:"Policies>Policy"`
		}
		if err := xml.Unmarshal(sfData, &root); err == nil {
			bundle.Name = root.Name
			bundle.Revision = root.Revision
		}
		if bundle.Name == "" {
			bundle.Name = filepath.Base(p.basePath)
		}
	}

	// Parse policies
	policiesDir := filepath.Join(p.basePath, "policies")
	if files, err := os.ReadDir(policiesDir); err == nil {
		for _, f := range files {
			if strings.HasSuffix(f.Name(), ".xml") {
				jsPolicy, genericPolicy, err := p.parsePolicyFile(filepath.Join(policiesDir, f.Name()))
				if err != nil {
					return nil, fmt.Errorf("failed to parse policy %s: %w", f.Name(), err)
				}
				if jsPolicy != nil && genericPolicy != nil {
					bundle.Policies[jsPolicy.Name] = jsPolicy
					bundle.PoliciesMap[genericPolicy.Name] = genericPolicy
				}
			}
		}
	}

	return bundle, nil
}

func (p *XMLParser) getAttributeValue(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}
