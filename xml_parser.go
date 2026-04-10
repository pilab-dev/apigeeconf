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
	possibleFiles := []string{"apiproxy.xml", "SAP.xml", "APIProxy.xml"}
	var apiproxyData []byte
	for _, name := range possibleFiles {
		apiproxyXML := filepath.Join(p.basePath, name)
		if data, err := os.ReadFile(apiproxyXML); err == nil {
			apiproxyData = data
			break
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

func (p *XMLParser) getAttributeValue(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if attr.Name.Local == name {
			return attr.Value
		}
	}
	return ""
}
