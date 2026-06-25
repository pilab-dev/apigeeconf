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
	depth := 0
	var result strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			if result.Len() == 0 {
				return "", err
			}
			return result.String(), nil
		}
		switch v := tok.(type) {
		case xml.CharData:
			result.WriteString(string(v))
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return strings.TrimSpace(result.String()), nil
			}
			depth--
		case xml.Comment:
			// Ignore comments
		case xml.ProcInst:
			// Ignore processing instructions
		case xml.Directive:
			// Ignore directives
		}
	}
}

func (p *XMLParser) readCharDataPreserve(decoder *xml.Decoder) string {
	depth := 0
	var result strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			return result.String()
		}
		switch v := tok.(type) {
		case xml.CharData:
			result.WriteString(string(v))
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return result.String()
			}
			depth--
		}
	}
}

func (p *XMLParser) readCharDataNested(decoder *xml.Decoder, parentName string) string {
	depth := 1
	var result strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			return strings.TrimSpace(result.String())
		}
		switch v := tok.(type) {
		case xml.CharData:
			result.WriteString(string(v))
		case xml.StartElement:
			result.WriteString("<" + v.Name.Local)
			for _, a := range v.Attr {
				result.WriteString(" " + a.Name.Local + "=\"" + a.Value + "\"")
			}
			result.WriteString(">")
			depth++
		case xml.EndElement:
			if v.Name.Local == parentName && depth == 1 {
				return result.String()
			}
			result.WriteString("</" + v.Name.Local + ">")
			depth--
		}
	}
}

// parseFlowStep parses a Step element
func (p *XMLParser) parseFlowStep(decoder *xml.Decoder, start xml.StartElement) FlowStep {
	step := FlowStep{}
	for _, attr := range start.Attr {
		if strings.EqualFold(attr.Name.Local, "Name") {
			step.PolicyName = attr.Value
		}
		if strings.EqualFold(attr.Name.Local, "ContinueOnError") {
			step.ContinueOnError = strings.ToLower(attr.Value) == "true"
		}
	}

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Name"):
				if txt, err := p.readCharData(decoder); err == nil {
					step.PolicyName = txt
				}
			case strings.EqualFold(t.Name.Local, "Condition"):
				if txt, err := p.readCharData(decoder); err == nil {
					step.Condition = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Step") {
				return step
			}
		}
	}
	return step
}

// parseFlowPhaseConfig parses PreFlow, PostFlow or PostClientFlow
func (p *XMLParser) parseFlowPhaseConfig(decoder *xml.Decoder, parentTag string) FlowPhaseConfig {
	config := FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	var currentSide string

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Description"):
				if txt, err := p.readCharData(decoder); err == nil {
					config.Description = txt
				}
			case strings.EqualFold(t.Name.Local, "Request"):
				currentSide = "Request"
			case strings.EqualFold(t.Name.Local, "Response"):
				currentSide = "Response"
			case strings.EqualFold(t.Name.Local, "Step"):
				step := p.parseFlowStep(decoder, t)
				if currentSide == "Request" {
					config.RequestSteps = append(config.RequestSteps, step)
				} else {
					config.ResponseSteps = append(config.ResponseSteps, step)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, parentTag) {
				return config
			}
		}
	}
	return config
}

// parseConditionalFlow parses a Flow element
func (p *XMLParser) parseConditionalFlow(decoder *xml.Decoder, start xml.StartElement) ConditionalFlow {
	flow := ConditionalFlow{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	for _, attr := range start.Attr {
		if strings.EqualFold(attr.Name.Local, "Name") {
			flow.Name = attr.Value
		}
	}

	var currentSide string
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Description"):
				if txt, err := p.readCharData(decoder); err == nil {
					flow.Description = txt
				}
			case strings.EqualFold(t.Name.Local, "Condition"):
				if txt, err := p.readCharData(decoder); err == nil {
					flow.Condition = txt
				}
			case strings.EqualFold(t.Name.Local, "Request"):
				currentSide = "Request"
			case strings.EqualFold(t.Name.Local, "Response"):
				currentSide = "Response"
			case strings.EqualFold(t.Name.Local, "Step"):
				step := p.parseFlowStep(decoder, t)
				if currentSide == "Request" {
					flow.RequestSteps = append(flow.RequestSteps, step)
				} else {
					flow.ResponseSteps = append(flow.ResponseSteps, step)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Flow") {
				return flow
			}
		}
	}
	return flow
}

// parseFaultRule parses a FaultRule element
func (p *XMLParser) parseFaultRule(decoder *xml.Decoder, start xml.StartElement) FaultRule {
	fr := FaultRule{Steps: []FlowStep{}}
	for _, attr := range start.Attr {
		if strings.EqualFold(attr.Name.Local, "Name") {
			fr.Name = attr.Value
		}
	}

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Condition"):
				if txt, err := p.readCharData(decoder); err == nil {
					fr.Condition = txt
				}
			case strings.EqualFold(t.Name.Local, "Step"):
				fr.Steps = append(fr.Steps, p.parseFlowStep(decoder, t))
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "FaultRule") {
				return fr
			}
		}
	}
	return fr
}

// parseDefaultFaultRule parses a DefaultFaultRule element
func (p *XMLParser) parseDefaultFaultRule(decoder *xml.Decoder, start xml.StartElement) DefaultFaultRule {
	dfr := DefaultFaultRule{Steps: []FlowStep{}}
	for _, attr := range start.Attr {
		if strings.EqualFold(attr.Name.Local, "AlwaysEnforce") {
			dfr.AlwaysEnforce = strings.ToLower(attr.Value) == "true"
		}
	}

	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Condition"):
				if txt, err := p.readCharData(decoder); err == nil {
					dfr.Condition = txt
				}
			case strings.EqualFold(t.Name.Local, "Step"):
				dfr.Steps = append(dfr.Steps, p.parseFlowStep(decoder, t))
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "DefaultFaultRule") {
				return dfr
			}
		}
	}
	return dfr
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

func (p *XMLParser) parseProperties(decoder *xml.Decoder, props map[string]string) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Property") {
				name := p.getAttributeValue(t.Attr, "name")
				if txt, err := p.readCharData(decoder); err == nil {
					props[name] = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Properties") {
				return
			}
		}
	}
}

// readBool returns true if the element text is "true" (case-insensitive)
func (p *XMLParser) readBool(decoder *xml.Decoder) bool {
	if txt, err := p.readCharData(decoder); err == nil {
		return strings.ToLower(txt) == "true"
	}
	return false
}

// readInt returns the integer value of the element text
func (p *XMLParser) readInt(decoder *xml.Decoder) int {
	var val int
	if txt, err := p.readCharData(decoder); err == nil {
		fmt.Sscanf(txt, "%d", &val)
	}
	return val
}

func (p *XMLParser) getAttributeValue(attrs []xml.Attr, name string) string {
	for _, attr := range attrs {
		if strings.EqualFold(attr.Name.Local, name) {
			return attr.Value
		}
	}
	return ""
}
