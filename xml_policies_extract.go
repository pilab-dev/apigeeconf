package apigeeconf

import (
	"encoding/xml"
	"strings"
)

// parseExtractVariablesPolicy parses an ExtractVariables policy
func (p *XMLParser) parseExtractVariablesPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:            PolicyTypeExtractVariables,
		Name:            policyName,
		VariableConfigs: []VariableConfig{},
		Properties:      make(map[string]string),
	}

	jsPolicy := &JavaScriptPolicy{
		Name:       policyName,
		Properties: make(map[string]string),
		Includes:   []string{},
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Source":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.Source = txt
					policy.Properties["source"] = txt
				}
			case "VariablePrefix":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.VariablePrefix = txt
				}
			case "IgnoreUnresolvedVariables":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.IgnoreUnresolvedVariables = strings.ToLower(txt) == "true"
				}
			case "JSONPayload":
				p.parseExtractVariablesPayload(decoder, "JSONPayload", policy)
			case "XMLPayload":
				p.parseExtractVariablesPayload(decoder, "XMLPayload", policy)
			case "FormParam":
				name := p.getAttributeValue(elem.Attr, "name")
				p.parseExtractVariablesParam(decoder, "FormParam", name, policy)
			case "Header":
				name := p.getAttributeValue(elem.Attr, "name")
				p.parseExtractVariablesParam(decoder, "Header", name, policy)
			case "QueryParam":
				name := p.getAttributeValue(elem.Attr, "name")
				p.parseExtractVariablesParam(decoder, "QueryParam", name, policy)
			case "URIPath":
				p.parseExtractVariablesParam(decoder, "URIPath", "", policy)
			}
		case xml.EndElement:
			if elem.Name.Local == "ExtractVariables" {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseExtractVariablesPayload(decoder *xml.Decoder, parentTag string, policy *Policy) {
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local == "Variable" {
				varConfig := VariableConfig{
					Name: p.getAttributeValue(elem.Attr, "name"),
					Type: strings.TrimSuffix(parentTag, "Payload"),
				}
			VariableLoop:
				for {
					tok, err := decoder.Token()
					if err != nil {
						break
					}
					switch t := tok.(type) {
					case xml.StartElement:
						if t.Name.Local == "JSONPath" {
							if txt, err := p.readCharData(decoder); err == nil {
								varConfig.JSONPath = txt
								varConfig.Pattern = txt
							}
						} else if t.Name.Local == "XPath" {
							if txt, err := p.readCharData(decoder); err == nil {
								varConfig.XPath = txt
								varConfig.Pattern = txt
							}
						}
					case xml.EndElement:
						if t.Name.Local == "Variable" {
							break VariableLoop
						}
					}
				}
				policy.VariableConfigs = append(policy.VariableConfigs, varConfig)
			}
		case xml.EndElement:
			if elem.Name.Local == parentTag {
				return
			}
		}
	}
}

func (p *XMLParser) parseExtractVariablesParam(decoder *xml.Decoder, parentTag string, name string, policy *Policy) {
	varConfig := VariableConfig{
		Type: parentTag,
	}
	switch parentTag {
	case "Header":
		varConfig.HeaderName = name
	case "QueryParam":
		varConfig.QueryParamName = name
	case "FormParam":
		varConfig.FormParamName = name
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local == "Pattern" {
				if txt, err := p.readCharData(decoder); err == nil {
					varConfig.Pattern = txt
				}
			}
		case xml.EndElement:
			if elem.Name.Local == parentTag {
				policy.VariableConfigs = append(policy.VariableConfigs, varConfig)
				return
			}
		}
	}
}
