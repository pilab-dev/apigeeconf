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
			switch {
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.Source = txt
					policy.Properties["source"] = txt
					policy.SourceClearPayload = strings.ToLower(p.getAttributeValue(elem.Attr, "clearPayload")) == "true"
				}
			case strings.EqualFold(elem.Name.Local, "VariablePrefix"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.VariablePrefix = txt
				}
			case strings.EqualFold(elem.Name.Local, "IgnoreUnresolvedVariables"):
				policy.IgnoreUnresolvedVariables = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "Variable"):
				p.parseExtractVariablesVariable(decoder, policy, p.getAttributeValue(elem.Attr, "name"))
			case strings.EqualFold(elem.Name.Local, "JSONPayload"):
				p.parseExtractVariablesPayload(decoder, "JSONPayload", policy)
			case strings.EqualFold(elem.Name.Local, "XMLPayload"):
				p.parseExtractVariablesPayload(decoder, "XMLPayload", policy)
			case strings.EqualFold(elem.Name.Local, "FormParam"):
				p.parseExtractVariablesParam(decoder, "FormParam", p.getAttributeValue(elem.Attr, "name"), policy)
			case strings.EqualFold(elem.Name.Local, "Header"):
				p.parseExtractVariablesParam(decoder, "Header", p.getAttributeValue(elem.Attr, "name"), policy)
			case strings.EqualFold(elem.Name.Local, "QueryParam"):
				p.parseExtractVariablesParam(decoder, "QueryParam", p.getAttributeValue(elem.Attr, "name"), policy)
			case strings.EqualFold(elem.Name.Local, "URIPath"):
				p.parseExtractVariablesParam(decoder, "URIPath", "", policy)
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "ExtractVariables") {
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
			if strings.EqualFold(elem.Name.Local, "Variable") {
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
						switch {
						case strings.EqualFold(t.Name.Local, "JSONPath"):
							if txt, err := p.readCharData(decoder); err == nil {
								varConfig.JSONPath = txt
								varConfig.Pattern = txt
							}
						case strings.EqualFold(t.Name.Local, "XPath"):
							if txt, err := p.readCharData(decoder); err == nil {
								varConfig.XPath = txt
								varConfig.Pattern = txt
							}
						}
					case xml.EndElement:
						if strings.EqualFold(t.Name.Local, "Variable") {
							break VariableLoop
						}
					}
				}
				policy.VariableConfigs = append(policy.VariableConfigs, varConfig)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, parentTag) {
				return
			}
		}
	}
}

func (p *XMLParser) parseExtractVariablesParam(decoder *xml.Decoder, parentTag string, name string, policy *Policy) {
	varConfig := VariableConfig{
		Type: parentTag,
	}
	switch {
	case strings.EqualFold(parentTag, "Header"):
		varConfig.HeaderName = name
	case strings.EqualFold(parentTag, "QueryParam"):
		varConfig.QueryParamName = name
	case strings.EqualFold(parentTag, "FormParam"):
		varConfig.FormParamName = name
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			if strings.EqualFold(elem.Name.Local, "Pattern") {
				varConfig.IgnoreCase = strings.ToLower(p.getAttributeValue(elem.Attr, "ignoreCase")) == "true"
				if txt, err := p.readCharData(decoder); err == nil {
					varConfig.Pattern = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, parentTag) {
				policy.VariableConfigs = append(policy.VariableConfigs, varConfig)
				return
			}
		}
	}
}

func (p *XMLParser) parseExtractVariablesVariable(decoder *xml.Decoder, policy *Policy, varName string) {
	varConfig := VariableConfig{
		Type: "Variable",
		Name: varName,
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "Pattern"):
				varConfig.IgnoreCase = strings.ToLower(p.getAttributeValue(elem.Attr, "ignoreCase")) == "true"
				if txt, err := p.readCharData(decoder); err == nil {
					varConfig.Pattern = txt
				}
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					varConfig.Source = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "Variable") {
				if varConfig.Name != "" {
					policy.VariableConfigs = append(policy.VariableConfigs, varConfig)
				}
				return
			}
		}
	}
}
