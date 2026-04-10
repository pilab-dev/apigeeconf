package apigeeconf

import (
	"encoding/xml"
	"strings"
)

// parseAssignMessagePolicy parses an AssignMessage policy
func (p *XMLParser) parseAssignMessagePolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:            PolicyTypeAssignMessage,
		Name:            policyName,
		Headers:         make(map[string]string),
		AssignVariables: make(map[string]string),
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
			case "Set":
				config, _ := p.parseAssignMessageConfig(decoder, "Set")
				policy.AssignMessageSet = config
				// Also populate main Policy fields for compatibility
				if config.Verb != "" {
					policy.Verb = config.Verb
				}
				if config.Payload != "" {
					policy.Payload = config.Payload
				}
				for k, v := range config.Headers {
					policy.Headers[k] = v
				}
			case "Add":
				config, _ := p.parseAssignMessageConfig(decoder, "Add")
				policy.AssignMessageAdd = config
			case "Remove":
				config, _ := p.parseAssignMessageConfig(decoder, "Remove")
				policy.AssignMessageRemove = config
			case "Copy":
				config, _ := p.parseAssignMessageConfig(decoder, "Copy")
				policy.AssignMessageCopy = config
			case "Replace":
				config, _ := p.parseAssignMessageConfig(decoder, "Replace")
				policy.AssignMessageReplace = config
			case "AssignVariable":
				var varName, varValue, varRef string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "Name" {
						varName = attr.Value
					}
				}
			AssignVarLoop:
				for {
					tok, err := decoder.Token()
					if err != nil {
						break
					}
					switch t := tok.(type) {
					case xml.StartElement:
						switch t.Name.Local {
						case "Name":
							if txt, err := p.readCharData(decoder); err == nil {
								varName = txt
							}
						case "Value", "Template":
							if txt, err := p.readCharData(decoder); err == nil {
								varValue = txt
							}
						case "Ref":
							if txt, err := p.readCharData(decoder); err == nil {
								varRef = txt
							}
						}
					case xml.EndElement:
						if t.Name.Local == "AssignVariable" {
							break AssignVarLoop
						}
					}
				}
				if varName != "" {
					if varRef != "" {
						policy.AssignVariables[varName] = "ref:" + varRef
					} else {
						policy.AssignVariables[varName] = varValue
					}
				}
			case "IgnoreUnresolvedVariables":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.IgnoreUnresolvedVariables = strings.ToLower(txt) == "true"
				}
			case "AssignTo":
				policy.AssignMessageAssignToType = p.getAttributeValue(elem.Attr, "type")
				if txt, err := p.readCharData(decoder); err == nil && txt != "" {
					policy.AssignMessageAssignTo = txt
					policy.AssignTo = txt // Keep for backwards compatibility
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "AssignMessage" {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseAssignMessageConfig(decoder *xml.Decoder, parentTag string) (*AssignMessageConfig, error) {
	config := &AssignMessageConfig{
		Headers:     make(map[string]string),
		QueryParams: make(map[string]string),
		FormParams:  make(map[string]string),
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Header":
				name := p.getAttributeValue(elem.Attr, "name")
				if val, err := p.readCharData(decoder); err == nil {
					config.Headers[name] = val
				}
			case "QueryParam":
				name := p.getAttributeValue(elem.Attr, "name")
				if val, err := p.readCharData(decoder); err == nil {
					config.QueryParams[name] = val
				}
			case "FormParam":
				name := p.getAttributeValue(elem.Attr, "name")
				if val, err := p.readCharData(decoder); err == nil {
					config.FormParams[name] = val
				}
			case "Payload":
				if val, err := p.readCharData(decoder); err == nil {
					config.Payload = val
				}
			case "Verb":
				if val, err := p.readCharData(decoder); err == nil {
					config.Verb = strings.ToUpper(val)
				}
			case "Path":
				if val, err := p.readCharData(decoder); err == nil {
					config.Path = val
				}
			}
		case xml.EndElement:
			if elem.Name.Local == parentTag {
				return config, nil
			}
		}
	}
	return config, nil
}
