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
			switch {
			case strings.EqualFold(elem.Name.Local, "Set"):
				config := p.parseAssignMessageConfig(decoder, elem.Name.Local)
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
			case strings.EqualFold(elem.Name.Local, "Add"):
				policy.AssignMessageAdd = p.parseAssignMessageConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "Remove"):
				policy.AssignMessageRemove = p.parseAssignMessageConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "Copy"):
				policy.AssignMessageCopy = p.parseAssignMessageConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "Replace"):
				policy.AssignMessageReplace = p.parseAssignMessageConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "AssignVariable"):
				p.parseAssignVariable(decoder, elem, policy)
			case strings.EqualFold(elem.Name.Local, "IgnoreUnresolvedVariables"):
				policy.IgnoreUnresolvedVariables = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "AssignTo"):
				policy.AssignMessageAssignToType = p.getAttributeValue(elem.Attr, "type")
				if txt, err := p.readCharData(decoder); err == nil && txt != "" {
					policy.AssignMessageAssignTo = txt
					policy.AssignTo = txt
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "AssignMessage") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseAssignVariable(decoder *xml.Decoder, start xml.StartElement, policy *Policy) {
	var varName, varValue, varRef, varTemplate string
	varName = p.getAttributeValue(start.Attr, "Name")

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
					varName = txt
				}
			case strings.EqualFold(t.Name.Local, "Value"):
				if txt, err := p.readCharData(decoder); err == nil {
					varValue = txt
				}
			case strings.EqualFold(t.Name.Local, "Ref"):
				if txt, err := p.readCharData(decoder); err == nil {
					varRef = txt
				}
			case strings.EqualFold(t.Name.Local, "Template"):
				if txt, err := p.readCharData(decoder); err == nil {
					varTemplate = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "AssignVariable") {
				if varName != "" {
					val := varValue
					if varTemplate != "" {
						val = varTemplate
					}
					if varRef != "" {
						policy.AssignVariables[varName] = "ref:" + varRef
					} else {
						policy.AssignVariables[varName] = val
					}
				}
				return
			}
		}
	}
}

func (p *XMLParser) parseAssignMessageConfig(decoder *xml.Decoder, parentTag string) *AssignMessageConfig {
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
			switch {
			case strings.EqualFold(elem.Name.Local, "Header"):
				name := p.getAttributeValue(elem.Attr, "name")
				if val, err := p.readCharData(decoder); err == nil {
					config.Headers[name] = val
				}
			case strings.EqualFold(elem.Name.Local, "QueryParam"):
				name := p.getAttributeValue(elem.Attr, "name")
				if val, err := p.readCharData(decoder); err == nil {
					config.QueryParams[name] = val
				}
			case strings.EqualFold(elem.Name.Local, "FormParam"):
				name := p.getAttributeValue(elem.Attr, "name")
				if val, err := p.readCharData(decoder); err == nil {
					config.FormParams[name] = val
				}
			case strings.EqualFold(elem.Name.Local, "Payload"):
				if val := p.readCharDataNested(decoder, "Payload"); val != "" {
					config.Payload = val
				}
			case strings.EqualFold(elem.Name.Local, "Verb"):
				if val, err := p.readCharData(decoder); err == nil {
					config.Verb = strings.ToUpper(val)
				}
			case strings.EqualFold(elem.Name.Local, "Path"):
				if val, err := p.readCharData(decoder); err == nil {
					config.Path = val
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, parentTag) {
				return config
			}
		}
	}
	return config
}
