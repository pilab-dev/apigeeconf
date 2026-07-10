package apigeeconf

import (
	"encoding/xml"
	"strings"
)

// parseRaiseFaultPolicy parses a RaiseFault policy
func (p *XMLParser) parseRaiseFaultPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeRaiseFault,
		Name:       policyName,
		Properties: make(map[string]string),
	}

	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "FaultResponse"):
				p.parseFaultResponse(decoder, policy)
			case strings.EqualFold(elem.Name.Local, "IgnoreUnresolvedVariables"):
				policy.IgnoreUnresolvedVariables = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "AssignTo"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.RaiseFaultAssignTo = txt
					policy.AssignTo = txt // Compatibility
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "RaiseFault") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseFaultResponse(decoder *xml.Decoder, policy *Policy) {
	policy.FaultResponse = &FaultResponseConfig{
		Headers: make(map[string]string),
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
				p.parseFaultResponseAction(decoder, "Set", policy.FaultResponse)
			case strings.EqualFold(elem.Name.Local, "Add"):
				p.parseFaultResponseAction(decoder, "Add", policy.FaultResponse)
			case strings.EqualFold(elem.Name.Local, "Remove"):
				p.parseFaultResponseAction(decoder, "Remove", policy.FaultResponse)
			case strings.EqualFold(elem.Name.Local, "Copy"):
				p.parseFaultResponseAction(decoder, "Copy", policy.FaultResponse)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "FaultResponse") {
				return
			}
		}
	}
}

func (p *XMLParser) parseFaultResponseAction(decoder *xml.Decoder, action string, config *FaultResponseConfig) {
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "StatusCode"):
				if txt, err := p.readCharData(decoder); err == nil {
					if action == "Set" {
						config.StatusCode = txt
					} else if action == "Copy" {
						config.CopyStatusCode = true
					}
				}
			case strings.EqualFold(elem.Name.Local, "ReasonPhrase"):
				if txt, err := p.readCharData(decoder); err == nil {
					if action == "Set" {
						config.ReasonPhrase = txt
					} else if action == "Copy" {
						config.CopyReasonPhrase = true
					}
				}
			case strings.EqualFold(elem.Name.Local, "Payload"):
				config.PayloadContentType = p.getAttributeValue(elem.Attr, "contentType")
				if txt := p.readCharDataNested(decoder, "Payload"); txt != "" {
					config.Payload = txt
				}
			case strings.EqualFold(elem.Name.Local, "Header"):
				name := p.getAttributeValue(elem.Attr, "name")
				if txt, err := p.readCharData(decoder); err == nil {
					if action == "Set" || action == "Add" {
						config.Headers[name] = txt
					} else if action == "Remove" {
						config.RemoveHeaders = append(config.RemoveHeaders, name)
					} else if action == "Copy" {
						config.CopyHeaders = append(config.CopyHeaders, name)
					}
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, action) {
				return
			}
		}
	}
}
