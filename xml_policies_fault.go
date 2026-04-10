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
			switch elem.Name.Local {
			case "FaultResponse":
				p.parseFaultResponse(decoder, policy)
			case "IgnoreUnresolvedVariables":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.IgnoreUnresolvedVariables = strings.ToLower(txt) == "true"
				}
			case "AssignTo":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.RaiseFaultAssignTo = txt
					policy.AssignTo = txt // Compatibility
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "RaiseFault" {
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
			switch elem.Name.Local {
			case "Set":
				p.parseFaultResponseAction(decoder, "Set", policy.FaultResponse)
			case "Add":
				p.parseFaultResponseAction(decoder, "Add", policy.FaultResponse)
			case "Remove":
				p.parseFaultResponseAction(decoder, "Remove", policy.FaultResponse)
			case "Copy":
				p.parseFaultResponseAction(decoder, "Copy", policy.FaultResponse)
			}
		case xml.EndElement:
			if elem.Name.Local == "FaultResponse" {
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
			switch elem.Name.Local {
			case "StatusCode":
				if txt, err := p.readCharData(decoder); err == nil {
					if action == "Set" {
						config.StatusCode = txt
					} else if action == "Copy" {
						config.CopyStatusCode = true
					}
				}
			case "ReasonPhrase":
				if txt, err := p.readCharData(decoder); err == nil {
					if action == "Set" {
						config.ReasonPhrase = txt
					} else if action == "Copy" {
						config.CopyReasonPhrase = true
					}
				}
			case "Payload":
				config.PayloadContentType = p.getAttributeValue(elem.Attr, "contentType")
				if txt, err := p.readCharData(decoder); err == nil {
					config.Payload = txt
				}
			case "Header":
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
			if elem.Name.Local == action {
				return
			}
		}
	}
}
