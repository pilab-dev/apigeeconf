package apigeeconf

import (
	"encoding/xml"
	"strings"
)

// parseServiceCalloutPolicy parses a ServiceCallout policy
func (p *XMLParser) parseServiceCalloutPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:        PolicyTypeServiceCallout,
		Name:        policyName,
		HTTPHeaders: make(map[string]string),
		Properties:  make(map[string]string),
	}

	jsPolicy := &JavaScriptPolicy{
		Name:       policyName,
		Properties: make(map[string]string),
		Includes:   []string{},
	}

	var currentElement string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			currentElement = elem.Name.Local
			switch elem.Name.Local {
			case "Request":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "clear" {
						// Handle clear attribute
					}
				}
			case "Set":
				// Headers, Payload, Verb, etc.
			case "HTTPHeader":
				var headerName, headerValue string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						headerName = attr.Value
					}
				}
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						headerValue = strings.TrimSpace(string(char))
					}
				}
				if headerName != "" {
					policy.HTTPHeaders[headerName] = headerValue
				}
			case "Payload":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						policy.HTTPPayload = string(char)
					}
				}
			case "Verb":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						policy.HTTPMethod = strings.ToUpper(strings.TrimSpace(string(char)))
					}
				}
			case "Response":
				// Response variable name
			case "LocalTargetConnection":
				// Internal callout target
			case "HTTPURL":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						policy.HTTPURL = strings.TrimSpace(string(char))
					}
				}
			}
		case xml.CharData:
			if currentElement == "Response" {
				respVar := strings.TrimSpace(string(elem))
				if respVar != "" {
					policy.ServiceCalloutResponse = respVar
				}
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseFlowCalloutPolicy parses a FlowCallout policy
func (p *XMLParser) parseFlowCalloutPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeFlowCallout,
		Name:       policyName,
		Properties: make(map[string]string),
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
			case "SharedFlowBundle":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.SharedFlowBundle = txt
					policy.Source = txt // Keep for backwards compatibility
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "FlowCallout" {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}
