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

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "Request"):
				policy.ServiceCalloutRequest = p.getAttributeValue(elem.Attr, "variable")
				p.parseServiceCalloutRequest(decoder, policy)
			case strings.EqualFold(elem.Name.Local, "Response"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.ServiceCalloutResponse = txt
				}
			case strings.EqualFold(elem.Name.Local, "HTTPTargetConnection"):
				p.parseServiceCalloutHTTPConnection(decoder, policy)
			case strings.EqualFold(elem.Name.Local, "LocalTargetConnection"):
				// Not fully implemented in types.go yet
				decoder.Skip()
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "ServiceCallout") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseServiceCalloutRequest(decoder *xml.Decoder, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Set"):
				p.parseServiceCalloutSet(decoder, policy)
			case strings.EqualFold(t.Name.Local, "IgnoreUnresolvedVariables"):
				policy.IgnoreUnresolvedVariables = p.readBool(decoder)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Request") {
				return
			}
		}
	}
}

func (p *XMLParser) parseServiceCalloutSet(decoder *xml.Decoder, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Headers"):
				p.parseServiceCalloutHeaders(decoder, policy)
			case strings.EqualFold(t.Name.Local, "Payload"):
				if txt := p.readCharDataNested(decoder, "Payload"); txt != "" {
					policy.HTTPPayload = txt
				}
			case strings.EqualFold(t.Name.Local, "Verb"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.HTTPMethod = strings.ToUpper(txt)
					policy.Verb = policy.HTTPMethod
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Set") {
				return
			}
		}
	}
}

func (p *XMLParser) parseServiceCalloutHeaders(decoder *xml.Decoder, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Header") {
				name := p.getAttributeValue(t.Attr, "name")
				if txt, err := p.readCharData(decoder); err == nil {
					policy.HTTPHeaders[name] = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Headers") {
				return
			}
		}
	}
}

func (p *XMLParser) parseServiceCalloutHTTPConnection(decoder *xml.Decoder, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "URL") {
				if txt, err := p.readCharData(decoder); err == nil {
					policy.HTTPURL = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "HTTPTargetConnection") {
				return
			}
		}
	}
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
			switch {
			case strings.EqualFold(elem.Name.Local, "SharedFlowBundle"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.SharedFlowBundle = txt
					policy.Source = txt
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "FlowCallout") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}
