package apigeeconf

import (
	"encoding/xml"
	"os"
	"strings"
)

// parseProxyEndpointFile parses a proxy endpoint XML file
func (p *XMLParser) parseProxyEndpointFile(path string) (*ProxyEndpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	proxy := &ProxyEndpoint{
		ConditionalFlows: []ConditionalFlow{},
		RouteRules:       []RouteRule{},
		Properties:       make(map[string]string),
		PreFlow:          FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}},
		PostFlow:         FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}},
		PostClientFlow:   FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}},
	}

	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "ProxyEndpoint"):
				proxy.Name = p.getAttributeValue(elem.Attr, "name")
			case strings.EqualFold(elem.Name.Local, "HTTPProxyConnection"):
				p.parseHTTPProxyConnection(decoder, proxy)
			case strings.EqualFold(elem.Name.Local, "PreFlow"):
				proxy.PreFlow = p.parseFlowPhaseConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "PostFlow"):
				proxy.PostFlow = p.parseFlowPhaseConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "PostClientFlow"):
				proxy.PostClientFlow = p.parseFlowPhaseConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "Flows"):
				// Continue parsing children (Flow elements)
			case strings.EqualFold(elem.Name.Local, "Flow"):
				proxy.ConditionalFlows = append(proxy.ConditionalFlows, p.parseConditionalFlow(decoder, elem))
			case strings.EqualFold(elem.Name.Local, "RouteRule"):
				proxy.RouteRules = append(proxy.RouteRules, p.parseRouteRule(decoder, elem))
			case strings.EqualFold(elem.Name.Local, "FaultRules"):
				// Continue parsing children (FaultRule elements)
			case strings.EqualFold(elem.Name.Local, "FaultRule"):
				proxy.FaultRules = append(proxy.FaultRules, p.parseFaultRule(decoder, elem))
			case strings.EqualFold(elem.Name.Local, "DefaultFaultRule"):
				dfr := p.parseDefaultFaultRule(decoder, elem)
				proxy.DefaultFaultRule = &dfr
			}
		}
	}

	return proxy, nil
}

func (p *XMLParser) parseHTTPProxyConnection(decoder *xml.Decoder, proxy *ProxyEndpoint) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "BasePath"):
				if txt, err := p.readCharData(decoder); err == nil {
					proxy.BasePath = txt
					proxy.HTTPProxyConn.BasePath = txt
				}
			case strings.EqualFold(t.Name.Local, "VirtualHost"):
				if txt, err := p.readCharData(decoder); err == nil {
					if txt != "" {
						proxy.VirtualHost = append(proxy.VirtualHost, txt)
						proxy.HTTPProxyConn.VirtualHost = append(proxy.HTTPProxyConn.VirtualHost, txt)
					}
				}
			case strings.EqualFold(t.Name.Local, "Properties"):
				p.parseProperties(decoder, proxy.Properties)
				// Sync to HTTPProxyConn as well for compatibility
				if proxy.HTTPProxyConn.Properties == nil {
					proxy.HTTPProxyConn.Properties = make(map[string]string)
				}
				for k, v := range proxy.Properties {
					proxy.HTTPProxyConn.Properties[k] = v
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "HTTPProxyConnection") {
				return
			}
		}
	}
}

func (p *XMLParser) parseRouteRule(decoder *xml.Decoder, start xml.StartElement) RouteRule {
	rule := RouteRule{
		Name: p.getAttributeValue(start.Attr, "name"),
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
					rule.Condition = txt
				}
			case strings.EqualFold(t.Name.Local, "TargetEndpoint"):
				if txt, err := p.readCharData(decoder); err == nil {
					rule.TargetEndpoint = txt
				}
			case strings.EqualFold(t.Name.Local, "URL"):
				if txt, err := p.readCharData(decoder); err == nil {
					rule.URL = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "RouteRule") {
				return rule
			}
		}
	}
	return rule
}
