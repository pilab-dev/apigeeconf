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
	}

	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	proxy.PreFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	proxy.PostFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	proxy.PostClientFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}

	var currentFlow string
	var currentSide string
	var inCondition bool
	var inHTTPProxyConn bool
	var inFaultRules bool
	var inDefaultFaultRule bool
	var inDescription bool
	var currentFaultRule *FaultRule
	var currentDefaultFaultRule *DefaultFaultRule
	var descTarget string // tracks which element we're reading description for

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "ProxyEndpoint":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						proxy.Name = attr.Value
					}
				}
			case "HTTPProxyConnection":
				inHTTPProxyConn = true
			case "BasePath":
				if inHTTPProxyConn {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							proxy.BasePath = strings.TrimSpace(string(char))
							proxy.HTTPProxyConn.BasePath = proxy.BasePath
						}
					}
				}
			case "VirtualHost":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						vh := strings.TrimSpace(string(char))
						if vh != "" {
							proxy.VirtualHost = append(proxy.VirtualHost, vh)
							proxy.HTTPProxyConn.VirtualHost = append(proxy.HTTPProxyConn.VirtualHost, vh)
						}
					}
				}
			case "PreFlow":
				currentFlow = "PreFlow"
			case "PostFlow":
				currentFlow = "PostFlow"
			case "PostClientFlow":
				currentFlow = "PostClientFlow"
			case "Flows":
				currentFlow = "Flows"
			case "Flow":
				flow := ConditionalFlow{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						flow.Name = attr.Value
					}
				}
				proxy.ConditionalFlows = append(proxy.ConditionalFlows, flow)
				currentFlow = "Flow"
			case "Description":
				inDescription = true
				switch currentFlow {
				case "PreFlow":
					descTarget = "PreFlow"
				case "PostFlow":
					descTarget = "PostFlow"
				case "PostClientFlow":
					descTarget = "PostClientFlow"
				case "Flow":
					descTarget = "Flow"
				}
			case "Condition":
				if currentFlow == "Flow" || currentFlow == "RouteRule" {
					inCondition = true
				}
			case "Request":
				currentSide = "Request"
			case "Response":
				currentSide = "Response"
			case "Step":
				step := FlowStep{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "Name" {
						step.PolicyName = attr.Value
					}
				}
				if step.PolicyName == "" {
					for {
						tok, err := decoder.Token()
						if err != nil {
							break
						}
						if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "Name" {
							if tok2, err := decoder.Token(); err == nil {
								if char, ok := tok2.(xml.CharData); ok {
									step.PolicyName = strings.TrimSpace(string(char))
								}
							}
						}
						if end, ok := tok.(xml.EndElement); ok && end.Name.Local == "Step" {
							break
						}
					}
				}
				if currentFlow == "PreFlow" {
					if currentSide == "Request" {
						proxy.PreFlow.RequestSteps = append(proxy.PreFlow.RequestSteps, step)
					} else {
						proxy.PreFlow.ResponseSteps = append(proxy.PreFlow.ResponseSteps, step)
					}
				} else if currentFlow == "PostFlow" {
					if currentSide == "Request" {
						proxy.PostFlow.RequestSteps = append(proxy.PostFlow.RequestSteps, step)
					} else {
						proxy.PostFlow.ResponseSteps = append(proxy.PostFlow.ResponseSteps, step)
					}
				} else if currentFlow == "PostClientFlow" {
					if currentSide == "Response" {
						proxy.PostClientFlow.ResponseSteps = append(proxy.PostClientFlow.ResponseSteps, step)
					}
				} else if currentFlow == "Flow" && len(proxy.ConditionalFlows) > 0 {
					if currentSide == "Request" {
						proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].RequestSteps =
							append(proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].RequestSteps, step)
					} else {
						proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].ResponseSteps =
							append(proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].ResponseSteps, step)
					}
				} else if inFaultRules && currentFaultRule != nil {
					currentFaultRule.Steps = append(currentFaultRule.Steps, step)
				} else if inDefaultFaultRule && currentDefaultFaultRule != nil {
					currentDefaultFaultRule.Steps = append(currentDefaultFaultRule.Steps, step)
				}
			case "Name":
				// Only handle Name inside Step (already handled inline above)
			case "RouteRule":
				rule := RouteRule{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						rule.Name = attr.Value
					}
				}
				proxy.RouteRules = append(proxy.RouteRules, rule)
				currentFlow = "RouteRule"
			case "FaultRules":
				inFaultRules = true
			case "FaultRule":
				if inFaultRules {
					fr := FaultRule{}
					for _, attr := range elem.Attr {
						if attr.Name.Local == "name" {
							fr.Name = attr.Value
						}
					}
					proxy.FaultRules = append(proxy.FaultRules, fr)
					currentFaultRule = &proxy.FaultRules[len(proxy.FaultRules)-1]
				}
			case "DefaultFaultRule":
				inDefaultFaultRule = true
				proxy.DefaultFaultRule = &DefaultFaultRule{}
				currentDefaultFaultRule = proxy.DefaultFaultRule
				for _, attr := range elem.Attr {
					if attr.Name.Local == "alwaysEnforce" {
						proxy.DefaultFaultRule.AlwaysEnforce = strings.ToLower(attr.Value) == "true"
					}
				}
			case "Property":
				var propName, propValue string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						propName = attr.Value
					}
				}
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						propValue = strings.TrimSpace(string(char))
					}
				}
				if propName != "" {
					if proxy.Properties == nil {
						proxy.Properties = make(map[string]string)
					}
					proxy.Properties[propName] = propValue
					if proxy.HTTPProxyConn.Properties == nil {
						proxy.HTTPProxyConn.Properties = make(map[string]string)
					}
					proxy.HTTPProxyConn.Properties[propName] = propValue
				}
			}
		case xml.CharData:
			if inCondition {
				condition := strings.TrimSpace(string(elem))
				if currentFlow == "Flow" && len(proxy.ConditionalFlows) > 0 {
					proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].Condition = condition
				} else if currentFlow == "RouteRule" && len(proxy.RouteRules) > 0 {
					proxy.RouteRules[len(proxy.RouteRules)-1].Condition = condition
				} else if inFaultRules && currentFaultRule != nil {
					currentFaultRule.Condition = condition
				} else if inDefaultFaultRule && currentDefaultFaultRule != nil {
					currentDefaultFaultRule.Condition = condition
				}
				inCondition = false
			}
			if inDescription {
				desc := strings.TrimSpace(string(elem))
				switch descTarget {
				case "PreFlow":
					proxy.PreFlow.Description = desc
				case "PostFlow":
					proxy.PostFlow.Description = desc
				case "PostClientFlow":
					proxy.PostClientFlow.Description = desc
				case "Flow":
					if len(proxy.ConditionalFlows) > 0 {
						proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].Description = desc
					}
				}
				inDescription = false
			}
		case xml.EndElement:
			switch elem.Name.Local {
			case "PreFlow", "PostFlow", "PostClientFlow":
				currentFlow = ""
			case "Flows":
				currentFlow = ""
			case "HTTPProxyConnection":
				inHTTPProxyConn = false
			case "FaultRules":
				inFaultRules = false
				currentFaultRule = nil
			case "FaultRule":
				currentFaultRule = nil
			case "DefaultFaultRule":
				inDefaultFaultRule = false
				currentDefaultFaultRule = nil
			case "RouteRule":
				currentFlow = ""
			case "Description":
				inDescription = false
			}
		}
	}

	// Second pass to resolve RouteRule target endpoints
	decoder = xml.NewDecoder(strings.NewReader(string(data)))
	var inRouteRule bool
	var currentRouteRule *RouteRule
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local == "RouteRule" {
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						for i := range proxy.RouteRules {
							if proxy.RouteRules[i].Name == attr.Value {
								currentRouteRule = &proxy.RouteRules[i]
								inRouteRule = true
								break
							}
						}
					}
				}
			}
			if inRouteRule && elem.Name.Local == "TargetEndpoint" {
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						currentRouteRule.TargetEndpoint = strings.TrimSpace(string(char))
					}
				}
			}
			if inRouteRule && elem.Name.Local == "URL" {
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						currentRouteRule.URL = strings.TrimSpace(string(char))
					}
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "RouteRule" {
				inRouteRule = false
				currentRouteRule = nil
			}
		}
	}

	return proxy, nil
}
