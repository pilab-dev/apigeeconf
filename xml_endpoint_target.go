package apigeeconf

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
)

// parseTargetEndpointFile parses a target endpoint XML file
func (p *XMLParser) parseTargetEndpointFile(path string) (*TargetEndpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	target := &TargetEndpoint{
		Properties: make(map[string]string),
	}

	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	var currentFlow string
	var currentSide string
	var inHTTPTargetConn bool
	var inSSLInfo bool
	var inLoadBalancer bool
	var inHealthMonitor bool
	var inHTTPMonitor bool
	var inLocalTargetConn bool
	var inScriptTarget bool
	var inFaultRules bool
	var inDefaultFaultRule bool
	var currentFaultRule *FaultRule
	var currentDefaultFaultRule *DefaultFaultRule
	var currentLBServer LoadBalancerServer

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "TargetEndpoint":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						target.Name = attr.Value
					}
				}
			case "PreFlow":
				currentFlow = "PreFlow"
			case "PostFlow":
				currentFlow = "PostFlow"
			case "Flows":
				currentFlow = "Flows"
			case "Flow":
				currentFlow = "Flow"
			case "Request":
				currentSide = "Request"
			case "Response":
				currentSide = "Response"
			case "HTTPTargetConnection":
				inHTTPTargetConn = true
				currentFlow = "HTTPTargetConnection"
			case "URL":
				if inHTTPTargetConn {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.URL = strings.TrimSpace(string(char))
						}
					}
				}
			case "SSLInfo":
				inSSLInfo = true
				for _, attr := range elem.Attr {
					if attr.Name.Local == "enabled" {
						target.SSLInfo.Enabled = strings.ToLower(attr.Value) == "true"
					}
				}
			case "Enabled":
				if inSSLInfo {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.SSLInfo.Enabled = strings.ToLower(strings.TrimSpace(string(char))) == "true"
						}
					}
				}
			case "ClientAuthEnabled":
				if inSSLInfo {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.SSLInfo.ClientAuthEnabled = strings.ToLower(strings.TrimSpace(string(char))) == "true"
						}
					}
				}
			case "Keystore":
				if inSSLInfo {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.SSLInfo.Keystore = strings.TrimSpace(string(char))
						}
					}
				}
			case "Truststore":
				if inSSLInfo {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.SSLInfo.Truststore = strings.TrimSpace(string(char))
						}
					}
				}
			case "IgnoreValidationErrors":
				if inSSLInfo {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.SSLInfo.IgnoreValidationErrors = strings.ToLower(strings.TrimSpace(string(char))) == "true"
						}
					}
				}
			case "CommonName":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "wildcardMatch" {
						target.SSLInfo.CommonName.WildcardMatch = strings.ToLower(attr.Value) == "true"
					}
				}
			case "LoadBalancer":
				inLoadBalancer = true
				target.LoadBalancer = &LoadBalancer{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "algorithm" {
						target.LoadBalancer.Algorithm = attr.Value
					}
				}
			case "Server":
				if inLoadBalancer {
					currentLBServer = LoadBalancerServer{}
					for _, attr := range elem.Attr {
						if attr.Name.Local == "name" {
							currentLBServer.Name = attr.Value
						}
						if attr.Name.Local == "weight" {
							fmt.Sscanf(attr.Value, "%d", &currentLBServer.Weight)
						}
					}
				}
			case "MaxFailures":
				if inLoadBalancer {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							fmt.Sscanf(strings.TrimSpace(string(char)), "%d", &target.LoadBalancer.MaxFailures)
						}
					}
				}
			case "IsFallback":
				if inLoadBalancer {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							currentLBServer.IsFallback = strings.ToLower(strings.TrimSpace(string(char))) == "true"
						}
					}
				}
			case "PathSuffix":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						target.PathSuffix = strings.TrimSpace(string(char))
					}
				}
			case "Connection":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						target.Connection = strings.TrimSpace(string(char))
					}
				}
			case "HealthMonitor":
				inHealthMonitor = true
				target.HealthMonitor = &HealthMonitor{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "isEnabled" {
						target.HealthMonitor.IsEnabled = strings.ToLower(attr.Value) == "true"
					}
				}
			case "IntervalInSec":
				if inHealthMonitor {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							fmt.Sscanf(strings.TrimSpace(string(char)), "%d", &target.HealthMonitor.IntervalInSec)
						}
					}
				}
			case "HTTPMonitor":
				inHTTPMonitor = true
				target.HealthMonitor.HTTPMonitor = &HTTPMonitor{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "port" {
						fmt.Sscanf(attr.Value, "%d", &target.HealthMonitor.HTTPMonitor.Port)
					}
				}
			case "ConnectTimeoutInSec":
				if inHTTPMonitor {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							fmt.Sscanf(strings.TrimSpace(string(char)), "%d", &target.HealthMonitor.HTTPMonitor.Request.ConnectTimeoutInSec)
						}
					}
				}
			case "SocketReadTimeoutInSec":
				if inHTTPMonitor {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							fmt.Sscanf(strings.TrimSpace(string(char)), "%d", &target.HealthMonitor.HTTPMonitor.Request.SocketReadTimeoutInSec)
						}
					}
				}
			case "PayloadLimitInKB":
				if inHTTPMonitor {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							fmt.Sscanf(strings.TrimSpace(string(char)), "%d", &target.HealthMonitor.HTTPMonitor.Request.PayloadLimitInKB)
						}
					}
				}
			case "Verb":
				if inHTTPMonitor {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.HealthMonitor.HTTPMonitor.Request.Verb = strings.TrimSpace(string(char))
						}
					}
				}
			case "LocalTargetConnection":
				inLocalTargetConn = true
			case "APIProxy":
				if inLocalTargetConn {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.LocalTargetConn.APIProxy = strings.TrimSpace(string(char))
						}
					}
				}
			case "ProxyEndpoint":
				if inLocalTargetConn {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.LocalTargetConn.ProxyEndpoint = strings.TrimSpace(string(char))
						}
					}
				}
			case "ScriptTarget":
				inScriptTarget = true
			case "ResourceURL":
				if inScriptTarget {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							target.ScriptTarget.ResourceURL = strings.TrimSpace(string(char))
						}
					}
				}
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
						target.PreFlow.RequestSteps = append(target.PreFlow.RequestSteps, step)
					} else {
						target.PreFlow.ResponseSteps = append(target.PreFlow.ResponseSteps, step)
					}
				} else if currentFlow == "PostFlow" {
					if currentSide == "Request" {
						target.PostFlow.RequestSteps = append(target.PostFlow.RequestSteps, step)
					} else {
						target.PostFlow.ResponseSteps = append(target.PostFlow.ResponseSteps, step)
					}
				} else if inFaultRules && currentFaultRule != nil {
					currentFaultRule.Steps = append(currentFaultRule.Steps, step)
				} else if inDefaultFaultRule && currentDefaultFaultRule != nil {
					currentDefaultFaultRule.Steps = append(currentDefaultFaultRule.Steps, step)
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
					target.Properties[propName] = propValue
				}
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
					target.FaultRules = append(target.FaultRules, fr)
					currentFaultRule = &target.FaultRules[len(target.FaultRules)-1]
				}
			case "DefaultFaultRule":
				inDefaultFaultRule = true
				target.DefaultFaultRule = &DefaultFaultRule{}
				currentDefaultFaultRule = target.DefaultFaultRule
				for _, attr := range elem.Attr {
					if attr.Name.Local == "alwaysEnforce" {
						target.DefaultFaultRule.AlwaysEnforce = strings.ToLower(attr.Value) == "true"
					}
				}
			}
		case xml.CharData:
			// Handle CharData for elements like Server name inside LoadBalancer
		case xml.EndElement:
			switch elem.Name.Local {
			case "PreFlow", "PostFlow", "Flows":
				currentFlow = ""
			case "HTTPTargetConnection":
				inHTTPTargetConn = false
				currentFlow = ""
			case "SSLInfo":
				inSSLInfo = false
			case "LoadBalancer":
				inLoadBalancer = false
			case "HealthMonitor":
				inHealthMonitor = false
			case "HTTPMonitor":
				inHTTPMonitor = false
			case "LocalTargetConnection":
				inLocalTargetConn = false
			case "ScriptTarget":
				inScriptTarget = false
			case "FaultRules":
				inFaultRules = false
				currentFaultRule = nil
			case "FaultRule":
				currentFaultRule = nil
			case "DefaultFaultRule":
				inDefaultFaultRule = false
				currentDefaultFaultRule = nil
			}
		}
	}

	return target, nil
}
