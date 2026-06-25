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
		Properties:       make(map[string]string),
		ConditionalFlows: []ConditionalFlow{},
		PreFlow:          FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}},
		PostFlow:         FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}},
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
			case strings.EqualFold(elem.Name.Local, "TargetEndpoint"):
				target.Name = p.getAttributeValue(elem.Attr, "name")
			case strings.EqualFold(elem.Name.Local, "PreFlow"):
				target.PreFlow = p.parseFlowPhaseConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "PostFlow"):
				target.PostFlow = p.parseFlowPhaseConfig(decoder, elem.Name.Local)
			case strings.EqualFold(elem.Name.Local, "Flows"):
				// Continue parsing children (Flow elements)
			case strings.EqualFold(elem.Name.Local, "Flow"):
				target.ConditionalFlows = append(target.ConditionalFlows, p.parseConditionalFlow(decoder, elem))
			case strings.EqualFold(elem.Name.Local, "HTTPTargetConnection"):
				p.parseHTTPTargetConnection(decoder, target)
			case strings.EqualFold(elem.Name.Local, "LocalTargetConnection"):
				p.parseLocalTargetConnection(decoder, target)
			case strings.EqualFold(elem.Name.Local, "ScriptTarget"):
				p.parseScriptTarget(decoder, target)
			case strings.EqualFold(elem.Name.Local, "FaultRules"):
				// Continue parsing children
			case strings.EqualFold(elem.Name.Local, "FaultRule"):
				target.FaultRules = append(target.FaultRules, p.parseFaultRule(decoder, elem))
			case strings.EqualFold(elem.Name.Local, "DefaultFaultRule"):
				dfr := p.parseDefaultFaultRule(decoder, elem)
				target.DefaultFaultRule = &dfr
			}
		}
	}

	return target, nil
}

func (p *XMLParser) parseHTTPTargetConnection(decoder *xml.Decoder, target *TargetEndpoint) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "URL"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.URL = txt
				}
			case strings.EqualFold(t.Name.Local, "SSLInfo"):
				p.parseSSLInfo(decoder, t, target)
			case strings.EqualFold(t.Name.Local, "LoadBalancer"):
				p.parseLoadBalancer(decoder, t, target)
			case strings.EqualFold(t.Name.Local, "HealthMonitor"):
				p.parseHealthMonitor(decoder, t, target)
			case strings.EqualFold(t.Name.Local, "Properties"):
				p.parseProperties(decoder, target.Properties)
			case strings.EqualFold(t.Name.Local, "PathSuffix") || strings.EqualFold(t.Name.Local, "Path"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.PathSuffix = txt
				}
			case strings.EqualFold(t.Name.Local, "Connection"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.Connection = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "HTTPTargetConnection") {
				return
			}
		}
	}
}

func (p *XMLParser) parseSSLInfo(decoder *xml.Decoder, start xml.StartElement, target *TargetEndpoint) {
	target.SSLInfo.Enabled = strings.ToLower(p.getAttributeValue(start.Attr, "enabled")) == "true"
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Enabled"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.SSLInfo.Enabled = strings.ToLower(txt) == "true"
				}
			case strings.EqualFold(t.Name.Local, "ClientAuthEnabled"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.SSLInfo.ClientAuthEnabled = strings.ToLower(txt) == "true"
				}
			case strings.EqualFold(t.Name.Local, "Keystore"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.SSLInfo.Keystore = txt
				}
			case strings.EqualFold(t.Name.Local, "Truststore"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.SSLInfo.Truststore = txt
				}
			case strings.EqualFold(t.Name.Local, "IgnoreValidationErrors"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.SSLInfo.IgnoreValidationErrors = strings.ToLower(txt) == "true"
				}
			case strings.EqualFold(t.Name.Local, "CommonName"):
				target.SSLInfo.CommonName.WildcardMatch = strings.ToLower(p.getAttributeValue(t.Attr, "wildcardMatch")) == "true"
				if txt, err := p.readCharData(decoder); err == nil {
					target.SSLInfo.CommonName.Value = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "SSLInfo") {
				return
			}
		}
	}
}

func (p *XMLParser) parseLoadBalancer(decoder *xml.Decoder, start xml.StartElement, target *TargetEndpoint) {
	target.LoadBalancer = &LoadBalancer{
		Algorithm: p.getAttributeValue(start.Attr, "algorithm"),
		Server:    []LoadBalancerServer{},
	}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Server"):
				server := LoadBalancerServer{
					Name: p.getAttributeValue(t.Attr, "name"),
				}
				if weight := p.getAttributeValue(t.Attr, "weight"); weight != "" {
					fmt.Sscanf(weight, "%d", &server.Weight)
				}
				target.LoadBalancer.Server = append(target.LoadBalancer.Server, server)
			case strings.EqualFold(t.Name.Local, "MaxFailures"):
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &target.LoadBalancer.MaxFailures)
				}
			case strings.EqualFold(t.Name.Local, "RetryEnabled"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.LoadBalancer.RetryEnabled = strings.ToLower(txt) == "true"
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "LoadBalancer") {
				return
			}
		}
	}
}

func (p *XMLParser) parseHealthMonitor(decoder *xml.Decoder, start xml.StartElement, target *TargetEndpoint) {
	target.HealthMonitor = &HealthMonitor{
		IsEnabled: strings.ToLower(p.getAttributeValue(start.Attr, "isEnabled")) == "true",
	}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "IntervalInSec"):
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &target.HealthMonitor.IntervalInSec)
				}
			case strings.EqualFold(t.Name.Local, "HTTPMonitor"):
				target.HealthMonitor.HTTPMonitor = &HTTPMonitor{}
				if port := p.getAttributeValue(t.Attr, "port"); port != "" {
					fmt.Sscanf(port, "%d", &target.HealthMonitor.HTTPMonitor.Port)
				}
				p.parseHTTPMonitor(decoder, target.HealthMonitor.HTTPMonitor)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "HealthMonitor") {
				return
			}
		}
	}
}

func (p *XMLParser) parseHTTPMonitor(decoder *xml.Decoder, monitor *HTTPMonitor) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Request"):
				// Handle inner Request properties if needed
			case strings.EqualFold(t.Name.Local, "Verb"):
				if txt, err := p.readCharData(decoder); err == nil {
					monitor.Request.Verb = txt
				}
			case strings.EqualFold(t.Name.Local, "Path"):
				if txt, err := p.readCharData(decoder); err == nil {
					monitor.Request.Path = txt
				}
			case strings.EqualFold(t.Name.Local, "ConnectTimeoutInSec"):
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &monitor.Request.ConnectTimeoutInSec)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "HTTPMonitor") {
				return
			}
		}
	}
}

func (p *XMLParser) parseLocalTargetConnection(decoder *xml.Decoder, target *TargetEndpoint) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "APIProxy"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.LocalTargetConn.APIProxy = txt
				}
			case strings.EqualFold(t.Name.Local, "ProxyEndpoint"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.LocalTargetConn.ProxyEndpoint = txt
				}
			case strings.EqualFold(t.Name.Local, "Path"):
				if txt, err := p.readCharData(decoder); err == nil {
					target.LocalTargetConn.PathSuffix = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "LocalTargetConnection") {
				return
			}
		}
	}
}

func (p *XMLParser) parseScriptTarget(decoder *xml.Decoder, target *TargetEndpoint) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "ResourceURL") {
				if txt, err := p.readCharData(decoder); err == nil {
					target.ScriptTarget.ResourceURL = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "ScriptTarget") {
				return
			}
		}
	}
}
