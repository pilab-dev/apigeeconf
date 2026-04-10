package apigeeconf

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// parseSpikeArrestPolicy parses a SpikeArrest policy
func (p *XMLParser) parseSpikeArrestPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeSpikeArrest,
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
			case "Rate":
				var rateRef string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						rateRef = attr.Value
					}
				}
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						rate := strings.TrimSpace(string(char))
						if rate != "" {
							policy.SpikeRate = rate
						}
					}
				}
				if rateRef != "" {
					policy.SpikeRateRef = rateRef
				}
			case "Identifier":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.SpikeIdentifier = attr.Value
					}
				}
			case "MessageWeight":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.SpikeMessageWeight = attr.Value
					}
				}
			case "UseEffectiveCount":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						val := strings.TrimSpace(string(char))
						policy.SpikeUseEffectiveCount = strings.ToLower(val) == "true"
					}
				}
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseQuotaPolicy parses a Quota policy
func (p *XMLParser) parseQuotaPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeQuota,
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
			case "Interval":
				var intervalRef string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						intervalRef = attr.Value
					}
				}
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						val := strings.TrimSpace(string(char))
						if val != "" {
							fmt.Sscanf(val, "%d", &policy.QuotaInterval)
						}
					}
				}
				if intervalRef != "" {
					policy.QuotaIntervalRef = intervalRef
				}
			case "TimeUnit":
				var timeUnitRef string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						timeUnitRef = attr.Value
					}
				}
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						val := strings.TrimSpace(string(char))
						if val != "" {
							policy.QuotaTimeUnit = val
						}
					}
				}
				if timeUnitRef != "" {
					policy.QuotaTimeUnitRef = timeUnitRef
				}
			case "Allow":
				var countRef string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "count" {
						fmt.Sscanf(attr.Value, "%d", &policy.QuotaAllow)
					}
					if attr.Name.Local == "countRef" {
						countRef = attr.Value
					}
				}
				if tok, err := decoder.Token(); err == nil {
					// Check for Class element
					if start, ok := tok.(xml.StartElement); ok && start.Name.Local == "Class" {
						// Skip Class for now
					}
				}
				if countRef != "" {
					policy.QuotaAllowRef = countRef
				}
			case "StartTime":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						policy.QuotaStartTime = strings.TrimSpace(string(char))
					}
				}
			case "Identifier":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.QuotaIdentifier = attr.Value
					}
				}
			case "Distributed":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						val := strings.TrimSpace(string(char))
						policy.QuotaDistributed = strings.ToLower(val) == "true"
					}
				}
			case "Synchronous":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						val := strings.TrimSpace(string(char))
						policy.QuotaSynchronous = strings.ToLower(val) == "true"
					}
				}
			case "MessageWeight":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.QuotaMessageWeight = attr.Value
					}
				}
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseConcurrentRatePolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeConcurrentRate, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "AllowConnections":
				for _, attr := range elem.Attr {
					switch attr.Name.Local {
					case "count":
						fmt.Sscanf(attr.Value, "%d", &policy.ConcurrentRateAllowConnections)
					case "ttl":
						fmt.Sscanf(attr.Value, "%d", &policy.ConcurrentRateTTL)
					}
				}
			case "Distributed":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.ConcurrentRateDistributed = txt == "true"
				}
			case "StrictOnTtl":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.ConcurrentRateStrictOnTTL = txt == "true"
				}
			case "TargetIdentifier":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						policy.ConcurrentRateTargetIdentifier = attr.Value
					}
				}
			}
		}
	}

	return jsPolicy, policy, nil
}
