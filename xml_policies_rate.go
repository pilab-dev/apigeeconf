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
			switch {
			case strings.EqualFold(elem.Name.Local, "Rate"):
				policy.SpikeRateRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && txt != "" {
					policy.SpikeRate = txt
				}
			case strings.EqualFold(elem.Name.Local, "Identifier"):
				policy.SpikeIdentifier = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.SpikeIdentifier == "" {
					policy.SpikeIdentifier = txt
				}
			case strings.EqualFold(elem.Name.Local, "MessageWeight"):
				policy.SpikeMessageWeight = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.SpikeMessageWeight == "" {
					policy.SpikeMessageWeight = txt
				}
			case strings.EqualFold(elem.Name.Local, "UseEffectiveCount"):
				policy.SpikeUseEffectiveCount = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "SpikeArrest") {
				return jsPolicy, policy, nil
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
			switch {
			case strings.EqualFold(elem.Name.Local, "Interval"):
				policy.QuotaIntervalRef = p.getAttributeValue(elem.Attr, "ref")
				policy.QuotaInterval = p.readInt(decoder)
			case strings.EqualFold(elem.Name.Local, "TimeUnit"):
				policy.QuotaTimeUnitRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && txt != "" {
					policy.QuotaTimeUnit = txt
				}
			case strings.EqualFold(elem.Name.Local, "Allow"):
				policy.QuotaAllowRef = p.getAttributeValue(elem.Attr, "countRef")
				policy.QuotaAllow = p.readInt(decoder)
				if policy.QuotaAllow == 0 {
					if count := p.getAttributeValue(elem.Attr, "count"); count != "" {
						fmt.Sscanf(count, "%d", &policy.QuotaAllow)
					}
				}
			case strings.EqualFold(elem.Name.Local, "StartTime"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.QuotaStartTime = txt
				}
			case strings.EqualFold(elem.Name.Local, "Identifier"):
				policy.QuotaIdentifier = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.QuotaIdentifier == "" {
					policy.QuotaIdentifier = txt
				}
			case strings.EqualFold(elem.Name.Local, "Distributed"):
				policy.QuotaDistributed = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "Synchronous"):
				policy.QuotaSynchronous = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "MessageWeight"):
				policy.QuotaMessageWeight = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.QuotaMessageWeight == "" {
					policy.QuotaMessageWeight = txt
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "Quota") {
				return jsPolicy, policy, nil
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
			switch {
			case strings.EqualFold(elem.Name.Local, "AllowConnections"):
				for _, attr := range elem.Attr {
					if strings.EqualFold(attr.Name.Local, "count") {
						fmt.Sscanf(attr.Value, "%d", &policy.ConcurrentRateAllowConnections)
					}
					if strings.EqualFold(attr.Name.Local, "ttl") {
						fmt.Sscanf(attr.Value, "%d", &policy.ConcurrentRateTTL)
					}
				}
			case strings.EqualFold(elem.Name.Local, "Distributed"):
				policy.ConcurrentRateDistributed = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "StrictOnTtl"):
				policy.ConcurrentRateStrictOnTTL = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "TargetIdentifier"):
				policy.ConcurrentRateTargetIdentifier = p.getAttributeValue(elem.Attr, "name")
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "ConcurrentRatelimit") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}
