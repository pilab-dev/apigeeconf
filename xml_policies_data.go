package apigeeconf

import (
	"encoding/xml"
	"strings"
)

// parseKeyValueMapPolicy parses a KeyValueMapOperations policy
func (p *XMLParser) parseKeyValueMapPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:          PolicyTypeKeyValueMap,
		Name:          policyName,
		Properties:    make(map[string]string),
		KVMOperations: []KVMOperation{},
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
			case strings.EqualFold(elem.Name.Local, "KeyValueMapOperations"):
				policy.KVMMapIdentifier = p.getAttributeValue(elem.Attr, "mapIdentifier")
				if policy.KVMMapIdentifier == "" {
					policy.KVMMapIdentifier = p.getAttributeValue(elem.Attr, "name")
				}
			case strings.EqualFold(elem.Name.Local, "Scope"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.KVMScope = txt
				}
			case strings.EqualFold(elem.Name.Local, "ExpiryTimeInSecs"):
				policy.KVMExpiryTimeInSecs = p.readInt(decoder)
			case strings.EqualFold(elem.Name.Local, "ExclusiveCache"):
				policy.KVMExclusiveCache = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "Get"):
				p.parseKVMOperation(decoder, "Get", elem.Attr, policy)
			case strings.EqualFold(elem.Name.Local, "Put"):
				p.parseKVMOperation(decoder, "Put", elem.Attr, policy)
			case strings.EqualFold(elem.Name.Local, "Delete"):
				p.parseKVMOperation(decoder, "Delete", elem.Attr, policy)
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "KeyValueMapOperations") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseKVMOperation(decoder *xml.Decoder, opType string, attrs []xml.Attr, policy *Policy) {
	op := KVMOperation{
		Operation: opType,
	}

	if strings.EqualFold(opType, "Get") {
		op.AssignTo = p.getAttributeValue(attrs, "assignTo")
		policy.KVMIndex = p.getAttributeValue(attrs, "index")
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "Key"):
			KeyLoop:
				for {
					tok, err := decoder.Token()
					if err != nil {
						break
					}
					switch t := tok.(type) {
					case xml.StartElement:
						if strings.EqualFold(t.Name.Local, "Parameter") {
							ref := p.getAttributeValue(t.Attr, "ref")
							if txt, err := p.readCharData(decoder); err == nil {
								if ref != "" {
									op.Key = "ref:" + ref
								} else {
									op.Key = txt
								}
							}
						}
					case xml.EndElement:
						if strings.EqualFold(t.Name.Local, "Key") {
							break KeyLoop
						}
					}
				}
			case strings.EqualFold(elem.Name.Local, "Value"):
				ref := p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil {
					if ref != "" {
						op.Value = "ref:" + ref
					} else {
						op.Value = txt
					}
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, opType) {
				policy.KVMOperations = append(policy.KVMOperations, op)
				return
			}
		}
	}
}

// parseMessageLoggingPolicy parses a MessageLogging policy
func (p *XMLParser) parseMessageLoggingPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeMessageLogging,
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
			case strings.EqualFold(elem.Name.Local, "Syslog"):
				policy.MessageLoggingDestination = "Syslog"
				policy.MessageLoggingSyslog = &SyslogConfig{}
				p.parseSyslogConfig(decoder, policy.MessageLoggingSyslog)
			case strings.EqualFold(elem.Name.Local, "File"):
				policy.MessageLoggingDestination = "File"
				policy.MessageLoggingFile = &FileConfig{}
				p.parseFileLogConfig(decoder, policy.MessageLoggingFile)
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "MessageLogging") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseSyslogConfig(decoder *xml.Decoder, config *SyslogConfig) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Message"):
				if txt, err := p.readCharData(decoder); err == nil {
					config.Message = txt
				}
			case strings.EqualFold(t.Name.Local, "Host"):
				if txt, err := p.readCharData(decoder); err == nil {
					config.Host = txt
				}
			case strings.EqualFold(t.Name.Local, "Port"):
				config.Port = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "Protocol"):
				if txt, err := p.readCharData(decoder); err == nil {
					config.Protocol = txt
				}
			case strings.EqualFold(t.Name.Local, "FormatMessage"):
				config.FormatMessage = p.readBool(decoder)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Syslog") {
				return
			}
		}
	}
}

func (p *XMLParser) parseFileLogConfig(decoder *xml.Decoder, config *FileConfig) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Message") {
				if txt, err := p.readCharData(decoder); err == nil {
					config.Message = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "File") {
				return
			}
		}
	}
}

// parseStatisticsCollectorPolicy parses a StatisticsCollector policy
func (p *XMLParser) parseStatisticsCollectorPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeStatistics, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Statistics") {
				p.parseStatistics(decoder, policy)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "StatisticsCollector") {
				return jsPolicy, policy, nil
			}
		}
	}
	return jsPolicy, policy, nil
}

func (p *XMLParser) parseStatistics(decoder *xml.Decoder, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Statistic") {
				stat := StatisticsDimension{
					Name:  p.getAttributeValue(t.Attr, "name"),
					Ref:   p.getAttributeValue(t.Attr, "ref"),
				}
				if txt, err := p.readCharData(decoder); err == nil {
					stat.Value = txt
				}
				policy.StatisticsDimensions = append(policy.StatisticsDimensions, stat)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Statistics") {
				return
			}
		}
	}
}

// parseCORSPolicy parses a CORS policy
func (p *XMLParser) parseCORSPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeCors, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "AllowOrigins"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CORSAllowOrigins = strings.Split(txt, ",")
				}
			case strings.EqualFold(t.Name.Local, "AllowMethods"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CORSAllowMethods = strings.Split(txt, ",")
				}
			case strings.EqualFold(t.Name.Local, "AllowHeaders"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CORSAllowHeaders = strings.Split(txt, ",")
				}
			case strings.EqualFold(t.Name.Local, "ExposeHeaders"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CORSExposeHeaders = strings.Split(txt, ",")
				}
			case strings.EqualFold(t.Name.Local, "MaxAge"):
				policy.CORSMaxAge = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "AllowCredentials"):
				policy.CORSAllowCredentials = p.readBool(decoder)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "CORS") {
				return jsPolicy, policy, nil
			}
		}
	}
	return jsPolicy, policy, nil
}

// parseResponseCachePolicy parses a ResponseCache policy
func (p *XMLParser) parseResponseCachePolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeResponseCache, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "CacheKey"):
				// Handle CacheKey
			case strings.EqualFold(t.Name.Local, "ExpirySettings"):
				// Handle Expiry
			case strings.EqualFold(t.Name.Local, "CacheResource"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CacheResource = txt
				}
			case strings.EqualFold(t.Name.Local, "Scope"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CacheScope = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "ResponseCache") {
				return jsPolicy, policy, nil
			}
		}
	}
	return jsPolicy, policy, nil
}

// parsePopulateCachePolicy parses a PopulateCache policy
func (p *XMLParser) parsePopulateCachePolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypePopulateCache, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "CacheKey"):
				// Should parse children
			case strings.EqualFold(elem.Name.Local, "Source"):
				policy.CacheKeyRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.CacheKey == "" {
					policy.CacheKey = txt
				}
			case strings.EqualFold(elem.Name.Local, "ExpirySettings"):
				// Handle Expiry
			case strings.EqualFold(elem.Name.Local, "Scope"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CacheScope = txt
				}
			case strings.EqualFold(elem.Name.Local, "CacheResource"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CacheResource = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "PopulateCache") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseLookupCachePolicy parses a LookupCache policy
func (p *XMLParser) parseLookupCachePolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeLookupCache, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "CacheKey"):
				// Should parse children
			case strings.EqualFold(elem.Name.Local, "AssignTo"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheAssignTo = txt
				}
			case strings.EqualFold(elem.Name.Local, "Scope"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheScope = txt
				}
			case strings.EqualFold(elem.Name.Local, "CacheResource"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheResource = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "LookupCache") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseInvalidateCachePolicy parses a InvalidateCache policy
func (p *XMLParser) parseInvalidateCachePolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeInvalidateCache, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseJSONtoXMLPolicy parses a JSONtoXML policy
func (p *XMLParser) parseJSONtoXMLPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeJSONtoXML, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseXMLtoJSONPolicy parses a XMLtoJSON policy
func (p *XMLParser) parseXMLtoJSONPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:             PolicyTypeXMLtoJSON,
		Name:             policyName,
		Properties:       make(map[string]string),
		XMLToJSONOptions: make(map[string]string),
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
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XMLToJSONSource = txt
					policy.Source = txt // Compatibility
				}
			case strings.EqualFold(elem.Name.Local, "OutputVariable"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XMLToJSONOutputVariable = txt
				}
			case strings.EqualFold(elem.Name.Local, "Options"):
				p.parseXMLToJSONOptions(decoder, policy)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "XMLtoJSON") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseXMLToJSONOptions(decoder *xml.Decoder, policy *Policy) {
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			if txt, err := p.readCharData(decoder); err == nil {
				policy.XMLToJSONOptions[elem.Name.Local] = txt
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "Options") {
				return
			}
		}
	}
}

// parseXSLTransformPolicy parses a XSLTransform policy
func (p *XMLParser) parseXSLTransformPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeXSLTransform, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XSLSource = txt
				}
			case strings.EqualFold(elem.Name.Local, "ResourceURL"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XSLResource = txt
				}
			case strings.EqualFold(elem.Name.Local, "OutputVariable"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XSLOutputVariable = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "XSLTransform") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseAccessEntityPolicy parses a AccessEntity policy
func (p *XMLParser) parseAccessEntityPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeAccessEntity, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseExtensionCalloutPolicy parses a ExtensionCallout policy
func (p *XMLParser) parseExtensionCalloutPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeExtensionCallout, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseHMACPolicy parses a HMAC policy
func (p *XMLParser) parseHMACPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeHMAC, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}
