package apigeeconf

import (
	"encoding/xml"
	"fmt"
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
			switch elem.Name.Local {
			case "KeyValueMapOperations":
				policy.KVMMapIdentifier = p.getAttributeValue(elem.Attr, "mapIdentifier")
				if policy.KVMMapIdentifier == "" {
					policy.KVMMapIdentifier = p.getAttributeValue(elem.Attr, "name")
				}
			case "Scope":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.KVMScope = txt
				}
			case "ExpiryTimeInSecs":
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &policy.KVMExpiryTimeInSecs)
				}
			case "ExclusiveCache":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.KVMExclusiveCache = strings.ToLower(txt) == "true"
				}
			case "Get":
				p.parseKVMOperation(decoder, "Get", elem.Attr, policy)
			case "Put":
				p.parseKVMOperation(decoder, "Put", elem.Attr, policy)
			case "Delete":
				p.parseKVMOperation(decoder, "Delete", elem.Attr, policy)
			}
		case xml.EndElement:
			if elem.Name.Local == "KeyValueMapOperations" {
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

	if opType == "Get" {
		policy.KVMAssignTo = p.getAttributeValue(attrs, "assignTo")
		policy.KVMIndex = p.getAttributeValue(attrs, "index")
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Key":
				// Parse Key which contains multiple Parameter elements
			KeyLoop:
				for {
					tok, err := decoder.Token()
					if err != nil {
						break
					}
					switch t := tok.(type) {
					case xml.StartElement:
						if t.Name.Local == "Parameter" {
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
						if t.Name.Local == "Key" {
							break KeyLoop
						}
					}
				}
			case "Value":
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
			if elem.Name.Local == opType {
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

	var inSyslog bool
	var inFile bool
	var inMessage bool
	var messageBuilder strings.Builder

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Syslog":
				inSyslog = true
				policy.MessageLoggingDestination = "Syslog"
				policy.MessageLoggingSyslog = &SyslogConfig{}
			case "File":
				inFile = true
				policy.MessageLoggingDestination = "File"
				policy.MessageLoggingFile = &FileConfig{}
			case "Message":
				inMessage = true
				messageBuilder.Reset()
			case "Host":
				if inSyslog {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							policy.MessageLoggingSyslog.Host = strings.TrimSpace(string(char))
						}
					}
				}
			case "Port":
				if inSyslog {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							fmt.Sscanf(strings.TrimSpace(string(char)), "%d", &policy.MessageLoggingSyslog.Port)
						}
					}
				}
			case "Protocol":
				if inSyslog {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							policy.MessageLoggingSyslog.Protocol = strings.TrimSpace(string(char))
						}
					}
				}
			case "FormatMessage":
				if inSyslog {
					if tok, err := decoder.Token(); err == nil {
						if char, ok := tok.(xml.CharData); ok {
							val := strings.TrimSpace(string(char))
							policy.MessageLoggingSyslog.FormatMessage = strings.ToLower(val) == "true"
						}
					}
				}
			case "FileName":
				if inFile {
					// Not stored in FileConfig currently
				}
			case "logLevel":
				// Not stored currently
			case "BufferMessage":
				// Not stored currently
			}
		case xml.CharData:
			if inMessage {
				messageBuilder.WriteString(string(elem))
			}
		case xml.EndElement:
			switch elem.Name.Local {
			case "Syslog":
				inSyslog = false
			case "File":
				inFile = false
			case "Message":
				inMessage = false
				msg := messageBuilder.String()
				if policy.MessageLoggingDestination == "Syslog" && policy.MessageLoggingSyslog != nil {
					policy.MessageLoggingSyslog.Message = msg
				} else if policy.MessageLoggingDestination == "File" && policy.MessageLoggingFile != nil {
					policy.MessageLoggingFile.Message = msg
				}
				policy.MessageLoggingFormat = msg
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseStatisticsCollectorPolicy parses a StatisticsCollector policy
func (p *XMLParser) parseStatisticsCollectorPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeStatistics, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseCORSPolicy parses a CORS policy
func (p *XMLParser) parseCORSPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeCors, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseResponseCachePolicy parses a ResponseCache policy
func (p *XMLParser) parseResponseCachePolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeResponseCache, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
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
			switch elem.Name.Local {
			case "CacheKey":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CacheKey = txt
				}
			case "Source":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.CacheKeyRef = attr.Value
					}
				}
				if txt, err := p.readCharData(decoder); err == nil {
					if policy.CacheKey == "" {
						policy.CacheKey = txt
					}
				}
			case "Expiry":
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &policy.CacheExpiry)
				}
			case "Scope":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CacheScope = txt
				}
			case "Timeout":
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &policy.CacheTimeout)
				}
			case "CacheResource":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.CacheResource = txt
				}
			default:
				if len(elem.Attr) > 0 {
					for _, attr := range elem.Attr {
						if attr.Name.Local == "ref" {
							policy.CacheValueRef = attr.Value
						}
					}
				}
				decoder.Skip()
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
			switch elem.Name.Local {
			case "CacheKey":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheKey = txt
				}
			case "Source":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.LookupCacheKeyRef = attr.Value
					}
				}
				if txt, err := p.readCharData(decoder); err == nil {
					if policy.LookupCacheKey == "" {
						policy.LookupCacheKey = txt
					}
				}
			case "Scope":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheScope = txt
				}
			case "AssignTo":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheAssignTo = txt
				}
			case "CacheResource":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheResource = txt
				}
			case "SkipCacheOnHit":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.LookupCacheSkipCacheOnHit = txt == "true"
				}
			default:
				decoder.Skip()
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
			switch elem.Name.Local {
			case "Source":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XMLToJSONSource = txt
					policy.Source = txt // Compatibility
				}
			case "OutputVariable":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XMLToJSONOutputVariable = txt
				}
			case "Options":
				p.parseXMLToJSONOptions(decoder, policy)
			}
		case xml.EndElement:
			if elem.Name.Local == "XMLtoJSON" {
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
			if elem.Name.Local == "Options" {
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
			switch elem.Name.Local {
			case "Source":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XSLSource = txt
				}
			case "ResourceURL":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XSLResource = txt
				}
			case "OutputVariable":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.XSLOutputVariable = txt
				}
			case "Parameters":
				decoder.Skip()
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

// parseJavaCalloutPolicy parses a JavaCallout policy
func (p *XMLParser) parseJavaCalloutPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeJavaCallout, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parsePythonScriptPolicy parses a PythonScript policy
func (p *XMLParser) parsePythonScriptPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypePythonScript, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseResetQuotaPolicy parses a ResetQuota policy
func (p *XMLParser) parseResetQuotaPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeResetQuota, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}
