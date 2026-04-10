package apigeeconf

import (
	"encoding/xml"
	"os"
	"strings"
)

// parsePolicyFile parses any policy XML file (JS or AssignMessage, etc.)
func (p *XMLParser) parsePolicyFile(path string) (*JavaScriptPolicy, *Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}

	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	// Determine policy type by reading first start element
	var policyType string
	var policyName string

	// First pass: find the root element
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if elem, ok := token.(xml.StartElement); ok {
			policyType = elem.Name.Local
			for _, attr := range elem.Attr {
				if attr.Name.Local == "name" {
					policyName = attr.Value
				}
			}
			break
		}
	}

	// Reset decoder
	decoder = xml.NewDecoder(strings.NewReader(string(data)))

	// Handle based on policy type
	switch policyType {
	case "Javascript":
		jsPolicy, err := p.parseJavaScriptPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		genericPolicy := p.toGenericPolicy(jsPolicy)
		return jsPolicy, genericPolicy, nil
	case "AssignMessage":
		_, genericPolicy, err := p.parseAssignMessagePolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		// Return a JavaScriptPolicy wrapper for compatibility, but the genericPolicy has the real data
		jsPolicy := &JavaScriptPolicy{
			Name:       policyName,
			Properties: make(map[string]string),
			Includes:   []string{},
		}
		return jsPolicy, genericPolicy, nil
	case "ExtractVariables":
		_, genericPolicy, err := p.parseExtractVariablesPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{
			Name:       policyName,
			Properties: make(map[string]string),
			Includes:   []string{},
		}
		return jsPolicy, genericPolicy, nil
	case "ServiceCallout":
		_, genericPolicy, err := p.parseServiceCalloutPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{
			Name:       policyName,
			Properties: make(map[string]string),
			Includes:   []string{},
		}
		return jsPolicy, genericPolicy, nil
	case "FlowCallout":
		_, genericPolicy, err := p.parseFlowCalloutPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{
			Name:       policyName,
			Properties: make(map[string]string),
			Includes:   []string{},
		}
		return jsPolicy, genericPolicy, nil
	case "RaiseFault":
		_, genericPolicy, err := p.parseRaiseFaultPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "SpikeArrest":
		_, genericPolicy, err := p.parseSpikeArrestPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "Quota":
		_, genericPolicy, err := p.parseQuotaPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "VerifyAPIKey":
		_, genericPolicy, err := p.parseVerifyAPIKeyPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "OAuthV2":
		_, genericPolicy, err := p.parseOAuthV2Policy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "AccessControl":
		_, genericPolicy, err := p.parseAccessControlPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "BasicAuthentication":
		_, genericPolicy, err := p.parseBasicAuthPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "JSONThreatProtection":
		_, genericPolicy, err := p.parseJSONThreatPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "XMLThreatProtection":
		_, genericPolicy, err := p.parseXMLThreatPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "RegularExpressionProtection":
		_, genericPolicy, err := p.parseRegexProtectionPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "KeyValueMapOperations":
		_, genericPolicy, err := p.parseKeyValueMapPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "MessageLogging":
		_, genericPolicy, err := p.parseMessageLoggingPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "StatisticsCollector":
		_, genericPolicy, err := p.parseStatisticsCollectorPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "CORS":
		_, genericPolicy, err := p.parseCORSPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "ResponseCache":
		_, genericPolicy, err := p.parseResponseCachePolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "PopulateCache":
		_, genericPolicy, err := p.parsePopulateCachePolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "LookupCache":
		_, genericPolicy, err := p.parseLookupCachePolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "InvalidateCache":
		_, genericPolicy, err := p.parseInvalidateCachePolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "GenerateJWT":
		_, genericPolicy, err := p.parseGenerateJWTPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "VerifyJWT":
		_, genericPolicy, err := p.parseVerifyJWTPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "DecodeJWT":
		_, genericPolicy, err := p.parseDecodeJWTPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "GenerateJWS":
		_, genericPolicy, err := p.parseGenerateJWSPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "VerifyJWS":
		_, genericPolicy, err := p.parseVerifyJWSPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "DecodeJWS":
		_, genericPolicy, err := p.parseDecodeJWSPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "JSONtoXML":
		_, genericPolicy, err := p.parseJSONtoXMLPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "XMLtoJSON":
		_, genericPolicy, err := p.parseXMLtoJSONPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "XSLTransform":
		_, genericPolicy, err := p.parseXSLTransformPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "AccessEntity":
		_, genericPolicy, err := p.parseAccessEntityPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "ExtensionCallout":
		_, genericPolicy, err := p.parseExtensionCalloutPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "HMAC":
		_, genericPolicy, err := p.parseHMACPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "JavaCallout":
		_, genericPolicy, err := p.parseJavaCalloutPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "PythonScript":
		_, genericPolicy, err := p.parsePythonScriptPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "ResetQuota":
		_, genericPolicy, err := p.parseResetQuotaPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "ConcurrentRatelimit":
		_, genericPolicy, err := p.parseConcurrentRatePolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "GetOAuthV2Info":
		_, genericPolicy, err := p.parseGetOAuthV2InfoPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "RevokeOAuthV2":
		_, genericPolicy, err := p.parseRevokeOAuthV2Policy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "SetOAuthV2Info":
		_, genericPolicy, err := p.parseSetOAuthV2InfoPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "DeleteOAuthV2Info":
		_, genericPolicy, err := p.parseDeleteOAuthV2InfoPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "SAMLAssertion":
		_, genericPolicy, err := p.parseSAMLAssertionPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "SOAPMessageValidation":
		_, genericPolicy, err := p.parseSOAPValidationPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "OASValidation":
		_, genericPolicy, err := p.parseOASValidationPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "MonetizationLimitsCheck":
		_, genericPolicy, err := p.parseMonetizationLimitsPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	case "LDAP":
		_, genericPolicy, err := p.parseLDAPPolicy(decoder, policyName)
		if err != nil {
			return nil, nil, err
		}
		jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
		return jsPolicy, genericPolicy, nil
	default:
		// For unknown types, return a basic policy
		jsPolicy := &JavaScriptPolicy{
			Name:       policyName,
			Properties: make(map[string]string),
			Includes:   []string{},
		}
		genericPolicy := &Policy{
			Type:       PolicyType(policyType),
			Name:       policyName,
			Properties: make(map[string]string),
		}
		return jsPolicy, genericPolicy, nil
	}
}
