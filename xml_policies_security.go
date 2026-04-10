package apigeeconf

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// parseVerifyAPIKeyPolicy parses a VerifyAPIKey policy
func (p *XMLParser) parseVerifyAPIKeyPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeVerifyAPIKey,
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
			case "APIKey":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.APIKeyRef = attr.Value
					}
				}
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseOAuthV2Policy parses an OAuthV2 policy
func (p *XMLParser) parseOAuthV2Policy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeOAuthV2, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Operation":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OAuthOperation = txt
				}
			case "GenerateResponse":
				policy.OAuthGenerateResponse = true
			case "AccessToken":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OAuthAccessTokenRef = txt
				}
			case "ExpiresIn":
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &policy.OAuthExpiresIn)
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "OAuthV2" {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseAccessControlPolicy parses an AccessControl policy
func (p *XMLParser) parseAccessControlPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeAccessControl, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseBasicAuthPolicy parses a BasicAuthentication policy
func (p *XMLParser) parseBasicAuthPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeBasicAuth,
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
			switch elem.Name.Local {
			case "Operation":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthOperation = txt
				}
			case "User":
				policy.BasicAuthUserRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthUser = txt
				}
			case "Password":
				policy.BasicAuthPasswordRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthPassword = txt
				}
			case "AssignTo":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthAssignTo = txt
					policy.AssignTo = txt // Compatibility
				}
			case "IgnoreUnresolvedVariables":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.IgnoreUnresolvedVariables = strings.ToLower(txt) == "true"
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "BasicAuthentication" {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseJSONThreatPolicy parses a JSONThreatProtection policy
func (p *XMLParser) parseJSONThreatPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeJSONThreat, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseXMLThreatPolicy parses a XMLThreatProtection policy
func (p *XMLParser) parseXMLThreatPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeXMLThreat, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseRegexProtectionPolicy parses a RegularExpressionProtection policy
func (p *XMLParser) parseRegexProtectionPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeRegexProtection, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseGenerateJWTPolicy parses a GenerateJWT policy
func (p *XMLParser) parseGenerateJWTPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeGenerateJWT, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Algorithm":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.JWTAlgorithm = txt
				}
			case "PrivateKey":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.JWTPrivateKeyRef = attr.Value
					}
				}
				if txt, err := p.readCharData(decoder); err == nil {
					if policy.JWTPrivateKeyRef == "" {
						policy.JWTPrivateKeyRef = txt
					}
				}
			case "Subject":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.JWTSubject = attr.Value
					}
				}
				if txt, err := p.readCharData(decoder); err == nil {
					if policy.JWTSubject == "" {
						policy.JWTSubject = txt
					}
				}
			case "Issuer":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.JWTIssuer = attr.Value
					}
				}
				if txt, err := p.readCharData(decoder); err == nil {
					if policy.JWTIssuer == "" {
						policy.JWTIssuer = txt
					}
				}
			case "Audience":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						policy.JWTAudience = attr.Value
					}
				}
				if txt, err := p.readCharData(decoder); err == nil {
					if policy.JWTAudience == "" {
						policy.JWTAudience = txt
					}
				}
			case "ExpiresIn":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "ref" {
						// ref value stored, actual value resolved at runtime
					}
				}
				if txt, err := p.readCharData(decoder); err == nil {
					fmt.Sscanf(txt, "%d", &policy.JWTExpiresIn)
				}
			case "AdditionalHeaders":
				// Parse additional claims
				for {
					inner, err := decoder.Token()
					if err != nil {
						break
					}
					if se, ok := inner.(xml.StartElement); ok && se.Name.Local == "Claim" {
						var claimName, claimRef string
						for _, attr := range se.Attr {
							if attr.Name.Local == "name" {
								claimName = attr.Value
							}
							if attr.Name.Local == "ref" {
								claimRef = attr.Value
							}
						}
						if claimName != "" {
							if policy.JWTClaims == nil {
								policy.JWTClaims = make(map[string]string)
							}
							if claimRef != "" {
								policy.JWTClaims[claimName] = "{" + claimRef + "}"
							} else {
								if txt, err := p.readCharData(decoder); err == nil {
									policy.JWTClaims[claimName] = txt
								}
							}
						}
					}
					if ee, ok := inner.(xml.EndElement); ok && ee.Name.Local == "AdditionalHeaders" {
						break
					}
				}
			case "OutputVariable":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.JWTOutputVariable = txt
				}
			default:
				decoder.Skip()
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseVerifyJWTPolicy parses a VerifyJWT policy
func (p *XMLParser) parseVerifyJWTPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeVerifyJWT, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseDecodeJWTPolicy parses a DecodeJWT policy
func (p *XMLParser) parseDecodeJWTPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeDecodeJWT, Name: policyName, Properties: make(map[string]string)}
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
					policy.JWTInputVariable = txt
				}
			default:
				decoder.Skip()
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseGenerateJWSPolicy parses a GenerateJWS policy
func (p *XMLParser) parseGenerateJWSPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeGenerateJWS, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseVerifyJWSPolicy parses a VerifyJWS policy
func (p *XMLParser) parseVerifyJWSPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeVerifyJWS, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseDecodeJWSPolicy parses a DecodeJWS policy
func (p *XMLParser) parseDecodeJWSPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeDecodeJWS, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseSAMLAssertionPolicy parses a SAMLAssertion policy
func (p *XMLParser) parseSAMLAssertionPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeSAMLAssertion, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseSOAPValidationPolicy parses a SOAPMessageValidation policy
func (p *XMLParser) parseSOAPValidationPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Type:       PolicyTypeSOAPValidation,
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
			switch elem.Name.Local {
			case "Source":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.MessageValidationSource = txt
					policy.Source = txt // Compatibility
				}
			case "ResourceURL":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.ResourceURL = txt
				}
			case "SOAPMessage":
				policy.SOAPMessage = true
			}
		case xml.EndElement:
			if elem.Name.Local == "SOAPMessageValidation" {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseOASValidationPolicy parses a OASValidation policy
func (p *XMLParser) parseOASValidationPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeOASValidation, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "OASResource":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OASResourceURL = txt
				}
			case "Source":
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OASSource = txt
				}
			}
		}
	}

	return jsPolicy, policy, nil
}

// parseMonetizationLimitsPolicy parses a MonetizationLimitsCheck policy
func (p *XMLParser) parseMonetizationLimitsPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeMonetization, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseLDAPPolicy parses a LDAP policy
func (p *XMLParser) parseLDAPPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeLDAP, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseGetOAuthV2InfoPolicy parses a GetOAuthV2Info policy
func (p *XMLParser) parseGetOAuthV2InfoPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeGetOAuthV2Info, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseRevokeOAuthV2Policy parses a RevokeOAuthV2 policy
func (p *XMLParser) parseRevokeOAuthV2Policy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeRevokeOAuthV2, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseSetOAuthV2InfoPolicy parses a SetOAuthV2Info policy
func (p *XMLParser) parseSetOAuthV2InfoPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeSetOAuthV2Info, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}

// parseDeleteOAuthV2InfoPolicy parses a DeleteOAuthV2Info policy
func (p *XMLParser) parseDeleteOAuthV2InfoPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeDeleteOAuthV2, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	return jsPolicy, policy, nil
}
