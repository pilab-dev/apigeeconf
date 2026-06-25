package apigeeconf

import (
	"encoding/xml"
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
			switch {
			case strings.EqualFold(elem.Name.Local, "APIKey"):
				policy.APIKeyRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.APIKeyRef == "" {
					policy.APIKeyRef = txt
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "VerifyAPIKey") {
				return jsPolicy, policy, nil
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
			switch {
			case strings.EqualFold(elem.Name.Local, "Operation"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OAuthOperation = txt
				}
			case strings.EqualFold(elem.Name.Local, "GenerateResponse"):
				policy.OAuthGenerateResponse = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "AccessToken"):
				policy.OAuthAccessTokenRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.OAuthAccessTokenRef == "" {
					policy.OAuthAccessTokenRef = txt
				}
			case strings.EqualFold(elem.Name.Local, "ExpiresIn"):
				policy.OAuthExpiresInRef = p.getAttributeValue(elem.Attr, "ref")
				policy.OAuthExpiresIn = p.readInt(decoder)
			case strings.EqualFold(elem.Name.Local, "SupportedGrantTypes"):
				p.parseSupportedGrantTypes(decoder, policy)
			case strings.EqualFold(elem.Name.Local, "Attributes"):
				p.parseOAuthAttributes(decoder, policy)
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "OAuthV2") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseSupportedGrantTypes(decoder *xml.Decoder, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "GrantType") {
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OAuthSupportedGrantTypes = append(policy.OAuthSupportedGrantTypes, txt)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "SupportedGrantTypes") {
				return
			}
		}
	}
}

func (p *XMLParser) parseOAuthAttributes(decoder *xml.Decoder, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Attribute") {
				attr := OAuthAttribute{
					Name:    p.getAttributeValue(t.Attr, "name"),
					Ref:     p.getAttributeValue(t.Attr, "ref"),
					Display: strings.ToLower(p.getAttributeValue(t.Attr, "display")) == "true",
				}
				if txt, err := p.readCharData(decoder); err == nil {
					attr.Value = txt
				}
				policy.OAuthAttributes = append(policy.OAuthAttributes, attr)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "Attributes") {
				return
			}
		}
	}
}

// parseAccessControlPolicy parses an AccessControl policy
func (p *XMLParser) parseAccessControlPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeAccessControl, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "IPRules"):
				p.parseIPRules(decoder, policy)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "AccessControl") {
				return jsPolicy, policy, nil
			}
		}
	}
	return jsPolicy, policy, nil
}

func (p *XMLParser) parseIPRules(decoder *xml.Decoder, policy *Policy) {
	policy.AccessControlMatch = p.getAttributeValue(nil, "noRuleMatchAction") // Need to pass attrs if available
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "MatchRule") {
				policy.AccessControlMatch = p.getAttributeValue(t.Attr, "action")
			} else if strings.EqualFold(t.Name.Local, "IPAddress") {
				if txt, err := p.readCharData(decoder); err == nil {
					policy.AccessControlIPs = append(policy.AccessControlIPs, txt)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "IPRules") {
				return
			}
		}
	}
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
			switch {
			case strings.EqualFold(elem.Name.Local, "Operation"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthOperation = txt
				}
			case strings.EqualFold(elem.Name.Local, "User"):
				policy.BasicAuthUserRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthUser = txt
				}
			case strings.EqualFold(elem.Name.Local, "Password"):
				policy.BasicAuthPasswordRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthPassword = txt
				}
			case strings.EqualFold(elem.Name.Local, "AssignTo"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.BasicAuthAssignTo = txt
					policy.AssignTo = txt // Compatibility
				}
			case strings.EqualFold(elem.Name.Local, "IgnoreUnresolvedVariables"):
				policy.IgnoreUnresolvedVariables = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "BasicAuthentication") {
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
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "MaxDepth"):
				policy.JSONThreatMaxDepth = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxStringLength"):
				policy.JSONThreatMaxStringLength = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxArraySize"):
				policy.JSONThreatMaxArraySize = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxObjectSize"):
				policy.JSONThreatMaxObjectSize = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxNumberLength"):
				policy.JSONThreatMaxNumberLength = p.readInt(decoder)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "JSONThreatProtection") {
				return jsPolicy, policy, nil
			}
		}
	}
	return jsPolicy, policy, nil
}

// parseXMLThreatPolicy parses a XMLThreatProtection policy
func (p *XMLParser) parseXMLThreatPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeXMLThreat, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "MaxAttributeCount"):
				policy.XMLThreatMaxAttributeCount = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxAttributeValueLength"):
				policy.XMLThreatMaxAttributeValueLength = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxChildrenDepth"):
				policy.XMLThreatMaxChildrenDepth = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxElementDepth"):
				policy.XMLThreatMaxElementDepth = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxNSPrefixLength"):
				policy.XMLThreatMaxNSPrefixLength = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxNSCount"):
				policy.XMLThreatMaxNSCount = p.readInt(decoder)
			case strings.EqualFold(t.Name.Local, "MaxElementTextLength"):
				policy.XMLThreatMaxElementTextLength = p.readInt(decoder)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "XMLThreatProtection") {
				return jsPolicy, policy, nil
			}
		}
	}
	return jsPolicy, policy, nil
}

// parseRegexProtectionPolicy parses a RegularExpressionProtection policy
func (p *XMLParser) parseRegexProtectionPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{Type: PolicyTypeRegexProtection, Name: policyName, Properties: make(map[string]string)}
	jsPolicy := &JavaScriptPolicy{Name: policyName, Properties: make(map[string]string), Includes: []string{}}
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(t.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.Source = txt
				}
			case strings.EqualFold(t.Name.Local, "IgnoreUnresolvedVariables"):
				policy.IgnoreUnresolvedVariables = p.readBool(decoder)
			case strings.EqualFold(t.Name.Local, "JSONPayload"):
				p.parseRegexPatterns(decoder, "JSONPayload", policy)
			case strings.EqualFold(t.Name.Local, "XMLPayload"):
				p.parseRegexPatterns(decoder, "XMLPayload", policy)
			case strings.EqualFold(t.Name.Local, "FormParam"):
				p.parseRegexParam(decoder, "FormParam", p.getAttributeValue(t.Attr, "name"), policy)
			case strings.EqualFold(t.Name.Local, "Header"):
				p.parseRegexParam(decoder, "Header", p.getAttributeValue(t.Attr, "name"), policy)
			case strings.EqualFold(t.Name.Local, "QueryParam"):
				p.parseRegexParam(decoder, "QueryParam", p.getAttributeValue(t.Attr, "name"), policy)
			case strings.EqualFold(t.Name.Local, "Variable"):
				p.parseRegexParam(decoder, "Variable", p.getAttributeValue(t.Attr, "name"), policy)
			case strings.EqualFold(t.Name.Local, "URIPath"):
				p.parseRegexParam(decoder, "URIPath", "", policy)
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, "RegularExpressionProtection") {
				return jsPolicy, policy, nil
			}
		}
	}
	return jsPolicy, policy, nil
}

func (p *XMLParser) parseRegexPatterns(decoder *xml.Decoder, parent string, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Variable") {
				name := p.getAttributeValue(t.Attr, "name")
				for {
					tok2, err := decoder.Token()
					if err != nil {
						break
					}
					if se, ok := tok2.(xml.StartElement); ok && strings.EqualFold(se.Name.Local, "Pattern") {
						if txt, err := p.readCharData(decoder); err == nil {
							policy.RegexProtectionPatterns = append(policy.RegexProtectionPatterns, RegexPatternConfig{
								Name:    name,
								Pattern: txt,
							})
						}
					}
					if ee, ok := tok2.(xml.EndElement); ok && strings.EqualFold(ee.Name.Local, "Variable") {
						break
					}
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, parent) {
				return
			}
		}
	}
}

func (p *XMLParser) parseRegexParam(decoder *xml.Decoder, parent string, name string, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Pattern") {
				if txt, err := p.readCharData(decoder); err == nil {
					config := RegexPatternConfig{Pattern: txt}
					switch {
					case strings.EqualFold(parent, "Header"):
						config.HeaderName = name
					case strings.EqualFold(parent, "QueryParam"):
						config.QueryParamName = name
					case strings.EqualFold(parent, "FormParam"):
						config.FormParamName = name
					case strings.EqualFold(parent, "Variable"):
						config.VariableRef = name
					}
					policy.RegexProtectionPatterns = append(policy.RegexProtectionPatterns, config)
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, parent) {
				return
			}
		}
	}
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
			switch {
			case strings.EqualFold(elem.Name.Local, "Algorithm"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.JWTAlgorithm = txt
				}
			case strings.EqualFold(elem.Name.Local, "PrivateKey"):
				policy.JWTPrivateKeyRef = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.JWTPrivateKeyRef == "" {
					policy.JWTPrivateKeyRef = txt
				}
			case strings.EqualFold(elem.Name.Local, "Subject"):
				policy.JWTSubject = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.JWTSubject == "" {
					policy.JWTSubject = txt
				}
			case strings.EqualFold(elem.Name.Local, "Issuer"):
				policy.JWTIssuer = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.JWTIssuer == "" {
					policy.JWTIssuer = txt
				}
			case strings.EqualFold(elem.Name.Local, "Audience"):
				policy.JWTAudience = p.getAttributeValue(elem.Attr, "ref")
				if txt, err := p.readCharData(decoder); err == nil && policy.JWTAudience == "" {
					policy.JWTAudience = txt
				}
			case strings.EqualFold(elem.Name.Local, "ExpiresIn"):
				policy.JWTExpiresIn = p.readInt(decoder)
			case strings.EqualFold(elem.Name.Local, "AdditionalHeaders") || strings.EqualFold(elem.Name.Local, "AdditionalClaims"):
				p.parseJWTClaims(decoder, elem.Name.Local, policy)
			case strings.EqualFold(elem.Name.Local, "OutputVariable"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.JWTOutputVariable = txt
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "GenerateJWT") {
				return jsPolicy, policy, nil
			}
		}
	}

	return jsPolicy, policy, nil
}

func (p *XMLParser) parseJWTClaims(decoder *xml.Decoder, parent string, policy *Policy) {
	for {
		tok, err := decoder.Token()
		if err != nil {
			break
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if strings.EqualFold(t.Name.Local, "Claim") {
				name := p.getAttributeValue(t.Attr, "name")
				ref := p.getAttributeValue(t.Attr, "ref")
				if policy.JWTClaims == nil {
					policy.JWTClaims = make(map[string]string)
				}
				if ref != "" {
					policy.JWTClaims[name] = "{" + ref + "}"
				} else {
					if txt, err := p.readCharData(decoder); err == nil {
						policy.JWTClaims[name] = txt
					}
				}
			}
		case xml.EndElement:
			if strings.EqualFold(t.Name.Local, parent) {
				return
			}
		}
	}
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
			switch {
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.JWTInputVariable = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "DecodeJWT") {
				return jsPolicy, policy, nil
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
			switch {
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.MessageValidationSource = txt
					policy.Source = txt // Compatibility
				}
			case strings.EqualFold(elem.Name.Local, "ResourceURL"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.ResourceURL = txt
				}
			case strings.EqualFold(elem.Name.Local, "SOAPMessage"):
				policy.SOAPMessage = p.readBool(decoder)
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "SOAPMessageValidation") {
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
			switch {
			case strings.EqualFold(elem.Name.Local, "OASResource"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OASResourceURL = txt
				}
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.OASSource = txt
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "OASValidation") {
				return jsPolicy, policy, nil
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
