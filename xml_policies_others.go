package apigeeconf

import "encoding/xml"

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
