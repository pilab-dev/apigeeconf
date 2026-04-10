package apigeeconf

import (
	"fmt"
	"strings"
)

type ValidationError struct {
	Type   string
	Loc    string
	Policy string
	Err    string
}

func (e ValidationError) Error() string {
	if e.Policy != "" {
		return fmt.Sprintf("[%s] %s: policy %q: %s", e.Type, e.Loc, e.Policy, e.Err)
	}
	return fmt.Sprintf("[%s] %s: %s", e.Type, e.Loc, e.Err)
}

type ValidationResult struct {
	Errors   []ValidationError
	Warnings []ValidationError
}

func (r *ValidationResult) AddError(errType, loc, policy, err string) {
	r.Errors = append(r.Errors, ValidationError{
		Type:   errType,
		Loc:    loc,
		Policy: policy,
		Err:    err,
	})
}

func (r *ValidationResult) AddWarning(errType, loc, policy, err string) {
	r.Warnings = append(r.Warnings, ValidationError{
		Type:   errType,
		Loc:    loc,
		Policy: policy,
		Err:    err,
	})
}

func (r *ValidationResult) HasErrors() bool {
	return len(r.Errors) > 0
}

type PolicyValidator struct {
	bundle      *APIProxyBundle
	sharedFlows map[string]*SharedFlowBundle
}

func NewPolicyValidator(bundle *APIProxyBundle, sharedFlows map[string]*SharedFlowBundle) *PolicyValidator {
	return &PolicyValidator{
		bundle:      bundle,
		sharedFlows: sharedFlows,
	}
}

func (v *PolicyValidator) Validate() *ValidationResult {
	result := &ValidationResult{}

	v.validatePolicyExistence(result)
	v.validateSharedFlowReferences(result)
	v.validatePolicyTypes(result)
	v.validateFlowConditions(result)

	return result
}

func (v *PolicyValidator) validatePolicyExistence(result *ValidationResult) {
	referencedPolicies := make(map[string]bool)

	for _, pe := range v.bundle.ProxyEndpoints {
		v.collectFlowSteps(pe.PreFlow.RequestSteps, referencedPolicies)
		v.collectFlowSteps(pe.PreFlow.ResponseSteps, referencedPolicies)
		v.collectFlowSteps(pe.PostFlow.RequestSteps, referencedPolicies)
		v.collectFlowSteps(pe.PostFlow.ResponseSteps, referencedPolicies)
		v.collectFlowSteps(pe.PostClientFlow.RequestSteps, referencedPolicies)
		v.collectFlowSteps(pe.PostClientFlow.ResponseSteps, referencedPolicies)

		for _, flow := range pe.ConditionalFlows {
			v.collectFlowSteps(flow.RequestSteps, referencedPolicies)
			v.collectFlowSteps(flow.ResponseSteps, referencedPolicies)
		}

		for _, fr := range pe.FaultRules {
			v.collectFlowSteps(fr.Steps, referencedPolicies)
		}
		if pe.DefaultFaultRule != nil {
			v.collectFlowSteps(pe.DefaultFaultRule.Steps, referencedPolicies)
		}
	}

	for _, te := range v.bundle.TargetEndpoints {
		v.collectFlowSteps(te.PreFlow.RequestSteps, referencedPolicies)
		v.collectFlowSteps(te.PreFlow.ResponseSteps, referencedPolicies)
		v.collectFlowSteps(te.PostFlow.RequestSteps, referencedPolicies)
		v.collectFlowSteps(te.PostFlow.ResponseSteps, referencedPolicies)

		for _, fr := range te.FaultRules {
			v.collectFlowSteps(fr.Steps, referencedPolicies)
		}
		if te.DefaultFaultRule != nil {
			v.collectFlowSteps(te.DefaultFaultRule.Steps, referencedPolicies)
		}
	}

	for policyName := range referencedPolicies {
		if _, exists := v.bundle.PoliciesMap[policyName]; !exists {
			result.AddWarning("NOT_FOUND", "policies", policyName, "referenced policy does not exist in bundle")
		}
	}
}

func (v *PolicyValidator) collectFlowSteps(steps []FlowStep, referenced map[string]bool) {
	for _, step := range steps {
		if step.PolicyName != "" {
			referenced[step.PolicyName] = true
		}
	}
}

func (v *PolicyValidator) validateSharedFlowReferences(result *ValidationResult) {
	for name, policy := range v.bundle.PoliciesMap {
		if policy.Type == PolicyTypeFlowCallout {
			if policy.SharedFlowBundle == "" {
				result.AddError("INVALID_POLICY", "policies", name, "FlowCallout policy missing shared flow bundle name")
				continue
			}
			if _, exists := v.sharedFlows[policy.SharedFlowBundle]; !exists {
				result.AddWarning("INVALID_REF", "policies", name, "referenced shared flow does not exist: "+policy.SharedFlowBundle)
			}
		}
	}
}

func (v *PolicyValidator) validatePolicyTypes(result *ValidationResult) {
	for name, policy := range v.bundle.PoliciesMap {
		switch policy.Type {
		case PolicyTypeJavaScript:
			if policy.Source == "" && policy.ScriptURL == "" {
				result.AddWarning("MISSING_FIELD", "policies", name, "JavaScript policy has no source or script URL")
			}
		case PolicyTypeServiceCallout:
			if policy.HTTPURL == "" && policy.ServiceCalloutRequest == "" {
				result.AddWarning("MISSING_FIELD", "policies", name, "ServiceCallout policy missing both HTTPURL and request object name")
			}
		case PolicyTypeQuota, PolicyTypeSpikeArrest:
			if policy.SpikeRate == "" && policy.QuotaInterval == 0 {
				result.AddError("MISSING_FIELD", "policies", name, "rate limiting policy missing rate/interval")
			}
		case PolicyTypeOAuthV2:
			if policy.OAuthOperation == "" {
				result.AddError("MISSING_FIELD", "policies", name, "OAuthV2 policy missing operation")
			}
		case PolicyTypeVerifyAPIKey:
			if policy.APIKeyRef == "" {
				result.AddError("MISSING_FIELD", "policies", name, "VerifyAPIKey policy missing API key reference")
			}
		case PolicyTypeKeyValueMap:
			if policy.KVMMapName == "" && policy.KVMMapIdentifier == "" && len(policy.KVMOperations) == 0 {
				result.AddError("MISSING_FIELD", "policies", name, "KVM policy missing map name and operations")
			}
		}
	}
}

func (v *PolicyValidator) validateFlowConditions(result *ValidationResult) {
	for peName, pe := range v.bundle.ProxyEndpoints {
		for _, flow := range pe.ConditionalFlows {
			if err := validateCondition(flow.Condition); err != nil {
				result.AddWarning("INVALID_CONDITION", "ProxyEndpoint/"+peName+"/flows/"+flow.Name, "", err.Error())
			}
		}
		for _, fr := range pe.FaultRules {
			if err := validateCondition(fr.Condition); err != nil {
				result.AddWarning("INVALID_CONDITION", "ProxyEndpoint/"+peName+"/faultrules/"+fr.Name, "", err.Error())
			}
		}
		if pe.DefaultFaultRule != nil {
			if err := validateCondition(pe.DefaultFaultRule.Condition); err != nil {
				result.AddWarning("INVALID_CONDITION", "ProxyEndpoint/"+peName+"/defaultfaultrule", "", err.Error())
			}
		}
	}

	for teName, te := range v.bundle.TargetEndpoints {
		for _, fr := range te.FaultRules {
			if err := validateCondition(fr.Condition); err != nil {
				result.AddWarning("INVALID_CONDITION", "TargetEndpoint/"+teName+"/faultrules/"+fr.Name, "", err.Error())
			}
		}
		if te.DefaultFaultRule != nil {
			if err := validateCondition(te.DefaultFaultRule.Condition); err != nil {
				result.AddWarning("INVALID_CONDITION", "TargetEndpoint/"+teName+"/defaultfaultrule", "", err.Error())
			}
		}
	}
}

func validateCondition(cond string) error {
	if cond == "" {
		return nil
	}

	cond = strings.TrimSpace(cond)
	if strings.HasPrefix(cond, "{") && strings.HasSuffix(cond, "}") {
		return fmt.Errorf("condition should not be enclosed in braces: %s", cond)
	}

	return nil
}

func ValidateBundle(bundle *APIProxyBundle, sharedFlows map[string]*SharedFlowBundle) *ValidationResult {
	validator := NewPolicyValidator(bundle, sharedFlows)
	return validator.Validate()
}

func ValidateBundlePostInline(bundle *APIProxyBundle) *ValidationResult {
	result := &ValidationResult{}
	return result
}
