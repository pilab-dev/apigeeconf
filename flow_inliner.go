package apigeeconf

import (
	"fmt"
)

// InlineSharedFlows replaces FlowCallout steps with actual shared flow steps
// in all proxy endpoints of the given bundle.
// If sharedFlows is empty or nil, no inlining is performed.
func InlineSharedFlows(bundle *APIProxyBundle, sharedFlows map[string]*SharedFlowBundle, inline bool) {
	if !inline || len(sharedFlows) == 0 {
		return
	}

	inlined := make(map[string]bool)

	for _, proxy := range bundle.ProxyEndpoints {
		inlineFlowSteps(proxy.PreFlow.RequestSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(proxy.PreFlow.ResponseSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(proxy.PostFlow.RequestSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(proxy.PostFlow.ResponseSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(proxy.PostClientFlow.RequestSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(proxy.PostClientFlow.ResponseSteps, sharedFlows, inlined, bundle)

		for _, flow := range proxy.ConditionalFlows {
			inlineFlowSteps(flow.RequestSteps, sharedFlows, inlined, bundle)
			inlineFlowSteps(flow.ResponseSteps, sharedFlows, inlined, bundle)
		}
	}

	for _, target := range bundle.TargetEndpoints {
		inlineFlowSteps(target.PreFlow.RequestSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(target.PreFlow.ResponseSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(target.PostFlow.RequestSteps, sharedFlows, inlined, bundle)
		inlineFlowSteps(target.PostFlow.ResponseSteps, sharedFlows, inlined, bundle)
	}

	// Remove FlowCallout policies that were inlined
	for policyName := range inlined {
		delete(bundle.PoliciesMap, policyName)
		delete(bundle.Policies, policyName)
	}
}

func inlineFlowSteps(steps []FlowStep, sharedFlows map[string]*SharedFlowBundle, inlined map[string]bool, bundle *APIProxyBundle) []FlowStep {
	if len(steps) == 0 {
		return steps
	}

	var result []FlowStep
	for _, step := range steps {
		policy, exists := bundle.PoliciesMap[step.PolicyName]
		if !exists || policy.Type != PolicyTypeFlowCallout {
			result = append(result, step)
			continue
		}

		sfName := policy.SharedFlowBundle
		if sfName == "" {
			result = append(result, step)
			continue
		}

		sfBundle, ok := sharedFlows[sfName]
		if !ok {
			result = append(result, step)
			continue
		}

		// Mark this FlowCallout policy as inlined
		inlined[step.PolicyName] = true

		// Get the default shared flow definition
		sfDef, ok := sfBundle.SharedFlows["default"]
		if !ok {
			result = append(result, step)
			continue
		}

		// Inline the shared flow steps
		for _, sfStep := range sfDef.RequestSteps {
			// Merge conditions: if the original FlowCallout had a condition,
			// AND it with the shared flow step's condition
			condition := sfStep.Condition
			if step.Condition != "" {
				if condition != "" {
					condition = fmt.Sprintf("(%s) AND (%s)", step.Condition, condition)
				} else {
					condition = step.Condition
				}
			}

			// Check for policy name collision - bundle takes precedence
			if _, bundleHas := bundle.PoliciesMap[sfStep.PolicyName]; !bundleHas {
				// Add shared flow policy to bundle if not already present
				if sfPolicy, sfExists := sfBundle.PoliciesMap[sfStep.PolicyName]; sfExists {
					bundle.PoliciesMap[sfStep.PolicyName] = sfPolicy
				}
			}

			result = append(result, FlowStep{
				PolicyName: sfStep.PolicyName,
				Condition:  condition,
			})
		}
	}

	return result
}
