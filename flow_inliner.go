package apigeeconf

import (
	"fmt"
)

// InlineSharedFlows replaces FlowCallout steps with actual shared flow steps
// in all proxy endpoints of the given bundle.
// If sharedFlows is empty or nil, uses embedded shared flows from bundle.SharedFlows.
// Priority: external sharedFlows parameter > bundle.SharedFlows (embedded)
func InlineSharedFlows(bundle *APIProxyBundle, sharedFlows map[string]*SharedFlowBundle, inline bool) {
	if !inline {
		return
	}

	inlined := make(map[string]bool)

	// Use external shared flows if provided, otherwise use embedded
	useExternal := len(sharedFlows) > 0

	for _, proxy := range bundle.ProxyEndpoints {
		proxy.PreFlow.RequestSteps = inlineFlowSteps(proxy.PreFlow.RequestSteps, sharedFlows, inlined, bundle, useExternal)
		proxy.PreFlow.ResponseSteps = inlineFlowSteps(proxy.PreFlow.ResponseSteps, sharedFlows, inlined, bundle, useExternal)
		proxy.PostFlow.RequestSteps = inlineFlowSteps(proxy.PostFlow.RequestSteps, sharedFlows, inlined, bundle, useExternal)
		proxy.PostFlow.ResponseSteps = inlineFlowSteps(proxy.PostFlow.ResponseSteps, sharedFlows, inlined, bundle, useExternal)
		proxy.PostClientFlow.RequestSteps = inlineFlowSteps(proxy.PostClientFlow.RequestSteps, sharedFlows, inlined, bundle, useExternal)
		proxy.PostClientFlow.ResponseSteps = inlineFlowSteps(proxy.PostClientFlow.ResponseSteps, sharedFlows, inlined, bundle, useExternal)

		for _, flow := range proxy.ConditionalFlows {
			flow.RequestSteps = inlineFlowSteps(flow.RequestSteps, sharedFlows, inlined, bundle, useExternal)
			flow.ResponseSteps = inlineFlowSteps(flow.ResponseSteps, sharedFlows, inlined, bundle, useExternal)
		}
	}

	for _, target := range bundle.TargetEndpoints {
		target.PreFlow.RequestSteps = inlineFlowSteps(target.PreFlow.RequestSteps, sharedFlows, inlined, bundle, useExternal)
		target.PreFlow.ResponseSteps = inlineFlowSteps(target.PreFlow.ResponseSteps, sharedFlows, inlined, bundle, useExternal)
		target.PostFlow.RequestSteps = inlineFlowSteps(target.PostFlow.RequestSteps, sharedFlows, inlined, bundle, useExternal)
		target.PostFlow.ResponseSteps = inlineFlowSteps(target.PostFlow.ResponseSteps, sharedFlows, inlined, bundle, useExternal)
	}

	// Remove FlowCallout policies that were inlined
	// BUT only if they weren't replaced by actual policies from shared flows
	for policyName := range inlined {
		// Check if there's a non-FlowCallout policy with this name (replaced by shared flow)
		if p, exists := bundle.PoliciesMap[policyName]; exists && p.Type == PolicyTypeFlowCallout {
			delete(bundle.PoliciesMap, policyName)
			delete(bundle.Policies, policyName)
		}
	}
}

func inlineFlowSteps(steps []FlowStep, externalSharedFlows map[string]*SharedFlowBundle, inlined map[string]bool, bundle *APIProxyBundle, useExternal bool) []FlowStep {
	if steps == nil || len(steps) == 0 {
		return steps
	}

	var result []FlowStep
	for _, step := range steps {
		policy, exists := bundle.PoliciesMap[step.PolicyName]
		if !exists || policy == nil {
			result = append(result, step)
			continue
		}
		if policy.Type != PolicyTypeFlowCallout {
			result = append(result, step)
			continue
		}

		sfName := policy.SharedFlowBundle
		if sfName == "" {
			result = append(result, step)
			continue
		}

		var sfDef *SharedFlowDefinition
		var sfPolicies map[string]*Policy

		// Try embedded first, then external
		if !useExternal {
			if embedded, ok := bundle.SharedFlows[sfName]; ok {
				sfDef = embedded
				sfPolicies = bundle.PoliciesMap // Use bundle's policies
			}
		} else {
			if sfBundle, ok := externalSharedFlows[sfName]; ok {
				sfDef, _ = sfBundle.SharedFlows["default"]
				sfPolicies = sfBundle.PoliciesMap
			}
		}

		if sfDef == nil {
			result = append(result, step)
			continue
		}

		inlined[step.PolicyName] = true

		for _, sfStep := range sfDef.RequestSteps {
			condition := sfStep.Condition
			if step.Condition != "" {
				if condition != "" {
					condition = fmt.Sprintf("(%s) AND (%s)", step.Condition, condition)
				} else {
					condition = step.Condition
				}
			}

			existingPolicy, existingInBundle := bundle.PoliciesMap[sfStep.PolicyName]
			if !existingInBundle {
				if sfPolicies != nil {
					if sfPolicy, sfExists := sfPolicies[sfStep.PolicyName]; sfExists {
						bundle.PoliciesMap[sfStep.PolicyName] = sfPolicy
					}
				}
			} else if existingInBundle && existingPolicy.Type == PolicyTypeFlowCallout {
				if sfPolicies != nil {
					if sfPolicy, sfExists := sfPolicies[sfStep.PolicyName]; sfExists {
						bundle.PoliciesMap[sfStep.PolicyName] = sfPolicy
					}
				}
			}

			result = append(result, FlowStep{
				PolicyName: sfStep.PolicyName,
				Condition:  condition,
			})
		}

		for _, sfStep := range sfDef.ResponseSteps {
			condition := sfStep.Condition
			if step.Condition != "" {
				if condition != "" {
					condition = fmt.Sprintf("(%s) AND (%s)", step.Condition, condition)
				} else {
					condition = step.Condition
				}
			}

			existingPolicy, existingInBundle := bundle.PoliciesMap[sfStep.PolicyName]
			if !existingInBundle {
				if sfPolicies != nil {
					if sfPolicy, sfExists := sfPolicies[sfStep.PolicyName]; sfExists {
						bundle.PoliciesMap[sfStep.PolicyName] = sfPolicy
					}
				}
			} else if existingInBundle && existingPolicy.Type == PolicyTypeFlowCallout {
				if sfPolicies != nil {
					if sfPolicy, sfExists := sfPolicies[sfStep.PolicyName]; sfExists {
						bundle.PoliciesMap[sfStep.PolicyName] = sfPolicy
					}
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
