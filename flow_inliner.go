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
		proxy.PreFlow.RequestSteps = inlineFlowSteps(proxy.PreFlow.RequestSteps, sharedFlows, inlined, bundle)
		proxy.PreFlow.ResponseSteps = inlineFlowSteps(proxy.PreFlow.ResponseSteps, sharedFlows, inlined, bundle)
		proxy.PostFlow.RequestSteps = inlineFlowSteps(proxy.PostFlow.RequestSteps, sharedFlows, inlined, bundle)
		proxy.PostFlow.ResponseSteps = inlineFlowSteps(proxy.PostFlow.ResponseSteps, sharedFlows, inlined, bundle)
		proxy.PostClientFlow.RequestSteps = inlineFlowSteps(proxy.PostClientFlow.RequestSteps, sharedFlows, inlined, bundle)
		proxy.PostClientFlow.ResponseSteps = inlineFlowSteps(proxy.PostClientFlow.ResponseSteps, sharedFlows, inlined, bundle)

		for _, flow := range proxy.ConditionalFlows {
			flow.RequestSteps = inlineFlowSteps(flow.RequestSteps, sharedFlows, inlined, bundle)
			flow.ResponseSteps = inlineFlowSteps(flow.ResponseSteps, sharedFlows, inlined, bundle)
		}
	}

	for _, target := range bundle.TargetEndpoints {
		target.PreFlow.RequestSteps = inlineFlowSteps(target.PreFlow.RequestSteps, sharedFlows, inlined, bundle)
		target.PreFlow.ResponseSteps = inlineFlowSteps(target.PreFlow.ResponseSteps, sharedFlows, inlined, bundle)
		target.PostFlow.RequestSteps = inlineFlowSteps(target.PostFlow.RequestSteps, sharedFlows, inlined, bundle)
		target.PostFlow.ResponseSteps = inlineFlowSteps(target.PostFlow.ResponseSteps, sharedFlows, inlined, bundle)
	}

	// Remove FlowCallout policies that were inlined
	for policyName := range inlined {
		delete(bundle.PoliciesMap, policyName)
		delete(bundle.Policies, policyName)
	}
}

func inlineFlowSteps(steps []FlowStep, sharedFlows map[string]*SharedFlowBundle, inlined map[string]bool, bundle *APIProxyBundle) []FlowStep {
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

		sfBundle, ok := sharedFlows[sfName]
		if !ok {
			result = append(result, step)
			continue
		}

		inlined[step.PolicyName] = true

		sfDef, ok := sfBundle.SharedFlows["default"]
		if !ok {
			result = append(result, step)
			continue
		}

		for _, sfStep := range sfDef.RequestSteps {
			condition := sfStep.Condition
			if step.Condition != "" {
				if condition != "" {
					condition = fmt.Sprintf("(%s) AND (%s)", step.Condition, condition)
				} else {
					condition = step.Condition
				}
			}

			if _, bundleHas := bundle.PoliciesMap[sfStep.PolicyName]; !bundleHas {
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
