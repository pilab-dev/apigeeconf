package main

import (
	"fmt"
	"os"

	apigeeconf "github.com/pilab-dev/apigeeconf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <bundle-path> [shared-flow-dir]\n", os.Args[0])
		os.Exit(1)
	}

	bundlePath := os.Args[1]
	var sharedFlowDir string
	if len(os.Args) > 2 {
		sharedFlowDir = os.Args[2]
	}

	bundle, err := apigeeconf.LoadBundle(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading bundle: %v\n", err)
		os.Exit(1)
	}

	var sharedFlows map[string]*apigeeconf.SharedFlowBundle
	if sharedFlowDir != "" {
		sharedFlows, err = apigeeconf.LoadAllSharedFlows(sharedFlowDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading shared flows: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Loaded %d shared flows\n", len(sharedFlows))
		apigeeconf.InlineSharedFlows(bundle, sharedFlows, true)
	}

	result := apigeeconf.ValidateBundle(bundle, sharedFlows)
	postResult := apigeeconf.ValidateBundlePostInline(bundle)

	for _, e := range postResult.Warnings {
		result.Warnings = append(result.Warnings, e)
	}

	if len(result.Errors) > 0 {
		fmt.Println("Errors:")
		for _, e := range result.Errors {
			fmt.Printf("  %v\n", e)
		}
	}

	if len(result.Warnings) > 0 {
		fmt.Println("Warnings:")
		for _, w := range result.Warnings {
			fmt.Printf("  %v\n", w)
		}
	}

	if !result.HasErrors() && len(result.Warnings) == 0 {
		fmt.Println("Validation passed!")
	}

	if result.HasErrors() {
		os.Exit(1)
	}
}
