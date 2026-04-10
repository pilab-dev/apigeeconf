// Package apigeeconf provides utilities for parsing and manipulating Apigee Proxy configurations.
//
// This package offers functionality to load, parse, and work with Apigee API proxy configurations,
// supporting both XML and YAML formats. It enables tools to work with proxy endpoints, target endpoints,
// policies, and shared flows.
//
// # Key Features
//
//   - Load Apigee proxy bundles from directories or ZIP archives
//   - Parse XML API proxy definitions (apiproxy.xml)
//   - Parse policy XML configurations
//   - Load and inline shared flows into proxy bundles
//   - Work with YAML-based proxy configurations
//
// # Policy Support
//
// The package supports all Apigee policies including but not limited to:
//
//   - AccessControl
//   - AssignMessage
//   - BasicAuthentication
//   - ExtractVariables
//   - JavaScript
//   - KeyValueMapOperations
//   - OAuthV2
//   - Quota
//   - RaiseFault
//   - ServiceCallout
//   - SpikeArrest
//   - VerifyAPIKey
//
// For a complete list of supported policies and their configuration,
// see https://docs.apigee.com/api-platform/reference/policies/reference-overview-policy
//
// # Example Usage
//
// Load a proxy bundle from a directory:
//
//	bundle, err := apigeeconf.LoadProxyBundle("/path/to/proxy")
//	if err != nil {
//		log.Fatal(err)
//	}
//	fmt.Printf("Loaded proxy: %s\n", bundle.Name)
//
// Load from ZIP archive:
//
//	bundle, err := apigeeconf.LoadProxyBundleFromZip("proxy.zip")
//	if err != nil {
//		log.Fatal(err)
//	}
//
// # Additional Resources
//
//   - Apigee Policy Reference: https://docs.apigee.com/api-platform/reference/policies/reference-overview-policy
//   - Apigee API Platform Reference: https://docs.apigee.com/api-platform/reference/index
//   - Apigee Documentation: https://docs.apigee.com
package apigeeconf
