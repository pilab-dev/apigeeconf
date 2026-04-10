# ApigeeConf

<p align="center">
  <a href="https://pkg.go.dev/github.com/pilab-dev/apigeeconf">
    <img src="https://img.shields.io/badge/go.dev-reference-blue?logo=go&logoColor=white" alt="Go.dev">
  </a>
  <a href="https://github.com/pilab-dev/apigeeconf/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/pilab-dev/apigeeconf/ci.yml?logo=github" alt="CI">
  </a>
  <a href="https://goreportcard.com/report/github.com/pilab-dev/apigeeconf">
    <img src="https://goreportcard.com/badge/github.com/pilab-dev/apigeeconf" alt="Go Report Card">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT">
  </a>
</p>

> A powerful Go library for parsing, manipulating, and managing Apigee API proxy configurations.

ApigeeConf provides a comprehensive set of tools for working with Apigee API proxy configurations. It enables you to load proxy bundles from directories or ZIP archives, parse XML and YAML configurations, and work with policies, endpoints, and shared flows.

## Features

- **Multiple Input Formats**: Load configurations from XML files, YAML files, or ZIP archives
- **Complete Policy Support**: Parse all Apigee policy types including security, mediation, extension, and more
- **Proxy & Target Endpoints**: Full support for ProxyEndpoint and TargetEndpoint configurations
- **Shared Flows**: Load and inline shared flows into your proxy bundles
- **Type-Safe**: Strongly typed Go structs for all configuration elements
- **No External Dependencies**: Only depends on the Go standard library (plus yaml.v3 for YAML support)

## Installation

```bash
go get github.com/pilab-dev/apigeeconf
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/pilab-dev/apigeeconf"
)

func main() {
    // Load a proxy bundle from a directory
    bundle, err := apigeeconf.LoadProxyBundle("/path/to/apiproxy")
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Proxy Name: %s\n", bundle.Name)
    fmt.Printf("Revision: %s\n", bundle.Revision)
    fmt.Printf("Policies: %d\n", len(bundle.PoliciesMap))
    fmt.Printf("Proxy Endpoints: %d\n", len(bundle.ProxyEndpoints))
}
```

## Loading Configurations

### From Directory

```go
bundle, err := apigeeconf.LoadProxyBundle("/path/to/apiproxy")
```

### From ZIP Archive

```go
bundle, err := apigeeconf.LoadProxyBundleFromZip("proxy.zip")
```

### From YAML

```go
loader := apigeeconf.NewYAMLLoader()
bundle, err := loader.Load("config.yaml")
```

## Working with Policies

Access all parsed policies:

```go
for name, policy := range bundle.PoliciesMap {
    fmt.Printf("Policy: %s (Type: %s)\n", name, policy.Type)
}
```

### Supported Policy Types

ApigeeConf supports all Apigee policy types:

| Category | Policies |
|----------|----------|
| **Security** | OAuthV2, VerifyAPIKey, BasicAuthentication, AccessControl, JWT, SAML |
| **Mediation** | AssignMessage, ExtractVariables, RaiseFault, ServiceCallout |
| **Traffic Management** | Quota, SpikeArrest, ConcurrentRatelimit |
| **Extension** | JavaScript, PythonScript, NodeJS, JavaCallout |
| **Validation** | OASValidation, SOAPMessageValidation, JSONThreatProtection, XMLThreatProtection |
| **Caching** | ResponseCache, PopulateCache, LookupCache, InvalidateCache |
| **Key-Value Maps** | KeyValueMapOperations |
| **Logging** | MessageLogging |

For a complete list, see [Apigee Policy Reference](https://docs.apigee.com/api-platform/reference/policies/reference-overview-policy).

## Working with Endpoints

### Proxy Endpoints

```go
for name, endpoint := range bundle.ProxyEndpoints {
    fmt.Printf("ProxyEndpoint: %s\n", name)
    fmt.Printf("  BasePath: %s\n", endpoint.BasePath)
    
    // Access pre-flow steps
    for _, step := range endpoint.PreFlow.RequestSteps {
        fmt.Printf("  Request Step: %s\n", step.PolicyName)
    }
}
```

### Target Endpoints

```go
for name, target := range bundle.TargetEndpoints {
    fmt.Printf("TargetEndpoint: %s\n", name)
    fmt.Printf("  URL: %s\n", target.URL)
}
```

## Shared Flows

### Loading Shared Flows

```go
sfLoader := apigeeconf.NewSharedFlowLoader()
sharedFlows, err := sfLoader.LoadAllSharedFlows("/path/to/sharedflows")
```

### Inlining Shared Flows

```go
err := apigeeconf.InlineSharedFlows(bundle, sharedFlows)
```

## Configuration Types

### Flow Phases

```go
const (
    apigeeconf.FlowPhaseProxyReq   = "PROXY_REQ_FLOW"
    apigeeconf.FlowPhaseProxyResp  = "PROXY_RESP_FLOW"
    apigeeconf.FlowPhaseTargetReq  = "TARGET_REQ_FLOW"
    apigeeconf.FlowPhaseTargetResp = "TARGET_RESP_FLOW"
)
```

### Policy Types

All policy types are defined as constants:

```go
apigeeconf.PolicyTypeJavaScript
apigeeconf.PolicyTypeAssignMessage
apigeeconf.PolicyTypeOAuthV2
apigeeconf.PolicyTypeQuota
// ... and many more
```

## Examples

### Complete Proxy Analysis

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/pilab-dev/apigeeconf"
)

func analyzeProxy(bundle *.APIProxyBundle)apigeeconf {
    fmt.Println("=== Proxy Bundle Analysis ===")
    fmt.Printf("Name: %s\n", bundle.Name)
    fmt.Printf("Revision: %s\n", bundle.Revision)
    
    // Count policies by type
    policyCounts := make(map[string]int)
    for _, p := range bundle.PoliciesMap {
        policyCounts[string(p.Type)]++
    }
    
    fmt.Println("\nPolicy Distribution:")
    for ptype, count := range policyCounts {
        fmt.Printf("  %s: %d\n", ptype, count)
    }
}

func main() {
    bundle, err := apigeeconf.LoadProxyBundle("testdata/apiproxy")
    if err != nil {
        log.Fatal(err)
    }
    analyzeProxy(bundle)
}
```

### Policy Configuration Extraction

```go
// Extract all Quota policy configurations
func extractQuotaPolicies(bundle *apigeeconf.APIProxyBundle) []apigeeconf.Policy {
    var quotas []apigeeconf.Policy
    for _, policy := range bundle.PoliciesMap {
        if policy.Type == apigeeconf.PolicyTypeQuota {
            quotas = append(quotas, *policy)
        }
    }
    return quotas
}
```

## Documentation

- [Go Reference](https://pkg.go.dev/github.com/pilab-dev/apigeeconf)
- [Apigee Policy Reference](https://docs.apigee.com/api-platform/reference/policies/reference-overview-policy)
- [Apigee API Platform Reference](https://docs.apigee.com/api-platform/reference/index)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

<p align="center">
  Made with ❤️ by <a href="https://pilab.hu">PILAB</a>
</p>
