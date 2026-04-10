package apigeeconf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLLoader loads proxy configuration from YAML files
type YAMLLoader struct {
	basePath string
}

// NewYAMLLoader creates a new YAML loader
func NewYAMLLoader(basePath string) *YAMLLoader {
	return &YAMLLoader{basePath: basePath}
}

// yamlBundle is the top-level YAML structure
type yamlBundle struct {
	Name            string                       `yaml:"name"`
	Description     string                       `yaml:"description,omitempty"`
	DisplayName     string                       `yaml:"displayName,omitempty"`
	Revision        string                       `yaml:"revision,omitempty"`
	Spec            string                       `yaml:"spec,omitempty"`
	Proxy           *yamlProxyGlobal             `yaml:"proxy,omitempty"`
	ProxyEndpoints  map[string]*yamlProxy        `yaml:"proxyEndpoints,omitempty"`
	TargetEndpoints map[string]*yamlTarget       `yaml:"targetEndpoints,omitempty"`
	Policies        map[string]*yamlPolicy       `yaml:"policies,omitempty"`
	Resources       *yamlResources               `yaml:"resources,omitempty"`
	TargetServers   map[string]*yamlTargetServer `yaml:"targetServers,omitempty"`
}

type yamlProxyGlobal struct {
	BasePath     string            `yaml:"basePath,omitempty"`
	VirtualHosts []string          `yaml:"virtualHosts,omitempty"`
	Properties   map[string]string `yaml:"properties,omitempty"`
}

type yamlProxy struct {
	Description      string                `yaml:"description,omitempty"`
	BasePath         string                `yaml:"basePath,omitempty"`
	VirtualHosts     []string              `yaml:"virtualHosts,omitempty"`
	PreFlow          *yamlFlowPhase        `yaml:"preFlow,omitempty"`
	PostFlow         *yamlFlowPhase        `yaml:"postFlow,omitempty"`
	PostClientFlow   *yamlFlowPhase        `yaml:"postClientFlow,omitempty"`
	Flows            []yamlConditionalFlow `yaml:"flows,omitempty"`
	RouteRules       []yamlRouteRule       `yaml:"routeRules,omitempty"`
	FaultRules       []yamlFaultRule       `yaml:"faultRules,omitempty"`
	DefaultFaultRule *yamlDefaultFaultRule `yaml:"defaultFaultRule,omitempty"`
	Properties       map[string]string     `yaml:"properties,omitempty"`
}

type yamlTargetServer struct {
	Host      string       `yaml:"host"`
	Port      int          `yaml:"port,omitempty"`
	IsEnabled bool         `yaml:"isEnabled,omitempty"`
	SSL       *yamlSSLInfo `yaml:"ssl,omitempty"`
}

type yamlTarget struct {
	Description      string                `yaml:"description,omitempty"`
	Connection       *yamlTargetConnection `yaml:"connection,omitempty"`
	PreFlow          *yamlFlowPhase        `yaml:"preFlow,omitempty"`
	PostFlow         *yamlFlowPhase        `yaml:"postFlow,omitempty"`
	Properties       map[string]string     `yaml:"properties,omitempty"`
	SSLInfo          *yamlSSLInfo          `yaml:"ssl,omitempty"`
	LoadBalancer     *yamlLoadBalancer     `yaml:"loadBalancer,omitempty"`
	HealthMonitor    *yamlHealthMonitor    `yaml:"healthMonitor,omitempty"`
	LocalTargetConn  *yamlLocalTargetConn  `yaml:"localTargetConn,omitempty"`
	ScriptTarget     *yamlScriptTarget     `yaml:"scriptTarget,omitempty"`
	FaultRules       []yamlFaultRule       `yaml:"faultRules,omitempty"`
	DefaultFaultRule *yamlDefaultFaultRule `yaml:"defaultFaultRule,omitempty"`
	PathSuffix       string                `yaml:"pathSuffix,omitempty"`
}

type yamlTargetConnection struct {
	URL        string            `yaml:"url"`
	Properties map[string]string `yaml:"properties,omitempty"`
}

type yamlFlowPhase struct {
	Description string     `yaml:"description,omitempty"`
	Request     []yamlStep `yaml:"request,omitempty"`
	Response    []yamlStep `yaml:"response,omitempty"`
}

type yamlStep struct {
	Policy    string `yaml:"policy"`
	Condition string `yaml:"condition,omitempty"`
}

type yamlConditionalFlow struct {
	Name        string     `yaml:"name"`
	Description string     `yaml:"description,omitempty"`
	Condition   string     `yaml:"condition"`
	Request     []yamlStep `yaml:"request,omitempty"`
	Response    []yamlStep `yaml:"response,omitempty"`
}

type yamlRouteRule struct {
	Name           string `yaml:"name"`
	TargetEndpoint string `yaml:"targetEndpoint,omitempty"`
	URL            string `yaml:"url,omitempty"`
	Condition      string `yaml:"condition,omitempty"`
}

type yamlFaultRule struct {
	Name      string     `yaml:"name"`
	Condition string     `yaml:"condition,omitempty"`
	Steps     []yamlStep `yaml:"steps,omitempty"`
}

type yamlDefaultFaultRule struct {
	AlwaysEnforce bool       `yaml:"alwaysEnforce,omitempty"`
	Condition     string     `yaml:"condition,omitempty"`
	Steps         []yamlStep `yaml:"steps,omitempty"`
}

type yamlResources struct {
	JSC []yamlJSCResource `yaml:"jsc,omitempty"`
}

type yamlJSCResource struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

type yamlPolicy struct {
	Type            string            `yaml:"type"`
	Description     string            `yaml:"description,omitempty"`
	Enabled         bool              `yaml:"enabled,omitempty"`
	ContinueOnError bool              `yaml:"continueOnError,omitempty"`
	TimeLimit       int               `yaml:"timeLimit,omitempty"`
	Properties      map[string]string `yaml:"properties,omitempty"`

	// JavaScript
	Source   string   `yaml:"source,omitempty"`
	Script   string   `yaml:"script,omitempty"`
	Includes []string `yaml:"includes,omitempty"`

	// ExtractVariables source and clearPayload
	SourceClearPayload bool `yaml:"sourceClearPayload,omitempty"`

	// AssignMessage
	AssignMessage *yamlAssignMessage `yaml:"assignMessage,omitempty"`

	// ExtractVariables
	ExtractVariables *yamlExtractVariables `yaml:"extractVariables,omitempty"`

	// ServiceCallout
	ServiceCallout *yamlServiceCallout `yaml:"serviceCallout,omitempty"`

	// FlowCallout
	FlowCallout *yamlFlowCallout `yaml:"flowCallout,omitempty"`

	// MessageValidation
	MessageValidation *yamlMessageValidation `yaml:"messageValidation,omitempty"`

	// XMLToJSON
	XMLToJSON *yamlXMLToJSON `yaml:"xmlToJSON,omitempty"`

	// RaiseFault
	RaiseFault *yamlRaiseFault `yaml:"raiseFault,omitempty"`

	// SpikeArrest
	SpikeArrest *yamlSpikeArrest `yaml:"spikeArrest,omitempty"`

	// Quota
	Quota *yamlQuota `yaml:"quota,omitempty"`

	// VerifyAPIKey
	VerifyAPIKey *yamlVerifyAPIKey `yaml:"verifyApiKey,omitempty"`

	// OAuthV2
	OAuthV2 *yamlOAuthV2 `yaml:"oauthV2,omitempty"`

	// AccessControl
	AccessControl *yamlAccessControl `yaml:"accessControl,omitempty"`

	// BasicAuthentication
	BasicAuth *yamlBasicAuth `yaml:"basicAuth,omitempty"`

	// JSONThreatProtection
	JSONThreat *yamlJSONThreat `yaml:"jsonThreat,omitempty"`

	// XMLThreatProtection
	XMLThreat *yamlXMLThreat `yaml:"xmlThreat,omitempty"`

	// RegularExpressionProtection
	RegexProtection *yamlRegexProtection `yaml:"regexProtection,omitempty"`

	// KeyValueMapOperations
	KVM *yamlKVM `yaml:"kvm,omitempty"`

	// MessageLogging
	MessageLogging *yamlMessageLogging `yaml:"messageLogging,omitempty"`

	// StatisticsCollector
	Statistics *yamlStatistics `yaml:"statistics,omitempty"`

	// CORS
	CORS *yamlCORS `yaml:"cors,omitempty"`

	// ResponseCache
	ResponseCache *yamlResponseCache `yaml:"responseCache,omitempty"`
}

type yamlAssignMessage struct {
	Add                       *yamlAssignMessageConfig `yaml:"add,omitempty"`
	Remove                    *yamlAssignMessageConfig `yaml:"remove,omitempty"`
	Set                       *yamlAssignMessageConfig `yaml:"set,omitempty"`
	Copy                      *yamlAssignMessageConfig `yaml:"copy,omitempty"`
	Replace                   *yamlAssignMessageConfig `yaml:"replace,omitempty"`
	AssignTo                  string                   `yaml:"assignTo,omitempty"`
	AssignToType              string                   `yaml:"assignToType,omitempty"`
	IgnoreUnresolvedVariables bool                     `yaml:"ignoreUnresolvedVariables,omitempty"`

	// Kept for backward compatibility
	Headers   map[string]string    `yaml:"headers,omitempty"`
	Payload   string               `yaml:"payload,omitempty"`
	Verb      string               `yaml:"verb,omitempty"`
	Variables []yamlAssignVariable `yaml:"variables,omitempty"`
}

type yamlAssignMessageConfig struct {
	Headers     map[string]string `yaml:"headers,omitempty"`
	QueryParams map[string]string `yaml:"queryParams,omitempty"`
	FormParams  map[string]string `yaml:"formParams,omitempty"`
	Payload     string            `yaml:"payload,omitempty"`
	Verb        string            `yaml:"verb,omitempty"`
	Path        string            `yaml:"path,omitempty"`
}

type yamlAssignVariable struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value,omitempty"`
	Ref   string `yaml:"ref,omitempty"`
}

type yamlExtractVariables struct {
	Source             string           `yaml:"source,omitempty"`
	SourceClearPayload bool             `yaml:"sourceClearPayload,omitempty"`
	VariablePrefix     string           `yaml:"variablePrefix,omitempty"`
	Variables          []yamlExtractVar `yaml:"variables"`
}

type yamlFlowCallout struct {
	SharedFlowBundle string `yaml:"sharedFlowBundle"`
}

type yamlMessageValidation struct {
	SOAPMessage bool   `yaml:"soapMessage,omitempty"`
	ResourceURL string `yaml:"resourceURL,omitempty"`
	Source      string `yaml:"source,omitempty"`
}

type yamlXMLToJSON struct {
	Options        map[string]string `yaml:"options,omitempty"`
	Source         string            `yaml:"source,omitempty"`
	OutputVariable string            `yaml:"outputVariable,omitempty"`
}

type yamlExtractVar struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type,omitempty"`
	Pattern string `yaml:"pattern,omitempty"`
	Index   int    `yaml:"index,omitempty"`
	Prefix  string `yaml:"prefix,omitempty"`
}

type yamlServiceCallout struct {
	Request  string            `yaml:"request"`
	Response string            `yaml:"response"`
	URL      string            `yaml:"url,omitempty"`
	Method   string            `yaml:"method,omitempty"`
	Headers  map[string]string `yaml:"headers,omitempty"`
	Payload  string            `yaml:"payload,omitempty"`
}

type yamlRaiseFault struct {
	StatusCode       string               `yaml:"status_code,omitempty"`
	ReasonPhrase     string               `yaml:"reason_phrase,omitempty"`
	Payload          string               `yaml:"payload,omitempty"`
	ContentType      string               `yaml:"content_type,omitempty"`
	Headers          map[string]string    `yaml:"headers,omitempty"`
	Variables        []yamlAssignVariable `yaml:"variables,omitempty"`
	CopyHeaders      []string             `yaml:"copy_headers,omitempty"`
	CopyStatusCode   bool                 `yaml:"copy_status_code,omitempty"`
	CopyReasonPhrase bool                 `yaml:"copy_reason_phrase,omitempty"`
	RemoveHeaders    []string             `yaml:"remove_headers,omitempty"`
	AssignTo         string               `yaml:"assign_to,omitempty"`
}

type yamlSpikeArrest struct {
	Rate              string `yaml:"rate"`
	RateRef           string `yaml:"rate_ref,omitempty"`
	Identifier        string `yaml:"identifier,omitempty"`
	IdentifierRef     string `yaml:"identifier_ref,omitempty"`
	MessageWeight     string `yaml:"message_weight,omitempty"`
	MessageWeightRef  string `yaml:"message_weight_ref,omitempty"`
	UseEffectiveCount bool   `yaml:"use_effective_count,omitempty"`
}

type yamlQuota struct {
	Interval         int    `yaml:"interval"`
	IntervalRef      string `yaml:"interval_ref,omitempty"`
	TimeUnit         string `yaml:"time_unit"`
	TimeUnitRef      string `yaml:"time_unit_ref,omitempty"`
	Allow            int    `yaml:"allow"`
	AllowRef         string `yaml:"allow_ref,omitempty"`
	Type             string `yaml:"type,omitempty"`
	StartTime        string `yaml:"start_time,omitempty"`
	Identifier       string `yaml:"identifier,omitempty"`
	IdentifierRef    string `yaml:"identifier_ref,omitempty"`
	Distributed      bool   `yaml:"distributed,omitempty"`
	Synchronous      bool   `yaml:"synchronous,omitempty"`
	MessageWeight    string `yaml:"message_weight,omitempty"`
	MessageWeightRef string `yaml:"message_weight_ref,omitempty"`
}

type yamlVerifyAPIKey struct {
	APIKeyRef string `yaml:"api_key_ref"`
}

type yamlOAuthV2 struct {
	Operation             string               `yaml:"operation"`
	ExpiresIn             int                  `yaml:"expires_in,omitempty"`
	ExpiresInRef          string               `yaml:"expires_in_ref,omitempty"`
	GrantType             string               `yaml:"grant_type,omitempty"`
	GrantTypeRef          string               `yaml:"grant_type_ref,omitempty"`
	SupportedGrantTypes   []string             `yaml:"supported_grant_types,omitempty"`
	GenerateResponse      bool                 `yaml:"generate_response,omitempty"`
	AccessTokenRef        string               `yaml:"access_token_ref,omitempty"`
	AccessTokenPrefix     string               `yaml:"access_token_prefix,omitempty"`
	ClientId              string               `yaml:"client_id,omitempty"`
	Code                  string               `yaml:"code,omitempty"`
	RefreshTokenRef       string               `yaml:"refresh_token_ref,omitempty"`
	RefreshTokenExpiresIn int                  `yaml:"refresh_token_expires_in,omitempty"`
	ExternalAccess        bool                 `yaml:"external_access,omitempty"`
	ExternalAccessToken   string               `yaml:"external_access_token,omitempty"`
	StoreToken            bool                 `yaml:"store_token,omitempty"`
	AppEndUser            string               `yaml:"app_end_user,omitempty"`
	UserName              string               `yaml:"username,omitempty"`
	Password              string               `yaml:"password,omitempty"`
	Attributes            []yamlOAuthAttribute `yaml:"attributes,omitempty"`
}

type yamlOAuthAttribute struct {
	Name    string `yaml:"name"`
	Value   string `yaml:"value,omitempty"`
	Ref     string `yaml:"ref,omitempty"`
	Display bool   `yaml:"display,omitempty"`
}

type yamlAccessControl struct {
	IPs   []string `yaml:"ips"`
	Match string   `yaml:"match"`
}

type yamlBasicAuth struct {
	Operation   string `yaml:"operation"`
	User        string `yaml:"user,omitempty"`
	Password    string `yaml:"password,omitempty"`
	UserRef     string `yaml:"user_ref,omitempty"`
	PasswordRef string `yaml:"password_ref,omitempty"`
	AssignTo    string `yaml:"assign_to,omitempty"`
}

type yamlJSONThreat struct {
	MaxDepth        int `yaml:"max_depth,omitempty"`
	MaxStringLength int `yaml:"max_string_length,omitempty"`
	MaxArraySize    int `yaml:"max_array_size,omitempty"`
	MaxObjectSize   int `yaml:"max_object_size,omitempty"`
	MaxNumberLength int `yaml:"max_number_length,omitempty"`
}

type yamlXMLThreat struct {
	MaxAttributeCount       int `yaml:"max_attribute_count,omitempty"`
	MaxAttributeValueLength int `yaml:"max_attribute_value_length,omitempty"`
	MaxChildrenDepth        int `yaml:"max_children_depth,omitempty"`
	MaxElementDepth         int `yaml:"max_element_depth,omitempty"`
	MaxNSPrefixLength       int `yaml:"max_ns_prefix_length,omitempty"`
	MaxNSCount              int `yaml:"max_ns_count,omitempty"`
	MaxElementTextLength    int `yaml:"max_element_text_length,omitempty"`
}

type yamlRegexProtection struct {
	Patterns []yamlRegexPattern `yaml:"patterns"`
}

type yamlRegexPattern struct {
	Name           string `yaml:"name"`
	Pattern        string `yaml:"pattern"`
	VariableRef    string `yaml:"variable_ref,omitempty"`
	HeaderName     string `yaml:"header_name,omitempty"`
	QueryParamName string `yaml:"query_param_name,omitempty"`
	FormParamName  string `yaml:"form_param_name,omitempty"`
}

type yamlKVM struct {
	MapName    string      `yaml:"map_name"`
	Scope      string      `yaml:"scope,omitempty"`
	Index      string      `yaml:"index,omitempty"`
	AssignTo   string      `yaml:"assign_to,omitempty"`
	Identifier string      `yaml:"identifier,omitempty"`
	Operations []yamlKVMOp `yaml:"operations"`
}

type yamlKVMOp struct {
	Operation string `yaml:"operation"`
	Key       string `yaml:"key"`
	Value     string `yaml:"value,omitempty"`
	KeyRef    string `yaml:"key_ref,omitempty"`
	ValueRef  string `yaml:"value_ref,omitempty"`
}

type yamlMessageLogging struct {
	Destination string            `yaml:"destination"`
	Format      string            `yaml:"format,omitempty"`
	Syslog      *yamlSyslogConfig `yaml:"syslog,omitempty"`
	File        *yamlFileConfig   `yaml:"file,omitempty"`
}

type yamlSyslogConfig struct {
	Host          string `yaml:"host"`
	Port          int    `yaml:"port"`
	Protocol      string `yaml:"protocol,omitempty"`
	FormatMessage bool   `yaml:"format_message,omitempty"`
	Message       string `yaml:"message"`
}

type yamlFileConfig struct {
	Message string `yaml:"message"`
}

type yamlStatistics struct {
	Dimensions []yamlStatDimension `yaml:"dimensions"`
}

type yamlStatDimension struct {
	Name  string `yaml:"name"`
	Ref   string `yaml:"ref,omitempty"`
	Value string `yaml:"value,omitempty"`
}

type yamlCORS struct {
	AllowOrigins     []string `yaml:"allow_origins"`
	AllowMethods     []string `yaml:"allow_methods,omitempty"`
	AllowHeaders     []string `yaml:"allow_headers,omitempty"`
	ExposeHeaders    []string `yaml:"expose_headers,omitempty"`
	MaxAge           int      `yaml:"max_age,omitempty"`
	AllowCredentials bool     `yaml:"allow_credentials,omitempty"`
}

type yamlResponseCache struct {
	Lookup     *yamlCacheLookup     `yaml:"lookup,omitempty"`
	Populate   *yamlCachePopulate   `yaml:"populate,omitempty"`
	Invalidate *yamlCacheInvalidate `yaml:"invalidate,omitempty"`
}

type yamlCacheLookup struct {
	CacheKey        string `yaml:"cache_key"`
	CacheResource   string `yaml:"cache_resource,omitempty"`
	ExcludeResponse bool   `yaml:"exclude_response,omitempty"`
	SkipOnError     bool   `yaml:"skip_on_error,omitempty"`
}

type yamlCachePopulate struct {
	CacheKey      string `yaml:"cache_key"`
	CacheResource string `yaml:"cache_resource,omitempty"`
	Expiry        int    `yaml:"expiry"`
	SkipOnError   bool   `yaml:"skip_on_error,omitempty"`
}

type yamlCacheInvalidate struct {
	CacheKey      string `yaml:"cache_key"`
	CacheResource string `yaml:"cache_resource,omitempty"`
}

type yamlSSLInfo struct {
	Enabled                bool     `yaml:"enabled"`
	ClientAuthEnabled      bool     `yaml:"client_auth_enabled,omitempty"`
	Keystore               string   `yaml:"keystore,omitempty"`
	Truststore             string   `yaml:"truststore,omitempty"`
	CommonName             string   `yaml:"common_name,omitempty"`
	WildcardMatch          bool     `yaml:"wildcard_match,omitempty"`
	IgnoreValidationErrors bool     `yaml:"ignore_validation_errors,omitempty"`
	Protocols              []string `yaml:"protocols,omitempty"`
	Ciphers                []string `yaml:"ciphers,omitempty"`
}

type yamlLoadBalancer struct {
	Algorithm    string         `yaml:"algorithm"`
	Servers      []yamlLBServer `yaml:"servers"`
	MaxFailures  int            `yaml:"max_failures,omitempty"`
	RetryEnabled bool           `yaml:"retry_enabled,omitempty"`
	IsFallback   bool           `yaml:"is_fallback,omitempty"`
}

type yamlLBServer struct {
	Name       string `yaml:"name"`
	Weight     int    `yaml:"weight,omitempty"`
	IsFallback bool   `yaml:"is_fallback,omitempty"`
}

type yamlHealthMonitor struct {
	Enabled       bool             `yaml:"enabled"`
	IntervalInSec int              `yaml:"interval_sec"`
	HTTPMonitor   *yamlHTTPMonitor `yaml:"http_monitor,omitempty"`
	TCPMonitor    *yamlTCPMonitor  `yaml:"tcp_monitor,omitempty"`
}

type yamlHTTPMonitor struct {
	Port                   int    `yaml:"port"`
	Path                   string `yaml:"path"`
	ConnectTimeoutInSec    int    `yaml:"connect_timeout,omitempty"`
	SocketReadTimeoutInSec int    `yaml:"socket_read_timeout,omitempty"`
	PayloadLimitInKB       int    `yaml:"payload_limit_kb,omitempty"`
	Verb                   string `yaml:"verb,omitempty"`
}

type yamlTCPMonitor struct {
	Port                int `yaml:"port"`
	ConnectTimeoutInSec int `yaml:"connect_timeout,omitempty"`
}

type yamlLocalTargetConn struct {
	APIProxy      string `yaml:"api_proxy"`
	ProxyEndpoint string `yaml:"proxy_endpoint,omitempty"`
	PathSuffix    string `yaml:"path_suffix,omitempty"`
}

type yamlScriptTarget struct {
	ResourceURL string `yaml:"resource_url"`
}

// LoadBundle loads a proxy bundle from a YAML file
func (l *YAMLLoader) LoadBundle(path string) (*APIProxyBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read YAML file: %w", err)
	}

	var yb yamlBundle
	if err := yaml.Unmarshal(data, &yb); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Basic validation
	if yb.Name == "" {
		return nil, fmt.Errorf("proxy name is required")
	}

	if len(yb.ProxyEndpoints) == 0 {
		return nil, fmt.Errorf("at least one proxy endpoint is required")
	}

	bundle := &APIProxyBundle{
		Name:            yb.Name,
		Description:     yb.Description,
		DisplayName:     yb.DisplayName,
		Revision:        yb.Revision,
		Spec:            yb.Spec,
		ProxyEndpoints:  make(map[string]*ProxyEndpoint),
		TargetEndpoints: make(map[string]*TargetEndpoint),
		Policies:        make(map[string]*JavaScriptPolicy),
		PoliciesMap:     make(map[string]*Policy),
		ConfigVersion:   ConfigurationVersion{MajorVersion: 4, MinorVersion: 0},
	}

	// Set base path from proxy config
	if yb.Proxy != nil && yb.Proxy.BasePath != "" {
		bundle.BasePath = yb.Proxy.BasePath
	}

	for name, yp := range yb.ProxyEndpoints {
		proxy, err := l.parseProxy(name, yp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy %s: %w", name, err)
		}
		bundle.ProxyEndpoints[name] = proxy
		if bundle.BasePath == "" && proxy.BasePath != "" {
			bundle.BasePath = proxy.BasePath
		}
	}

	for name, yt := range yb.TargetEndpoints {
		target, err := l.parseTarget(name, yt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse target %s: %w", name, err)
		}
		bundle.TargetEndpoints[name] = target
	}

	for name, yp := range yb.Policies {
		jsPolicy, policy, err := l.parsePolicy(name, yp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy %s: %w", name, err)
		}
		bundle.PoliciesMap[name] = policy
		if policy.Type == PolicyTypeJavaScript {
			bundle.Policies[name] = jsPolicy
		}
	}

	bundle.Manifest.ProxyEndpoints = make([]string, 0, len(bundle.ProxyEndpoints))
	for name := range bundle.ProxyEndpoints {
		bundle.Manifest.ProxyEndpoints = append(bundle.Manifest.ProxyEndpoints, name)
	}
	bundle.Manifest.TargetEndpoints = make([]string, 0, len(bundle.TargetEndpoints))
	for name := range bundle.TargetEndpoints {
		bundle.Manifest.TargetEndpoints = append(bundle.Manifest.TargetEndpoints, name)
	}
	bundle.Manifest.Policies = make([]string, 0, len(bundle.PoliciesMap))
	for name := range bundle.PoliciesMap {
		bundle.Manifest.Policies = append(bundle.Manifest.Policies, name)
	}

	return bundle, nil
}

func (l *YAMLLoader) parseProxy(name string, yp *yamlProxy) (*ProxyEndpoint, error) {
	proxy := &ProxyEndpoint{
		Name:             name,
		BasePath:         yp.BasePath,
		VirtualHost:      yp.VirtualHosts,
		ConditionalFlows: make([]ConditionalFlow, 0),
		RouteRules:       make([]RouteRule, 0),
		FaultRules:       make([]FaultRule, 0),
		Properties:       yp.Properties,
		HTTPProxyConn: HTTPProxyConnection{
			BasePath:    yp.BasePath,
			VirtualHost: yp.VirtualHosts,
			Properties:  yp.Properties,
		},
	}

	if yp.PreFlow != nil {
		proxy.PreFlow = l.parseFlowPhase(yp.PreFlow)
	} else {
		proxy.PreFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	}

	if yp.PostFlow != nil {
		proxy.PostFlow = l.parseFlowPhase(yp.PostFlow)
	} else {
		proxy.PostFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	}

	if yp.PostClientFlow != nil {
		proxy.PostClientFlow = l.parseFlowPhase(yp.PostClientFlow)
	} else {
		proxy.PostClientFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	}

	for _, yf := range yp.Flows {
		proxy.ConditionalFlows = append(proxy.ConditionalFlows, l.parseConditionalFlow(yf))
	}

	for _, yr := range yp.RouteRules {
		proxy.RouteRules = append(proxy.RouteRules, RouteRule{
			Name:           yr.Name,
			TargetEndpoint: yr.TargetEndpoint,
			URL:            yr.URL,
			Condition:      yr.Condition,
		})
	}

	for _, yf := range yp.FaultRules {
		proxy.FaultRules = append(proxy.FaultRules, FaultRule{
			Name:      yf.Name,
			Condition: yf.Condition,
			Steps:     l.parseSteps(yf.Steps),
		})
	}

	if yp.DefaultFaultRule != nil {
		proxy.DefaultFaultRule = &DefaultFaultRule{
			AlwaysEnforce: yp.DefaultFaultRule.AlwaysEnforce,
			Condition:     yp.DefaultFaultRule.Condition,
			Steps:         l.parseSteps(yp.DefaultFaultRule.Steps),
		}
	}

	return proxy, nil
}

func (l *YAMLLoader) parseTarget(name string, yt *yamlTarget) (*TargetEndpoint, error) {
	target := &TargetEndpoint{
		Name:       name,
		Properties: yt.Properties,
		PathSuffix: yt.PathSuffix,
	}

	if yt.Connection != nil {
		target.URL = yt.Connection.URL
		if yt.Connection.Properties != nil {
			target.Properties = yt.Connection.Properties
		}
	}

	if yt.PreFlow != nil {
		target.PreFlow = l.parseFlowPhase(yt.PreFlow)
	} else {
		target.PreFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	}

	if yt.PostFlow != nil {
		target.PostFlow = l.parseFlowPhase(yt.PostFlow)
	} else {
		target.PostFlow = FlowPhaseConfig{RequestSteps: []FlowStep{}, ResponseSteps: []FlowStep{}}
	}

	if yt.SSLInfo != nil {
		target.SSLInfo = SSLInfo{
			Enabled:                yt.SSLInfo.Enabled,
			ClientAuthEnabled:      yt.SSLInfo.ClientAuthEnabled,
			Keystore:               yt.SSLInfo.Keystore,
			Truststore:             yt.SSLInfo.Truststore,
			CommonName:             CommonName{Value: yt.SSLInfo.CommonName, WildcardMatch: yt.SSLInfo.WildcardMatch},
			IgnoreValidationErrors: yt.SSLInfo.IgnoreValidationErrors,
			Protocols:              yt.SSLInfo.Protocols,
			Ciphers:                yt.SSLInfo.Ciphers,
		}
	}

	if yt.LoadBalancer != nil {
		target.LoadBalancer = &LoadBalancer{
			Algorithm:    yt.LoadBalancer.Algorithm,
			MaxFailures:  yt.LoadBalancer.MaxFailures,
			RetryEnabled: yt.LoadBalancer.RetryEnabled,
			IsFallback:   yt.LoadBalancer.IsFallback,
		}
		for _, s := range yt.LoadBalancer.Servers {
			target.LoadBalancer.Server = append(target.LoadBalancer.Server, LoadBalancerServer{
				Name:       s.Name,
				Weight:     s.Weight,
				IsFallback: s.IsFallback,
			})
		}
	}

	if yt.HealthMonitor != nil {
		target.HealthMonitor = &HealthMonitor{
			IsEnabled:     yt.HealthMonitor.Enabled,
			IntervalInSec: yt.HealthMonitor.IntervalInSec,
		}
		if yt.HealthMonitor.HTTPMonitor != nil {
			target.HealthMonitor.HTTPMonitor = &HTTPMonitor{
				Port: yt.HealthMonitor.HTTPMonitor.Port,
				Path: yt.HealthMonitor.HTTPMonitor.Path,
				Request: HealthMonitorRequest{
					ConnectTimeoutInSec:    yt.HealthMonitor.HTTPMonitor.ConnectTimeoutInSec,
					SocketReadTimeoutInSec: yt.HealthMonitor.HTTPMonitor.SocketReadTimeoutInSec,
					PayloadLimitInKB:       yt.HealthMonitor.HTTPMonitor.PayloadLimitInKB,
					Verb:                   yt.HealthMonitor.HTTPMonitor.Verb,
					Path:                   yt.HealthMonitor.HTTPMonitor.Path,
				},
			}
		}
		if yt.HealthMonitor.TCPMonitor != nil {
			target.HealthMonitor.TCPMonitor = &TCPMonitor{
				Port:                yt.HealthMonitor.TCPMonitor.Port,
				ConnectTimeoutInSec: yt.HealthMonitor.TCPMonitor.ConnectTimeoutInSec,
			}
		}
	}

	if yt.LocalTargetConn != nil {
		target.LocalTargetConn = LocalTargetConnection{
			APIProxy:      yt.LocalTargetConn.APIProxy,
			ProxyEndpoint: yt.LocalTargetConn.ProxyEndpoint,
			PathSuffix:    yt.LocalTargetConn.PathSuffix,
		}
	}

	if yt.ScriptTarget != nil {
		target.ScriptTarget = ScriptTarget{
			ResourceURL: yt.ScriptTarget.ResourceURL,
		}
	}

	for _, yf := range yt.FaultRules {
		target.FaultRules = append(target.FaultRules, FaultRule{
			Name:      yf.Name,
			Condition: yf.Condition,
			Steps:     l.parseSteps(yf.Steps),
		})
	}

	if yt.DefaultFaultRule != nil {
		target.DefaultFaultRule = &DefaultFaultRule{
			AlwaysEnforce: yt.DefaultFaultRule.AlwaysEnforce,
			Condition:     yt.DefaultFaultRule.Condition,
			Steps:         l.parseSteps(yt.DefaultFaultRule.Steps),
		}
	}

	return target, nil
}

func (l *YAMLLoader) parseFlowPhase(yfp *yamlFlowPhase) FlowPhaseConfig {
	fpc := FlowPhaseConfig{
		RequestSteps:  make([]FlowStep, 0),
		ResponseSteps: make([]FlowStep, 0),
	}
	if yfp == nil {
		return fpc
	}
	fpc.Description = yfp.Description
	fpc.RequestSteps = l.parseSteps(yfp.Request)
	fpc.ResponseSteps = l.parseSteps(yfp.Response)
	return fpc
}

func (l *YAMLLoader) parseConditionalFlow(yf yamlConditionalFlow) ConditionalFlow {
	return ConditionalFlow{
		Name:          yf.Name,
		Description:   yf.Description,
		Condition:     yf.Condition,
		RequestSteps:  l.parseSteps(yf.Request),
		ResponseSteps: l.parseSteps(yf.Response),
	}
}

func (l *YAMLLoader) parseSteps(ysteps []yamlStep) []FlowStep {
	steps := make([]FlowStep, 0, len(ysteps))
	for _, ys := range ysteps {
		steps = append(steps, FlowStep{
			PolicyName: ys.Policy,
			Condition:  ys.Condition,
		})
	}
	return steps
}

func (l *YAMLLoader) parsePolicy(name string, yp *yamlPolicy) (*JavaScriptPolicy, *Policy, error) {
	policy := &Policy{
		Name:       name,
		Type:       PolicyType(yp.Type),
		Properties: yp.Properties,
	}

	var jsPolicy *JavaScriptPolicy

	if !yp.Enabled {
		policy.Properties["enabled"] = "false"
	}
	if yp.ContinueOnError {
		policy.Properties["continueOnError"] = "true"
	}

	switch policy.Type {
	case PolicyTypeJavaScript:
		jsPolicy = &JavaScriptPolicy{
			Name:       name,
			Properties: yp.Properties,
			Includes:   yp.Includes,
		}
		jsPolicy.TimeLimit = yp.TimeLimit
		if jsPolicy.TimeLimit == 0 {
			jsPolicy.TimeLimit = 200
		}
		policy.TimeLimit = jsPolicy.TimeLimit
		jsPolicy.Source = yp.Source
		jsPolicy.ScriptURL = yp.Script
		jsPolicy.Includes = yp.Includes
		policy.Source = yp.Source
		policy.ScriptURL = yp.Script
		policy.Includes = yp.Includes

	case PolicyTypeAssignMessage:
		if yp.AssignMessage != nil {
			am := yp.AssignMessage
			policy.Headers = am.Headers
			policy.Payload = am.Payload
			policy.Verb = am.Verb
			policy.AssignTo = am.AssignTo
			policy.AssignMessageAssignTo = am.AssignTo
			policy.AssignMessageAssignToType = am.AssignToType
			policy.IgnoreUnresolvedVariables = am.IgnoreUnresolvedVariables
			if am.Variables != nil {
				policy.AssignVariables = make(map[string]string)
				for _, v := range am.Variables {
					policy.AssignVariables[v.Name] = v.Value
				}
			}

			// New fields
			if am.Add != nil {
				policy.AssignMessageAdd = &AssignMessageConfig{
					Headers:     am.Add.Headers,
					QueryParams: am.Add.QueryParams,
					FormParams:  am.Add.FormParams,
					Payload:     am.Add.Payload,
					Verb:        am.Add.Verb,
					Path:        am.Add.Path,
				}
			}
			if am.Remove != nil {
				policy.AssignMessageRemove = &AssignMessageConfig{
					Headers:     am.Remove.Headers,
					QueryParams: am.Remove.QueryParams,
					FormParams:  am.Remove.FormParams,
					Payload:     am.Remove.Payload,
					Verb:        am.Remove.Verb,
					Path:        am.Remove.Path,
				}
			}
			if am.Set != nil {
				policy.AssignMessageSet = &AssignMessageConfig{
					Headers:     am.Set.Headers,
					QueryParams: am.Set.QueryParams,
					FormParams:  am.Set.FormParams,
					Payload:     am.Set.Payload,
					Verb:        am.Set.Verb,
					Path:        am.Set.Path,
				}
			}
			if am.Copy != nil {
				policy.AssignMessageCopy = &AssignMessageConfig{
					Headers:     am.Copy.Headers,
					QueryParams: am.Copy.QueryParams,
					FormParams:  am.Copy.FormParams,
					Payload:     am.Copy.Payload,
					Verb:        am.Copy.Verb,
					Path:        am.Copy.Path,
				}
			}
			if am.Replace != nil {
				policy.AssignMessageReplace = &AssignMessageConfig{
					Headers:     am.Replace.Headers,
					QueryParams: am.Replace.QueryParams,
					FormParams:  am.Replace.FormParams,
					Payload:     am.Replace.Payload,
					Verb:        am.Replace.Verb,
					Path:        am.Replace.Path,
				}
			}
		}

	case PolicyTypeExtractVariables:
		if yp.ExtractVariables != nil {
			policy.Source = yp.ExtractVariables.Source
			policy.SourceClearPayload = yp.ExtractVariables.SourceClearPayload
			policy.VariablePrefix = yp.ExtractVariables.VariablePrefix
			for _, ev := range yp.ExtractVariables.Variables {
				policy.VariableConfigs = append(policy.VariableConfigs, VariableConfig{
					Name:    ev.Name,
					Type:    ev.Type,
					Pattern: ev.Pattern,
					Index:   ev.Index,
					Prefix:  ev.Prefix,
				})
			}
		}

	case PolicyTypeFlowCallout:
		if yp.FlowCallout != nil {
			policy.SharedFlowBundle = yp.FlowCallout.SharedFlowBundle
		}

	case PolicyTypeSOAPValidation:
		if yp.MessageValidation != nil {
			mv := yp.MessageValidation
			policy.SOAPMessage = mv.SOAPMessage
			policy.ResourceURL = mv.ResourceURL
			policy.MessageValidationSource = mv.Source
		}

	case PolicyTypeXMLtoJSON:
		if yp.XMLToJSON != nil {
			x2j := yp.XMLToJSON
			policy.XMLToJSONOptions = x2j.Options
			policy.XMLToJSONSource = x2j.Source
			policy.XMLToJSONOutputVariable = x2j.OutputVariable
		}

	case PolicyTypeServiceCallout:
		if yp.ServiceCallout != nil {
			sc := yp.ServiceCallout
			policy.ServiceCalloutRequest = sc.Request
			policy.ServiceCalloutResponse = sc.Response
			policy.HTTPURL = sc.URL
			policy.HTTPMethod = sc.Method
			policy.HTTPHeaders = sc.Headers
			policy.HTTPPayload = sc.Payload
		}

	case PolicyTypeRaiseFault:
		if yp.RaiseFault != nil {
			rf := yp.RaiseFault
			policy.FaultResponse = &FaultResponseConfig{
				StatusCode:         rf.StatusCode,
				ReasonPhrase:       rf.ReasonPhrase,
				Payload:            rf.Payload,
				PayloadContentType: rf.ContentType,
				Headers:            rf.Headers,
				CopyStatusCode:     rf.CopyStatusCode,
				CopyReasonPhrase:   rf.CopyReasonPhrase,
				CopyHeaders:        rf.CopyHeaders,
				RemoveHeaders:      rf.RemoveHeaders,
			}
			for _, v := range rf.Variables {
				policy.FaultResponse.AssignVariables = append(policy.FaultResponse.AssignVariables, AssignVariableConfig{
					Name:  v.Name,
					Value: v.Value,
					Ref:   v.Ref,
				})
			}
		}

	case PolicyTypeSpikeArrest:
		if yp.SpikeArrest != nil {
			sa := yp.SpikeArrest
			policy.SpikeRate = sa.Rate
			policy.SpikeRateRef = sa.RateRef
			policy.SpikeIdentifier = sa.Identifier
			if sa.IdentifierRef != "" {
				policy.SpikeIdentifier = sa.IdentifierRef
			}
			policy.SpikeMessageWeight = sa.MessageWeight
			if sa.MessageWeightRef != "" {
				policy.SpikeMessageWeight = sa.MessageWeightRef
			}
			policy.SpikeUseEffectiveCount = sa.UseEffectiveCount
		}

	case PolicyTypeQuota:
		if yp.Quota != nil {
			q := yp.Quota
			policy.QuotaInterval = q.Interval
			policy.QuotaIntervalRef = q.IntervalRef
			policy.QuotaTimeUnit = q.TimeUnit
			policy.QuotaTimeUnitRef = q.TimeUnitRef
			policy.QuotaAllow = q.Allow
			policy.QuotaAllowRef = q.AllowRef
			policy.QuotaType = q.Type
			policy.QuotaStartTime = q.StartTime
			policy.QuotaIdentifier = q.Identifier
			if q.IdentifierRef != "" {
				policy.QuotaIdentifier = q.IdentifierRef
			}
			policy.QuotaDistributed = q.Distributed
			policy.QuotaSynchronous = q.Synchronous
			policy.QuotaMessageWeight = q.MessageWeight
			if q.MessageWeightRef != "" {
				policy.QuotaMessageWeight = q.MessageWeightRef
			}
		}

	case PolicyTypeVerifyAPIKey:
		if yp.VerifyAPIKey != nil {
			policy.APIKeyRef = yp.VerifyAPIKey.APIKeyRef
		}

	case PolicyTypeOAuthV2:
		if yp.OAuthV2 != nil {
			o := yp.OAuthV2
			policy.OAuthOperation = o.Operation
			policy.OAuthExpiresIn = o.ExpiresIn
			policy.OAuthExpiresInRef = o.ExpiresInRef
			policy.OAuthGrantType = o.GrantType
			policy.OAuthGrantTypeRef = o.GrantTypeRef
			policy.OAuthSupportedGrantTypes = o.SupportedGrantTypes
			policy.OAuthGenerateResponse = o.GenerateResponse
			policy.OAuthAccessTokenRef = o.AccessTokenRef
			policy.OAuthAccessTokenPrefix = o.AccessTokenPrefix
			policy.OAuthClientId = o.ClientId
			policy.OAuthCode = o.Code
			policy.OAuthRefreshTokenRef = o.RefreshTokenRef
			policy.OAuthRefreshTokenExpiresIn = o.RefreshTokenExpiresIn
			policy.OAuthExternalAccess = o.ExternalAccess
			policy.OAuthExternalAccessToken = o.ExternalAccessToken
			policy.OAuthStoreToken = o.StoreToken
			policy.OAuthAppEndUser = o.AppEndUser
			policy.OAuthUserName = o.UserName
			policy.OAuthPassWord = o.Password
			for _, a := range o.Attributes {
				policy.OAuthAttributes = append(policy.OAuthAttributes, OAuthAttribute{
					Name:    a.Name,
					Value:   a.Value,
					Ref:     a.Ref,
					Display: a.Display,
				})
			}
		}

	case PolicyTypeAccessControl:
		if yp.AccessControl != nil {
			policy.AccessControlIPs = yp.AccessControl.IPs
			policy.AccessControlMatch = yp.AccessControl.Match
		}

	case PolicyTypeBasicAuth:
		if yp.BasicAuth != nil {
			ba := yp.BasicAuth
			policy.BasicAuthOperation = ba.Operation
			policy.BasicAuthUser = ba.User
			policy.BasicAuthPassword = ba.Password
			policy.BasicAuthUserRef = ba.UserRef
			policy.BasicAuthPasswordRef = ba.PasswordRef
			policy.BasicAuthAssignTo = ba.AssignTo
		}

	case PolicyTypeJSONThreat:
		if yp.JSONThreat != nil {
			jt := yp.JSONThreat
			policy.JSONThreatMaxDepth = jt.MaxDepth
			policy.JSONThreatMaxStringLength = jt.MaxStringLength
			policy.JSONThreatMaxArraySize = jt.MaxArraySize
			policy.JSONThreatMaxObjectSize = jt.MaxObjectSize
			policy.JSONThreatMaxNumberLength = jt.MaxNumberLength
		}

	case PolicyTypeXMLThreat:
		if yp.XMLThreat != nil {
			xt := yp.XMLThreat
			policy.XMLThreatMaxAttributeCount = xt.MaxAttributeCount
			policy.XMLThreatMaxAttributeValueLength = xt.MaxAttributeValueLength
			policy.XMLThreatMaxChildrenDepth = xt.MaxChildrenDepth
			policy.XMLThreatMaxElementDepth = xt.MaxElementDepth
			policy.XMLThreatMaxNSPrefixLength = xt.MaxNSPrefixLength
			policy.XMLThreatMaxNSCount = xt.MaxNSCount
			policy.XMLThreatMaxElementTextLength = xt.MaxElementTextLength
		}

	case PolicyTypeRegexProtection:
		if yp.RegexProtection != nil {
			for _, p := range yp.RegexProtection.Patterns {
				policy.RegexProtectionPatterns = append(policy.RegexProtectionPatterns, RegexPatternConfig{
					Name:           p.Name,
					Pattern:        p.Pattern,
					VariableRef:    p.VariableRef,
					HeaderName:     p.HeaderName,
					QueryParamName: p.QueryParamName,
					FormParamName:  p.FormParamName,
				})
			}
		}

	case PolicyTypeKeyValueMap:
		if yp.KVM != nil {
			kvm := yp.KVM
			policy.KVMMapName = kvm.MapName
			policy.KVMScope = kvm.Scope
			policy.KVMIndex = kvm.Index
			policy.KVMAssignTo = kvm.AssignTo
			for _, op := range kvm.Operations {
				kvmOp := KVMOperation{
					Operation: op.Operation,
					Key:       op.Key,
					Value:     op.Value,
				}
				if op.KeyRef != "" {
					policy.KVMGetKeyRef = op.KeyRef
					policy.KVMSetKeyRef = op.KeyRef
				}
				if op.ValueRef != "" {
					policy.KVMSetKeyRef = op.ValueRef
				}
				policy.KVMOperations = append(policy.KVMOperations, kvmOp)
			}
		}

	case PolicyTypeMessageLogging:
		if yp.MessageLogging != nil {
			ml := yp.MessageLogging
			policy.MessageLoggingDestination = ml.Destination
			policy.MessageLoggingFormat = ml.Format
			if ml.Syslog != nil {
				policy.MessageLoggingSyslog = &SyslogConfig{
					Host:          ml.Syslog.Host,
					Port:          ml.Syslog.Port,
					Protocol:      ml.Syslog.Protocol,
					FormatMessage: ml.Syslog.FormatMessage,
					Message:       ml.Syslog.Message,
				}
			}
			if ml.File != nil {
				policy.MessageLoggingFile = &FileConfig{
					Message: ml.File.Message,
				}
			}
		}

	case PolicyTypeStatistics:
		if yp.Statistics != nil {
			for _, d := range yp.Statistics.Dimensions {
				policy.StatisticsDimensions = append(policy.StatisticsDimensions, StatisticsDimension{
					Name:  d.Name,
					Ref:   d.Ref,
					Value: d.Value,
				})
			}
		}

	case PolicyTypeCors:
		if yp.CORS != nil {
			c := yp.CORS
			policy.CORSAllowOrigins = c.AllowOrigins
			policy.CORSAllowMethods = c.AllowMethods
			policy.CORSAllowHeaders = c.AllowHeaders
			policy.CORSExposeHeaders = c.ExposeHeaders
			policy.CORSMaxAge = c.MaxAge
			policy.CORSAllowCredentials = c.AllowCredentials
		}

	case PolicyTypeResponseCache:
		if yp.ResponseCache != nil {
			rc := yp.ResponseCache
			if rc.Lookup != nil {
				policy.CacheLookup = &CacheLookupConfig{
					CacheKey:        rc.Lookup.CacheKey,
					CacheResource:   rc.Lookup.CacheResource,
					ExcludeResponse: rc.Lookup.ExcludeResponse,
					SkipOnError:     rc.Lookup.SkipOnError,
				}
			}
			if rc.Populate != nil {
				policy.CachePopulate = &CachePopulateConfig{
					CacheKey:      rc.Populate.CacheKey,
					CacheResource: rc.Populate.CacheResource,
					Expiry:        rc.Populate.Expiry,
					SkipOnError:   rc.Populate.SkipOnError,
				}
			}
			if rc.Invalidate != nil {
				policy.CacheInvalidate = &CacheInvalidateConfig{
					CacheKey:      rc.Invalidate.CacheKey,
					CacheResource: rc.Invalidate.CacheResource,
				}
			}
		}
	}

	return jsPolicy, policy, nil
}

// LoadAllBundlesFromYAML discovers and loads all YAML bundles from a directory
func LoadAllBundlesFromYAML(dirPath string) (map[string]*APIProxyBundle, error) {
	loader := NewYAMLLoader(dirPath)
	result := make(map[string]*APIProxyBundle)

	entries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}

		bundle, err := loader.LoadBundle(filepath.Join(dirPath, name))
		if err != nil {
			return nil, fmt.Errorf("failed to load bundle %s: %w", name, err)
		}

		bundleName := strings.TrimSuffix(name, filepath.Ext(name))
		result[bundleName] = bundle
	}

	return result, nil
}

// ConvertBundleToYAML converts an APIProxyBundle to YAML format
func ConvertBundleToYAML(bundle *APIProxyBundle) ([]byte, error) {
	yamlBundle := &yamlBundle{
		Name:            bundle.Name,
		Description:     bundle.Description,
		DisplayName:     bundle.DisplayName,
		Revision:        bundle.Revision,
		Spec:            bundle.Spec,
		ProxyEndpoints:  make(map[string]*yamlProxy),
		TargetEndpoints: make(map[string]*yamlTarget),
		Policies:        make(map[string]*yamlPolicy),
	}

	// Convert proxy endpoints
	for name, proxy := range bundle.ProxyEndpoints {
		yamlBundle.ProxyEndpoints[name] = convertProxyToYAML(name, proxy)
	}

	// Convert target endpoints
	for name, target := range bundle.TargetEndpoints {
		yamlBundle.TargetEndpoints[name] = convertTargetToYAML(name, target)
	}

	// Convert policies
	for name, policy := range bundle.PoliciesMap {
		yamlBundle.Policies[name] = convertPolicyToYAML(name, policy)
	}

	return yaml.Marshal(yamlBundle)
}

// ConvertYAMLToBundle converts YAML data back to APIProxyBundle
func ConvertYAMLToBundle(yamlData []byte) (*APIProxyBundle, error) {
	var yb yamlBundle
	if err := yaml.Unmarshal(yamlData, &yb); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	loader := &YAMLLoader{}
	return loader.convertYAMLToBundle(&yb)
}

// convertProxyToYAML converts ProxyEndpoint to yamlProxy
func convertProxyToYAML(name string, proxy *ProxyEndpoint) *yamlProxy {
	yp := &yamlProxy{
		Description:    proxy.PreFlow.Description,
		BasePath:       proxy.BasePath,
		VirtualHosts:   proxy.VirtualHost,
		PreFlow:        convertFlowPhaseToYAML(&proxy.PreFlow),
		PostFlow:       convertFlowPhaseToYAML(&proxy.PostFlow),
		PostClientFlow: convertFlowPhaseToYAML(&proxy.PostClientFlow),
		Flows:          make([]yamlConditionalFlow, 0, len(proxy.ConditionalFlows)),
		RouteRules:     make([]yamlRouteRule, 0, len(proxy.RouteRules)),
		Properties:     proxy.Properties,
	}

	// Convert conditional flows
	for _, flow := range proxy.ConditionalFlows {
		yp.Flows = append(yp.Flows, yamlConditionalFlow{
			Name:        flow.Name,
			Description: flow.Description,
			Condition:   flow.Condition,
			Request:     convertStepsToYAML(flow.RequestSteps),
			Response:    convertStepsToYAML(flow.ResponseSteps),
		})
	}

	// Convert route rules
	for _, rule := range proxy.RouteRules {
		yp.RouteRules = append(yp.RouteRules, yamlRouteRule{
			Name:           rule.Name,
			TargetEndpoint: rule.TargetEndpoint,
			URL:            rule.URL,
			Condition:      rule.Condition,
		})
	}

	// Convert fault rules
	if len(proxy.FaultRules) > 0 {
		yp.FaultRules = make([]yamlFaultRule, 0, len(proxy.FaultRules))
		for _, fr := range proxy.FaultRules {
			yp.FaultRules = append(yp.FaultRules, yamlFaultRule{
				Name:      fr.Name,
				Condition: fr.Condition,
				Steps:     convertStepsToYAML(fr.Steps),
			})
		}
	}

	// Convert default fault rule
	if proxy.DefaultFaultRule != nil {
		yp.DefaultFaultRule = &yamlDefaultFaultRule{
			AlwaysEnforce: proxy.DefaultFaultRule.AlwaysEnforce,
			Condition:     proxy.DefaultFaultRule.Condition,
			Steps:         convertStepsToYAML(proxy.DefaultFaultRule.Steps),
		}
	}

	return yp
}

// convertTargetToYAML converts TargetEndpoint to yamlTarget
func convertTargetToYAML(name string, target *TargetEndpoint) *yamlTarget {
	yt := &yamlTarget{
		Description: target.PreFlow.Description,
		PreFlow:     convertFlowPhaseToYAML(&target.PreFlow),
		PostFlow:    convertFlowPhaseToYAML(&target.PostFlow),
		Properties:  target.Properties,
		PathSuffix:  target.PathSuffix,
	}

	if target.URL != "" || len(target.Properties) > 0 {
		yt.Connection = &yamlTargetConnection{
			URL:        target.URL,
			Properties: target.Properties,
		}
	}

	// Convert SSL info
	if target.SSLInfo.Enabled || target.SSLInfo.ClientAuthEnabled || target.SSLInfo.Keystore != "" {
		yt.SSLInfo = &yamlSSLInfo{
			Enabled:                target.SSLInfo.Enabled,
			ClientAuthEnabled:      target.SSLInfo.ClientAuthEnabled,
			Keystore:               target.SSLInfo.Keystore,
			Truststore:             target.SSLInfo.Truststore,
			CommonName:             target.SSLInfo.CommonName.Value,
			WildcardMatch:          target.SSLInfo.CommonName.WildcardMatch,
			IgnoreValidationErrors: target.SSLInfo.IgnoreValidationErrors,
			Protocols:              target.SSLInfo.Protocols,
			Ciphers:                target.SSLInfo.Ciphers,
		}
	}

	return yt
}

// convertPolicyToYAML converts Policy to yamlPolicy
func convertPolicyToYAML(name string, policy *Policy) *yamlPolicy {
	yp := &yamlPolicy{
		Type:            string(policy.Type),
		Enabled:         true, // Default to enabled
		ContinueOnError: false,
		TimeLimit:       policy.TimeLimit,
		Properties:      make(map[string]string),
	}

	// Copy properties
	for k, v := range policy.Properties {
		yp.Properties[k] = v
	}

	// Handle enabled/continueOnError from properties
	if val, ok := policy.Properties["enabled"]; ok && strings.ToLower(val) == "false" {
		yp.Enabled = false
	}
	if val, ok := policy.Properties["continueOnError"]; ok && strings.ToLower(val) == "true" {
		yp.ContinueOnError = true
	}

	// Convert based on policy type
	switch policy.Type {
	case PolicyTypeJavaScript:
		yp.Script = policy.ScriptURL
		yp.Source = policy.Source
		yp.Includes = policy.Includes

	case PolicyTypeAssignMessage:
		yp.AssignMessage = &yamlAssignMessage{
			AssignTo:                  policy.AssignTo,
			AssignToType:              policy.AssignMessageAssignToType,
			IgnoreUnresolvedVariables: policy.IgnoreUnresolvedVariables,
			Headers:                   policy.Headers,
			Payload:                   policy.Payload,
			Verb:                      policy.Verb,
		}
		if len(policy.AssignVariables) > 0 {
			yp.AssignMessage.Variables = make([]yamlAssignVariable, 0, len(policy.AssignVariables))
			for k, v := range policy.AssignVariables {
				yp.AssignMessage.Variables = append(yp.AssignMessage.Variables, yamlAssignVariable{
					Name:  k,
					Value: v,
				})
			}
		}
		if policy.AssignMessageAdd != nil {
			yp.AssignMessage.Add = convertAssignMessageConfigToYAML(policy.AssignMessageAdd)
		}
		if policy.AssignMessageRemove != nil {
			yp.AssignMessage.Remove = convertAssignMessageConfigToYAML(policy.AssignMessageRemove)
		}
		if policy.AssignMessageSet != nil {
			yp.AssignMessage.Set = convertAssignMessageConfigToYAML(policy.AssignMessageSet)
		}
		if policy.AssignMessageCopy != nil {
			yp.AssignMessage.Copy = convertAssignMessageConfigToYAML(policy.AssignMessageCopy)
		}
		if policy.AssignMessageReplace != nil {
			yp.AssignMessage.Replace = convertAssignMessageConfigToYAML(policy.AssignMessageReplace)
		}

	case PolicyTypeExtractVariables:
		yp.ExtractVariables = &yamlExtractVariables{
			Source:             policy.Source,
			SourceClearPayload: policy.SourceClearPayload,
			VariablePrefix:     policy.VariablePrefix,
			Variables:          make([]yamlExtractVar, 0, len(policy.VariableConfigs)),
		}
		for _, vc := range policy.VariableConfigs {
			yp.ExtractVariables.Variables = append(yp.ExtractVariables.Variables, yamlExtractVar{
				Name:    vc.Name,
				Type:    vc.Type,
				Pattern: vc.Pattern,
				Index:   vc.Index,
				Prefix:  vc.Prefix,
			})
		}

	case PolicyTypeFlowCallout:
		yp.FlowCallout = &yamlFlowCallout{
			SharedFlowBundle: policy.SharedFlowBundle,
		}

	case PolicyTypeSOAPValidation:
		yp.MessageValidation = &yamlMessageValidation{
			SOAPMessage: policy.SOAPMessage,
			ResourceURL: policy.ResourceURL,
			Source:      policy.MessageValidationSource,
		}

	case PolicyTypeXMLtoJSON:
		yp.XMLToJSON = &yamlXMLToJSON{
			Options:        policy.XMLToJSONOptions,
			Source:         policy.XMLToJSONSource,
			OutputVariable: policy.XMLToJSONOutputVariable,
		}

	case PolicyTypeServiceCallout:
		yp.ServiceCallout = &yamlServiceCallout{
			Request:  policy.ServiceCalloutRequest,
			Response: policy.ServiceCalloutResponse,
			URL:      policy.HTTPURL,
			Method:   policy.HTTPMethod,
			Headers:  policy.HTTPHeaders,
			Payload:  policy.HTTPPayload,
		}

	case PolicyTypeRaiseFault:
		if policy.FaultResponse != nil {
			yp.RaiseFault = &yamlRaiseFault{
				StatusCode:       policy.FaultResponse.StatusCode,
				ReasonPhrase:     policy.FaultResponse.ReasonPhrase,
				Payload:          policy.FaultResponse.Payload,
				ContentType:      policy.FaultResponse.PayloadContentType,
				Headers:          policy.FaultResponse.Headers,
				CopyStatusCode:   policy.FaultResponse.CopyStatusCode,
				CopyReasonPhrase: policy.FaultResponse.CopyReasonPhrase,
				CopyHeaders:      policy.FaultResponse.CopyHeaders,
				RemoveHeaders:    policy.FaultResponse.RemoveHeaders,
				AssignTo:         policy.RaiseFaultAssignTo,
			}
			if len(policy.FaultResponse.AssignVariables) > 0 {
				yp.RaiseFault.Variables = make([]yamlAssignVariable, 0, len(policy.FaultResponse.AssignVariables))
				for _, v := range policy.FaultResponse.AssignVariables {
					yp.RaiseFault.Variables = append(yp.RaiseFault.Variables, yamlAssignVariable{
						Name:  v.Name,
						Value: v.Value,
						Ref:   v.Ref,
					})
				}
			}
		}

	case PolicyTypeSpikeArrest:
		yp.SpikeArrest = &yamlSpikeArrest{
			Rate:              policy.SpikeRate,
			RateRef:           policy.SpikeRateRef,
			Identifier:        policy.SpikeIdentifier,
			MessageWeight:     policy.SpikeMessageWeight,
			UseEffectiveCount: policy.SpikeUseEffectiveCount,
		}

	case PolicyTypeQuota:
		yp.Quota = &yamlQuota{
			Interval:      policy.QuotaInterval,
			IntervalRef:   policy.QuotaIntervalRef,
			TimeUnit:      policy.QuotaTimeUnit,
			TimeUnitRef:   policy.QuotaTimeUnitRef,
			Allow:         policy.QuotaAllow,
			AllowRef:      policy.QuotaAllowRef,
			StartTime:     policy.QuotaStartTime,
			Identifier:    policy.QuotaIdentifier,
			Distributed:   policy.QuotaDistributed,
			Synchronous:   policy.QuotaSynchronous,
			MessageWeight: policy.QuotaMessageWeight,
		}

	case PolicyTypeVerifyAPIKey:
		yp.VerifyAPIKey = &yamlVerifyAPIKey{
			APIKeyRef: policy.APIKeyRef,
		}

	case PolicyTypeOAuthV2:
		yp.OAuthV2 = &yamlOAuthV2{
			Operation:             policy.OAuthOperation,
			ExpiresIn:             policy.OAuthExpiresIn,
			ExpiresInRef:          policy.OAuthExpiresInRef,
			GrantType:             policy.OAuthGrantType,
			GrantTypeRef:          policy.OAuthGrantTypeRef,
			SupportedGrantTypes:   policy.OAuthSupportedGrantTypes,
			GenerateResponse:      policy.OAuthGenerateResponse,
			AccessTokenRef:        policy.OAuthAccessTokenRef,
			AccessTokenPrefix:     policy.OAuthAccessTokenPrefix,
			ClientId:              policy.OAuthClientId,
			Code:                  policy.OAuthCode,
			RefreshTokenRef:       policy.OAuthRefreshTokenRef,
			RefreshTokenExpiresIn: policy.OAuthRefreshTokenExpiresIn,
			ExternalAccess:        policy.OAuthExternalAccess,
			ExternalAccessToken:   policy.OAuthExternalAccessToken,
			StoreToken:            policy.OAuthStoreToken,
			AppEndUser:            policy.OAuthAppEndUser,
			UserName:              policy.OAuthUserName,
			Password:              policy.OAuthPassWord,
		}
		if len(policy.OAuthAttributes) > 0 {
			yp.OAuthV2.Attributes = make([]yamlOAuthAttribute, 0, len(policy.OAuthAttributes))
			for _, attr := range policy.OAuthAttributes {
				yp.OAuthV2.Attributes = append(yp.OAuthV2.Attributes, yamlOAuthAttribute{
					Name:    attr.Name,
					Value:   attr.Value,
					Ref:     attr.Ref,
					Display: attr.Display,
				})
			}
		}

	case PolicyTypeAccessControl:
		yp.AccessControl = &yamlAccessControl{
			IPs:   policy.AccessControlIPs,
			Match: policy.AccessControlMatch,
		}

	case PolicyTypeBasicAuth:
		yp.BasicAuth = &yamlBasicAuth{
			Operation:   policy.BasicAuthOperation,
			User:        policy.BasicAuthUser,
			Password:    policy.BasicAuthPassword,
			UserRef:     policy.BasicAuthUserRef,
			PasswordRef: policy.BasicAuthPasswordRef,
			AssignTo:    policy.BasicAuthAssignTo,
		}

	case PolicyTypeJSONThreat:
		yp.JSONThreat = &yamlJSONThreat{
			MaxDepth:        policy.JSONThreatMaxDepth,
			MaxStringLength: policy.JSONThreatMaxStringLength,
			MaxArraySize:    policy.JSONThreatMaxArraySize,
			MaxObjectSize:   policy.JSONThreatMaxObjectSize,
			MaxNumberLength: policy.JSONThreatMaxNumberLength,
		}

	case PolicyTypeXMLThreat:
		yp.XMLThreat = &yamlXMLThreat{
			MaxAttributeCount:       policy.XMLThreatMaxAttributeCount,
			MaxAttributeValueLength: policy.XMLThreatMaxAttributeValueLength,
			MaxChildrenDepth:        policy.XMLThreatMaxChildrenDepth,
			MaxElementDepth:         policy.XMLThreatMaxElementDepth,
			MaxNSPrefixLength:       policy.XMLThreatMaxNSPrefixLength,
			MaxNSCount:              policy.XMLThreatMaxNSCount,
			MaxElementTextLength:    policy.XMLThreatMaxElementTextLength,
		}

	case PolicyTypeRegexProtection:
		if len(policy.RegexProtectionPatterns) > 0 {
			yp.RegexProtection = &yamlRegexProtection{
				Patterns: make([]yamlRegexPattern, 0, len(policy.RegexProtectionPatterns)),
			}
			for _, p := range policy.RegexProtectionPatterns {
				yp.RegexProtection.Patterns = append(yp.RegexProtection.Patterns, yamlRegexPattern{
					Name:           p.Name,
					Pattern:        p.Pattern,
					VariableRef:    p.VariableRef,
					HeaderName:     p.HeaderName,
					QueryParamName: p.QueryParamName,
					FormParamName:  p.FormParamName,
				})
			}
		}

	case PolicyTypeKeyValueMap:
		yp.KVM = &yamlKVM{
			MapName:  policy.KVMMapName,
			Scope:    policy.KVMScope,
			Index:    policy.KVMIndex,
			AssignTo: policy.KVMAssignTo,
		}
		if len(policy.KVMOperations) > 0 {
			yp.KVM.Operations = make([]yamlKVMOp, 0, len(policy.KVMOperations))
			for _, op := range policy.KVMOperations {
				yamlOp := yamlKVMOp{
					Operation: op.Operation,
					Key:       op.Key,
					Value:     op.Value,
				}
				yp.KVM.Operations = append(yp.KVM.Operations, yamlOp)
			}
		}

	case PolicyTypeMessageLogging:
		yp.MessageLogging = &yamlMessageLogging{
			Destination: policy.MessageLoggingDestination,
			Format:      policy.MessageLoggingFormat,
		}
		if policy.MessageLoggingSyslog != nil {
			yp.MessageLogging.Syslog = &yamlSyslogConfig{
				Host:          policy.MessageLoggingSyslog.Host,
				Port:          policy.MessageLoggingSyslog.Port,
				Protocol:      policy.MessageLoggingSyslog.Protocol,
				FormatMessage: policy.MessageLoggingSyslog.FormatMessage,
				Message:       policy.MessageLoggingSyslog.Message,
			}
		}
		if policy.MessageLoggingFile != nil {
			yp.MessageLogging.File = &yamlFileConfig{
				Message: policy.MessageLoggingFile.Message,
			}
		}

	case PolicyTypeStatistics:
		if len(policy.StatisticsDimensions) > 0 {
			yp.Statistics = &yamlStatistics{
				Dimensions: make([]yamlStatDimension, 0, len(policy.StatisticsDimensions)),
			}
			for _, d := range policy.StatisticsDimensions {
				yp.Statistics.Dimensions = append(yp.Statistics.Dimensions, yamlStatDimension{
					Name:  d.Name,
					Ref:   d.Ref,
					Value: d.Value,
				})
			}
		}

	case PolicyTypeCors:
		yp.CORS = &yamlCORS{
			AllowOrigins:     policy.CORSAllowOrigins,
			AllowMethods:     policy.CORSAllowMethods,
			AllowHeaders:     policy.CORSAllowHeaders,
			ExposeHeaders:    policy.CORSExposeHeaders,
			MaxAge:           policy.CORSMaxAge,
			AllowCredentials: policy.CORSAllowCredentials,
		}

	case PolicyTypeResponseCache:
		if policy.CacheLookup != nil || policy.CachePopulate != nil || policy.CacheInvalidate != nil {
			yp.ResponseCache = &yamlResponseCache{}
			if policy.CacheLookup != nil {
				yp.ResponseCache.Lookup = &yamlCacheLookup{
					CacheKey:        policy.CacheLookup.CacheKey,
					CacheResource:   policy.CacheLookup.CacheResource,
					ExcludeResponse: policy.CacheLookup.ExcludeResponse,
					SkipOnError:     policy.CacheLookup.SkipOnError,
				}
			}
			if policy.CachePopulate != nil {
				yp.ResponseCache.Populate = &yamlCachePopulate{
					CacheKey:      policy.CachePopulate.CacheKey,
					CacheResource: policy.CachePopulate.CacheResource,
					Expiry:        policy.CachePopulate.Expiry,
					SkipOnError:   policy.CachePopulate.SkipOnError,
				}
			}
			if policy.CacheInvalidate != nil {
				yp.ResponseCache.Invalidate = &yamlCacheInvalidate{
					CacheKey:      policy.CacheInvalidate.CacheKey,
					CacheResource: policy.CacheInvalidate.CacheResource,
				}
			}
		}
	}

	return yp
}

// convertJSPolicyToYAML converts JavaScriptPolicy to yamlPolicy
func convertJSPolicyToYAML(name string, jsPolicy *JavaScriptPolicy) *yamlPolicy {
	yp := &yamlPolicy{
		Type:       "Javascript",
		TimeLimit:  jsPolicy.TimeLimit,
		Properties: jsPolicy.Properties,
		Script:     jsPolicy.ScriptURL,
		Source:     jsPolicy.Source,
	}
	if len(jsPolicy.Includes) > 0 {
		yp.Includes = jsPolicy.Includes
	}
	return yp
}

// convertFlowPhaseToYAML converts FlowPhaseConfig to yamlFlowPhase
func convertFlowPhaseToYAML(fpc *FlowPhaseConfig) *yamlFlowPhase {
	return &yamlFlowPhase{
		Description: fpc.Description,
		Request:     convertStepsToYAML(fpc.RequestSteps),
		Response:    convertStepsToYAML(fpc.ResponseSteps),
	}
}

// convertStepsToYAML converts []FlowStep to []yamlStep
func convertStepsToYAML(steps []FlowStep) []yamlStep {
	yamlSteps := make([]yamlStep, 0, len(steps))
	for _, step := range steps {
		yamlSteps = append(yamlSteps, yamlStep{
			Policy:    step.PolicyName,
			Condition: step.Condition,
		})
	}
	return yamlSteps
}

func convertAssignMessageConfigToYAML(config *AssignMessageConfig) *yamlAssignMessageConfig {
	if config == nil {
		return nil
	}
	return &yamlAssignMessageConfig{
		Headers:     config.Headers,
		QueryParams: config.QueryParams,
		FormParams:  config.FormParams,
		Payload:     config.Payload,
		Verb:        config.Verb,
		Path:        config.Path,
	}
}

// convertYAMLToBundle converts yamlBundle to APIProxyBundle (internal method)
func (l *YAMLLoader) convertYAMLToBundle(yb *yamlBundle) (*APIProxyBundle, error) {
	bundle := &APIProxyBundle{
		Name:            yb.Name,
		Description:     yb.Description,
		DisplayName:     yb.DisplayName,
		Revision:        yb.Revision,
		Spec:            yb.Spec,
		ProxyEndpoints:  make(map[string]*ProxyEndpoint),
		TargetEndpoints: make(map[string]*TargetEndpoint),
		Policies:        make(map[string]*JavaScriptPolicy),
		PoliciesMap:     make(map[string]*Policy),
		ConfigVersion:   ConfigurationVersion{MajorVersion: 4, MinorVersion: 0},
	}

	// Convert proxy endpoints
	for name, yp := range yb.ProxyEndpoints {
		proxy, err := l.parseProxy(name, yp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse proxy %s: %w", name, err)
		}
		bundle.ProxyEndpoints[name] = proxy
	}

	// Convert target endpoints
	for name, yt := range yb.TargetEndpoints {
		target, err := l.parseTarget(name, yt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse target %s: %w", name, err)
		}
		bundle.TargetEndpoints[name] = target
	}

	// Convert policies
	for name, yp := range yb.Policies {
		jsPolicy, policy, err := l.parsePolicy(name, yp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse policy %s: %w", name, err)
		}
		bundle.PoliciesMap[name] = policy
		// Store all policies in Policies map (for compatibility with original XML parser)
		bundle.Policies[name] = jsPolicy
	}

	// Build manifest
	bundle.Manifest.ProxyEndpoints = make([]string, 0, len(bundle.ProxyEndpoints))
	for name := range bundle.ProxyEndpoints {
		bundle.Manifest.ProxyEndpoints = append(bundle.Manifest.ProxyEndpoints, name)
	}
	bundle.Manifest.TargetEndpoints = make([]string, 0, len(bundle.TargetEndpoints))
	for name := range bundle.TargetEndpoints {
		bundle.Manifest.TargetEndpoints = append(bundle.Manifest.TargetEndpoints, name)
	}
	bundle.Manifest.Policies = make([]string, 0, len(bundle.PoliciesMap))
	for name := range bundle.PoliciesMap {
		bundle.Manifest.Policies = append(bundle.Manifest.Policies, name)
	}

	return bundle, nil
}
