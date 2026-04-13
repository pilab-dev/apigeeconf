package apigeeconf

// FlowPhase represents the current flow phase
type FlowPhase string

const (
	// Flow phases
	FlowPhaseProxyReq   FlowPhase = "PROXY_REQ_FLOW"
	FlowPhaseProxyResp  FlowPhase = "PROXY_RESP_FLOW"
	FlowPhaseTargetReq  FlowPhase = "TARGET_REQ_FLOW"
	FlowPhaseTargetResp FlowPhase = "TARGET_RESP_FLOW"
)

// PolicyType represents the type of policy
type PolicyType string

const (
	PolicyTypeJavaScript       PolicyType = "Javascript"
	PolicyTypeAssignMessage    PolicyType = "AssignMessage"
	PolicyTypeExtractVariables PolicyType = "ExtractVariables"
	PolicyTypeServiceCallout   PolicyType = "ServiceCallout"
	PolicyTypeFlowCallout      PolicyType = "FlowCallout"
	PolicyTypeAccessControl    PolicyType = "AccessControl"
	PolicyTypeKeyValueMap      PolicyType = "KeyValueMapOperations"
	PolicyTypeRaiseFault       PolicyType = "RaiseFault"
	PolicyTypeQuota            PolicyType = "Quota"
	PolicyTypeSpikeArrest      PolicyType = "SpikeArrest"
	PolicyTypeOAuthV2          PolicyType = "OAuthV2"
	PolicyTypeVerifyAPIKey     PolicyType = "VerifyAPIKey"
	PolicyTypeMessageLogging   PolicyType = "MessageLogging"
	PolicyTypeStatistics       PolicyType = "StatisticsCollector"
	PolicyTypeRegexProtection  PolicyType = "RegexProtection"
	PolicyTypeJSONThreat       PolicyType = "JSONThreatProtection"
	PolicyTypeXMLThreat        PolicyType = "XMLThreatProtection"
	PolicyTypeBasicAuth        PolicyType = "BasicAuthentication"
	PolicyTypeGenerateJWT      PolicyType = "GenerateJWT"
	PolicyTypeVerifyJWT        PolicyType = "VerifyJWT"
	PolicyTypeCors             PolicyType = "CORS"
	PolicyTypeResponseCache    PolicyType = "ResponseCache"
	PolicyTypeAccessEntity     PolicyType = "AccessEntity"
	PolicyTypePopulateCache    PolicyType = "PopulateCache"
	PolicyTypeLookupCache      PolicyType = "LookupCache"
	PolicyTypeInvalidateCache  PolicyType = "InvalidateCache"
	PolicyTypeExtensionCallout PolicyType = "ExtensionCallout"
	PolicyTypeHMAC             PolicyType = "HMAC"
	PolicyTypeJavaCallout      PolicyType = "JavaCallout"
	PolicyTypeJSONtoXML        PolicyType = "JSONtoXML"
	PolicyTypeGenerateJWS      PolicyType = "GenerateJWS"
	PolicyTypeVerifyJWS        PolicyType = "VerifyJWS"
	PolicyTypeDecodeJWS        PolicyType = "DecodeJWS"
	PolicyTypeDecodeJWT        PolicyType = "DecodeJWT"
	PolicyTypeLDAP             PolicyType = "LDAP"
	PolicyTypeMonetization     PolicyType = "MonetizationLimitsCheck"
	PolicyTypeOASValidation    PolicyType = "OASValidation"
	PolicyTypeGetOAuthV2Info   PolicyType = "GetOAuthV2Info"
	PolicyTypeRevokeOAuthV2    PolicyType = "RevokeOAuthV2"
	PolicyTypeSetOAuthV2Info   PolicyType = "SetOAuthV2Info"
	PolicyTypeDeleteOAuthV2    PolicyType = "DeleteOAuthV2Info"
	PolicyTypePythonScript     PolicyType = "PythonScript"
	PolicyTypeResetQuota       PolicyType = "ResetQuota"
	PolicyTypeSAMLAssertion    PolicyType = "SAMLAssertion"
	PolicyTypeSOAPValidation   PolicyType = "SOAPMessageValidation"
	PolicyTypeXMLtoJSON        PolicyType = "XMLtoJSON"
	PolicyTypeXSLTransform     PolicyType = "XSLTransform"
	PolicyTypeConcurrentRate   PolicyType = "ConcurrentRatelimit"
)

// Policy represents a generic policy (can be JS or AssignMessage, etc.)
type Policy struct {
	Type                      PolicyType
	Name                      string
	Source                    string // For JavaScript and others
	SourceClearPayload        bool   // For ExtractVariables, etc.
	ScriptURL                 string // For JavaScript
	Properties                map[string]string
	TimeLimit                 int               // For JavaScript
	Includes                  []string          // For JavaScript
	Headers                   map[string]string // For AssignMessage
	Payload                   string            // For AssignMessage
	Verb                      string            // For AssignMessage
	AssignVariables           map[string]string // For AssignMessage (Name -> Value)
	IgnoreUnresolvedVariables bool
	AssignTo                  string

	// For ExtractVariables
	VariableConfigs []VariableConfig // For ExtractVariables
	VariablePrefix  string           // For ExtractVariables

	// For FlowCallout
	SharedFlowBundle string // For FlowCallout

	// For MessageValidation (SOAPMessageValidation)
	SOAPMessage             bool   // For SOAPMessageValidation
	ResourceURL             string // For MessageValidation and other policies
	MessageValidationSource string // For MessageValidation

	// For XMLToJSON
	XMLToJSONOptions        map[string]string // For XMLToJSON options
	XMLToJSONSource         string
	XMLToJSONOutputVariable string

	// For AssignMessage
	AssignMessageAdd          *AssignMessageConfig
	AssignMessageRemove       *AssignMessageConfig
	AssignMessageSet          *AssignMessageConfig
	AssignMessageCopy         *AssignMessageConfig
	AssignMessageReplace      *AssignMessageConfig
	AssignMessageAssignTo     string
	AssignMessageAssignToType string

	// For ServiceCallout
	ServiceCalloutRequest  string            // Request object name
	ServiceCalloutResponse string            // Response object name
	HTTPMethod             string            // GET, POST, etc.
	HTTPURL                string            // URL to call
	HTTPHeaders            map[string]string // Headers
	HTTPPayload            string            // Body

	// For RaiseFault
	FaultResponse      *FaultResponseConfig
	RaiseFaultAssignTo string

	// For SpikeArrest
	SpikeRate              string // e.g. "30pm", "5ps"
	SpikeRateRef           string // flow variable ref for rate
	SpikeIdentifier        string // flow variable ref for identifier
	SpikeMessageWeight     string // flow variable ref for message weight
	SpikeUseEffectiveCount bool

	// For Quota
	QuotaInterval      int
	QuotaIntervalRef   string
	QuotaTimeUnit      string // minute, hour, day, week, month
	QuotaTimeUnitRef   string
	QuotaAllow         int
	QuotaAllowRef      string
	QuotaType          string // calendar, flexi, rollingwindow
	QuotaStartTime     string
	QuotaIdentifier    string
	QuotaDistributed   bool
	QuotaSynchronous   bool
	QuotaMessageWeight string

	// For VerifyAPIKey
	APIKeyRef string

	// For OAuthV2
	OAuthOperation             string // GenerateAccessToken, VerifyAccessToken, etc.
	OAuthExpiresIn             int
	OAuthExpiresInRef          string
	OAuthGrantType             string
	OAuthGrantTypeRef          string
	OAuthSupportedGrantTypes   []string
	OAuthGenerateResponse      bool
	OAuthAccessTokenRef        string
	OAuthAccessTokenPrefix     string
	OAuthClientId              string
	OAuthCode                  string
	OAuthRefreshTokenRef       string
	OAuthRefreshTokenExpiresIn int
	OAuthExternalAccess        bool
	OAuthExternalAccessToken   string
	OAuthStoreToken            bool
	OAuthAppEndUser            string
	OAuthUserName              string
	OAuthPassWord              string
	OAuthAttributes            []OAuthAttribute

	// For AccessControl
	AccessControlIPs   []string
	AccessControlMatch string // "ALLOW" or "DENY"

	// For BasicAuthentication
	BasicAuthOperation   string // "Encode" or "Decode"
	BasicAuthUser        string
	BasicAuthPassword    string
	BasicAuthUserRef     string
	BasicAuthPasswordRef string
	BasicAuthAssignTo    string

	// For JSONThreatProtection
	JSONThreatMaxDepth        int
	JSONThreatMaxStringLength int
	JSONThreatMaxArraySize    int
	JSONThreatMaxObjectSize   int
	JSONThreatMaxNumberLength int

	// For XMLThreatProtection
	XMLThreatMaxAttributeCount       int
	XMLThreatMaxAttributeValueLength int
	XMLThreatMaxChildrenDepth        int
	XMLThreatMaxElementDepth         int
	XMLThreatMaxNSPrefixLength       int
	XMLThreatMaxNSCount              int
	XMLThreatMaxElementTextLength    int

	// For RegularExpressionProtection
	RegexProtectionPatterns []RegexPatternConfig

	// For KeyValueMapOperations
	KVMMapName          string
	KVMMapIdentifier    string
	KVMGetKey           string
	KVMGetKeyRef        string
	KVMSetKey           string
	KVMSetKeyRef        string
	KVMIndex            string
	KVMScope            string // organization, environment, apiproxy
	KVMAssignTo         string
	KVMExclusiveCache   bool
	KVMExpiryTimeInSecs int
	KVMOperations       []KVMOperation

	// For MessageLogging
	MessageLoggingDestination string // Syslog, File
	MessageLoggingFormat      string
	MessageLoggingSyslog      *SyslogConfig
	MessageLoggingFile        *FileConfig

	// For StatisticsCollector
	StatisticsDimensions []StatisticsDimension

	// For CORS
	CORSAllowOrigins     []string
	CORSAllowMethods     []string
	CORSAllowHeaders     []string
	CORSExposeHeaders    []string
	CORSMaxAge           int
	CORSAllowCredentials bool

	// For ResponseCache
	CacheLookup     *CacheLookupConfig
	CachePopulate   *CachePopulateConfig
	CacheInvalidate *CacheInvalidateConfig

	// For ConcurrentRatelimit
	ConcurrentRateAllowConnections int
	ConcurrentRateTTL              int
	ConcurrentRateDistributed      bool
	ConcurrentRateStrictOnTTL      bool
	ConcurrentRateTargetIdentifier string

	// For GenerateJWT
	JWTAlgorithm      string
	JWTPrivateKeyRef  string
	JWTSubject        string
	JWTIssuer         string
	JWTAudience       string
	JWTExpiresIn      int
	JWTId             string
	JWTClaims         map[string]string
	JWTOutputVariable string
	JWTHeaderName     string
	JWTClaimName      string

	// For DecodeJWT
	JWTInputVariable        string
	JWTDecodeOutputVariable string

	// For PopulateCache
	CacheKey      string
	CacheKeyRef   string
	CacheValueRef string
	CacheResource string
	CacheExpiry   int
	CacheScope    string // apiproxy, application, exclusive
	CacheTimeout  int

	// For LookupCache
	LookupCacheKey            string
	LookupCacheKeyRef         string
	LookupCacheAssignTo       string
	LookupCacheResource       string
	LookupCacheScope          string
	LookupCacheSkipCacheOnHit bool

	// For XSLTransform
	XSLResource       string
	XSLSource         string
	XSLOutputVariable string

	// For OASValidation
	OASResourceURL      string
	OASSource           string
	OASValidationAction string // "raiseFault" or "none"
}

// FaultResponseConfig represents the FaultResponse in RaiseFault policy
type FaultResponseConfig struct {
	StatusCode         string
	ReasonPhrase       string
	Payload            string
	PayloadContentType string
	Headers            map[string]string
	AssignVariables    []AssignVariableConfig
	CopyHeaders        []string
	CopyStatusCode     bool
	CopyReasonPhrase   bool
	RemoveHeaders      []string
}

// AssignVariableConfig represents AssignVariable in RaiseFault/AssignMessage
type AssignVariableConfig struct {
	Name  string
	Value string
	Ref   string
}

// OAuthAttribute represents custom attributes on OAuth tokens
type OAuthAttribute struct {
	Name    string
	Value   string
	Ref     string
	Display bool
}

// RegexPatternConfig represents a regex protection pattern
type RegexPatternConfig struct {
	Name           string
	Pattern        string
	VariableRef    string
	HeaderName     string
	QueryParamName string
	FormParamName  string
}

// KVMOperation represents a KeyValueMap operation
type KVMOperation struct {
	Operation string // Get, Put, Delete
	Key       string
	Value     string
	KeyRef    string
	ValueRef  string
}

// SyslogConfig represents syslog logging configuration
type SyslogConfig struct {
	Message       string
	Host          string
	Port          int
	Protocol      string // TCP, UDP
	FormatMessage bool
}

// FileConfig represents file logging configuration
type FileConfig struct {
	Message string
}

// StatisticsDimension represents a statistics collector dimension
type StatisticsDimension struct {
	Name  string
	Ref   string
	Value string
}

// CacheLookupConfig represents cache lookup configuration
type CacheLookupConfig struct {
	CacheKey        string
	CacheResource   string
	ExcludeResponse bool
	SkipOnError     bool
}

// CachePopulateConfig represents cache populate configuration
type CachePopulateConfig struct {
	CacheKey      string
	CacheResource string
	Expiry        int
	SkipOnError   bool
}

// CacheInvalidateConfig represents cache invalidate configuration
type CacheInvalidateConfig struct {
	CacheKey      string
	CacheResource string
}

// VariableConfig represents a variable extraction configuration
type VariableConfig struct {
	Name           string
	Type           string // JSON, XML, FormParam, Header, QueryParam, URIPath
	Pattern        string // For JSON path, XPath, or regex pattern
	JSONPath       string
	XPath          string
	Index          int    // For URIPath
	Prefix         string // Optional prefix for variable name
	HeaderName     string // For Header
	QueryParamName string // For QueryParam
	FormParamName  string // For FormParam
}

// ServiceCalloutConfig represents service callout configuration
type ServiceCalloutConfig struct {
	Request  string // Name of request variable to create
	Response string // Name of response variable to create
	URL      string
	Method   string
	Headers  map[string]string
	Payload  string
}

// AssignMessageConfig represents part of an AssignMessage policy (Set, Add, Remove, Copy, etc.)
type AssignMessageConfig struct {
	Headers     map[string]string
	QueryParams map[string]string
	FormParams  map[string]string
	Payload     string
	Verb        string
	Path        string
}

// AssignMessagePolicy represents a parsed AssignMessage policy
type AssignMessagePolicy struct {
	Name                      string
	Headers                   map[string]string
	Payload                   string
	Verb                      string
	AssignTo                  string
	AssignVariables           map[string]string
	IgnoreUnresolvedVariables bool
}

// JavaScriptPolicy represents a parsed JS policy (kept for backwards compatibility)
type JavaScriptPolicy struct {
	Name       string
	TimeLimit  int
	Properties map[string]string
	Includes   []string
	ScriptURL  string
	Source     string
}

// FlowStep represents a step in a flow
type FlowStep struct {
	PolicyName string
	Condition  string
}

// FlowPhase represents a flow phase configuration
type FlowPhaseConfig struct {
	Description   string
	RequestSteps  []FlowStep
	ResponseSteps []FlowStep
}

// ConditionalFlow represents a named conditional flow
type ConditionalFlow struct {
	Name          string
	Description   string
	Condition     string
	RequestSteps  []FlowStep
	ResponseSteps []FlowStep
}

// ConfigurationVersion represents the API proxy configuration schema version
type ConfigurationVersion struct {
	MajorVersion int `xml:"majorVersion,attr"`
	MinorVersion int `xml:"minorVersion,attr"`
}

// BundleManifest represents manifest lists in the apiproxy.xml
type BundleManifest struct {
	Policies        []string
	ProxyEndpoints  []string
	TargetEndpoints []string
	Resources       []string
	TargetServers   []string
}

// FaultRule represents a fault rule configuration
type FaultRule struct {
	Name      string
	Condition string
	Steps     []FlowStep
}

// DefaultFaultRule represents the default fault rule
type DefaultFaultRule struct {
	AlwaysEnforce bool
	Condition     string
	Steps         []FlowStep
}

// HTTPProxyConnection represents the HTTP proxy connection configuration
type HTTPProxyConnection struct {
	BasePath    string
	VirtualHost []string
	Properties  map[string]string
}

// SSLInfo represents SSL/TLS configuration
type SSLInfo struct {
	Enabled                bool
	ClientAuthEnabled      bool
	Keystore               string
	Truststore             string
	CommonName             CommonName
	IgnoreValidationErrors bool
	Protocols              []string
	Ciphers                []string
}

// CommonName represents SSL common name configuration
type CommonName struct {
	Value         string
	WildcardMatch bool
}

// LoadBalancer represents load balancer configuration for TargetEndpoint
type LoadBalancer struct {
	Algorithm    string
	Server       []LoadBalancerServer
	MaxFailures  int
	RetryEnabled bool
	IsFallback   bool
}

// LoadBalancerServer represents a server in the load balancer
type LoadBalancerServer struct {
	Name       string
	Weight     int
	IsFallback bool
}

// HealthMonitor represents health monitor configuration
type HealthMonitor struct {
	IsEnabled     bool
	IntervalInSec int
	HTTPMonitor   *HTTPMonitor
	TCPMonitor    *TCPMonitor
}

// HTTPMonitor represents HTTP health monitor
type HTTPMonitor struct {
	Request HealthMonitorRequest
	Port    int
	Path    string
}

// HealthMonitorRequest represents the health check request
type HealthMonitorRequest struct {
	ConnectTimeoutInSec    int
	SocketReadTimeoutInSec int
	PayloadLimitInKB       int
	Verb                   string
	Path                   string
}

// TCPMonitor represents TCP health monitor
type TCPMonitor struct {
	Port                int
	ConnectTimeoutInSec int
}

// LocalTargetConnection represents local proxy-to-proxy chaining
type LocalTargetConnection struct {
	APIProxy      string
	ProxyEndpoint string
	PathSuffix    string
}

// ScriptTarget represents a Node.js script target
type ScriptTarget struct {
	ResourceURL string
}

// ProxyEndpoint represents parsed proxy configuration
type ProxyEndpoint struct {
	Name             string
	BasePath         string
	VirtualHost      []string
	HTTPProxyConn    HTTPProxyConnection
	PreFlow          FlowPhaseConfig
	PostFlow         FlowPhaseConfig
	PostClientFlow   FlowPhaseConfig // ProxyEndpoint only, Response-only
	ConditionalFlows []ConditionalFlow
	RouteRules       []RouteRule
	FaultRules       []FaultRule
	DefaultFaultRule *DefaultFaultRule
	Properties       map[string]string
}

// RouteRule defines routing to target
type RouteRule struct {
	Name           string
	TargetEndpoint string
	URL            string
	Condition      string
}

// TargetEndpoint represents parsed target configuration
type TargetEndpoint struct {
	Name             string
	PreFlow          FlowPhaseConfig
	PostFlow         FlowPhaseConfig
	URL              string
	Properties       map[string]string
	SSLInfo          SSLInfo
	LoadBalancer     *LoadBalancer
	HealthMonitor    *HealthMonitor
	LocalTargetConn  LocalTargetConnection
	ScriptTarget     ScriptTarget
	PathSuffix       string
	Connection       string // TargetServer name
	FaultRules       []FaultRule
	DefaultFaultRule *DefaultFaultRule
}

// HTTPStatus represents HTTP status
type HTTPStatus struct {
	Code    int
	Message string
}

type APIProxyBundle struct {
	Name            string
	Description     string
	DisplayName     string
	Revision        string
	ConfigVersion   ConfigurationVersion
	ProxyEndpoints  map[string]*ProxyEndpoint
	TargetEndpoints map[string]*TargetEndpoint
	Policies        map[string]*JavaScriptPolicy
	PoliciesMap     map[string]*Policy // All policies including AssignMessage, ExtractVariables, etc.
	BasePath        string
	Manifest        BundleManifest
	Spec            string                           // OpenAPI spec URL or path
	SharedFlows     map[string]*SharedFlowDefinition // Embedded shared flows (bundled with proxy)
}

// RouteHandler maps route to execution config
type RouteHandler struct {
	Route          string
	Bundle         *APIProxyBundle
	ProxyEndpoint  *ProxyEndpoint
	TargetEndpoint *TargetEndpoint
	OverrideURL    string
	StaticHeaders  map[string]string
}
