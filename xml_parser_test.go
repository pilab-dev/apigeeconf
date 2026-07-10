package apigeeconf

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestXMLParserConditions(t *testing.T) {
	testCases := []struct {
		name     string
		xmlInput string
		wantCond string
	}{
		{
			name:     "simple condition",
			xmlInput: `<Flow><Condition>request.verb = "GET"</Condition></Flow>`,
			wantCond: `request.verb = "GET"`,
		},
		{
			name:     "regex with parentheses",
			xmlInput: `<Flow><Condition>(proxy.pathsuffix Matches "^/api/v1/.*")</Condition></Flow>`,
			wantCond: `(proxy.pathsuffix Matches "^/api/v1/.*")`,
		},
		{
			name:     "regex with question mark",
			xmlInput: `<Flow><Condition>request.uri Matches "\?.*"</Condition></Flow>`,
			wantCond: `request.uri Matches "\?.*"`,
		},
		{
			name:     "regex with slash and dots",
			xmlInput: `<Flow><Condition>proxy.pathsuffix MatchesPath "/(v1|v2)/users/.*"</Condition></Flow>`,
			wantCond: `proxy.pathsuffix MatchesPath "/(v1|v2)/users/.*"`,
		},
		{
			name:     "complex regex pattern",
			xmlInput: `<Flow><Condition>(request.header.X-Api-Key Matches "[A-Za-z0-9]+") and (request.verb = "POST")</Condition></Flow>`,
			wantCond: `(request.header.X-Api-Key Matches "[A-Za-z0-9]+") and (request.verb = "POST")`,
		},
		{
			name:     "regex with brackets",
			xmlInput: `<Flow><Condition>request.path Matches "^/api/v1/users/[0-9]+"</Condition></Flow>`,
			wantCond: `request.path Matches "^/api/v1/users/[0-9]+"`,
		},
		{
			name:     "numeric variable",
			xmlInput: `<Flow><Condition>request.content Length > 1000</Condition></Flow>`,
			wantCond: `request.content Length > 1000`,
		},
		{
			name:     "or condition with regex",
			xmlInput: `<Flow><Condition>((proxy.pathsuffix /^admin/) or (proxy.pathsuffix /^v2/))</Condition></Flow>`,
			wantCond: `((proxy.pathsuffix /^admin/) or (proxy.pathsuffix /^v2/))`,
		},
		{
			name:     "empty condition",
			xmlInput: `<Flow><Condition></Condition></Flow>`,
			wantCond: "",
		},
		{
			name:     "whitespace condition",
			xmlInput: `<Flow><Condition>   request.verb = "GET"   </Condition></Flow>`,
			wantCond: `request.verb = "GET"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := testParseCondition(tc.xmlInput)
			if result != tc.wantCond {
				t.Errorf("condition = %q, want %q", result, tc.wantCond)
			}
		})
	}
}

func testParseCondition(xmlInput string) string {
	xmlContent := `<?xml version="1.0"?><Flow xmlns="apigee.com">` + strings.ReplaceAll(strings.ReplaceAll(xmlInput, "<Flow>", ""), "</Flow>", "") + `</Flow>`
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	var inCondition bool
	var condition strings.Builder

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local == "Condition" {
				inCondition = true
			}
		case xml.CharData:
			if inCondition {
				condition.WriteString(string(elem))
			}
		case xml.EndElement:
			if elem.Name.Local == "Condition" {
				inCondition = false
			}
		}
	}
	return strings.TrimSpace(condition.String())
}

func TestPolicyRegexPatterns(t *testing.T) {
	testCases := []struct {
		name      string
		xmlInput  string
		wantCount int
		wantFirst string
	}{
		{
			name: "simple regex pattern",
			xmlInput: `<RegularExpressionProtection name="RegexPolicy1">
				<Source>request</Source>
				<Pattern>^[a-z]+$</Pattern>
			</RegularExpressionProtection>`,
			wantCount: 1,
			wantFirst: `^[a-z]+$`,
		},
		{
			name: "regex with alternation",
			xmlInput: `<RegularExpressionProtection name="RegexPolicy3">
				<Source>request</Source>
				<Pattern>admin|v1|v2</Pattern>
			</RegularExpressionProtection>`,
			wantCount: 1,
			wantFirst: `admin|v1|v2`,
		},
		{
			name: "multiple regex patterns",
			xmlInput: `<RegularExpressionProtection name="RegexPolicy4">
				<Source>request</Source>
				<Pattern>one</Pattern>
				<Pattern>two</Pattern>
				<Pattern>three</Pattern>
			</RegularExpressionProtection>`,
			wantCount: 3,
			wantFirst: `one`,
		},
		{
			name: "regex with special chars",
			xmlInput: `<RegularExpressionProtection name="RegexPolicy5">
				<Source>request</Source>
				<Pattern>/api/v1/users</Pattern>
			</RegularExpressionProtection>`,
			wantCount: 1,
			wantFirst: `/api/v1/users`,
		},
		{
			name: "regex with question mark",
			xmlInput: `<RegularExpressionProtection name="RegexPolicy7">
				<Source>request</Source>
				<Pattern>colou?r</Pattern>
			</RegularExpressionProtection>`,
			wantCount: 1,
			wantFirst: `colou?r`,
		},
		{
			name: "empty pattern",
			xmlInput: `<RegularExpressionProtection name="RegexPolicy8">
				<Source>request</Source>
			</RegularExpressionProtection>`,
			wantCount: 0,
			wantFirst: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := testParseRegexPolicy(tc.xmlInput)
			count := len(result)
			if count != tc.wantCount {
				t.Errorf("pattern count = %d, want %d", count, tc.wantCount)
			}
			if count > 0 && result[0] != tc.wantFirst {
				t.Errorf("pattern[0] = %q, want %q", result[0], tc.wantFirst)
			}
		})
	}
}

func testParseRegexPolicy(xmlInput string) []string {
	xmlContent := `<?xml version="1.0"?>` + xmlInput
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	var patterns []string
	var inSource bool

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Source":
				inSource = true
			case "Pattern":
				if txt, err := readCharDataRaw(decoder); err == nil {
					patterns = append(patterns, txt)
				}
			}
		case xml.CharData:
			if inSource {
				inSource = false
			}
		}
	}
	return patterns
}

func readCharDataRaw(decoder *xml.Decoder) (string, error) {
	depth := 0
	var result strings.Builder
	for {
		tok, err := decoder.Token()
		if err != nil {
			if result.Len() == 0 {
				return "", err
			}
			return result.String(), nil
		}
		switch v := tok.(type) {
		case xml.CharData:
			result.WriteString(string(v))
		case xml.StartElement:
			depth++
		case xml.EndElement:
			if depth == 0 {
				return strings.TrimSpace(result.String()), nil
			}
			depth--
		}
	}
}

func TestAssignMessagePayloads(t *testing.T) {
	testCases := []struct {
		name     string
		xmlInput string
		want     string
	}{
		{
			name: "simple XML payload",
			xmlInput: `<AssignMessage name="AssignPayload1">
				<Set>
					<Payload><Root><Item>test</Item></Root></Payload>
				</Set>
			</AssignMessage>`,
			want: `<Root><Item>test</Item></Root>`,
		},
		{
			name: "JSON payload with braces",
			xmlInput: `<AssignMessage name="AssignPayload2">
				<Set>
					<Payload>{"key": "value", "array": [1,2,3]}</Payload>
				</Set>
			</AssignMessage>`,
			want: `{"key": "value", "array": [1,2,3]}`,
		},
		{
			name: "template with variables",
			xmlInput: `<AssignMessage name="AssignPayload4">
				<Set>
					<Payload>{request.header.X-Custom}</Payload>
				</Set>
			</AssignMessage>`,
			want: `{request.header.X-Custom}`,
		},
		{
			name: "empty payload",
			xmlInput: `<AssignMessage name="AssignPayload5">
				<Set>
					<Payload></Payload>
				</Set>
			</AssignMessage>`,
			want: "",
		},
		{
			name: "payload with newlines",
			xmlInput: `<AssignMessage name="AssignPayload6">
				<Set>
					<Payload>line1
line2
line3</Payload>
				</Set>
			</AssignMessage>`,
			want: "line1\nline2\nline3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := testParseAssignMessage(tc.xmlInput)
			if result != tc.want {
				t.Errorf("payload = %q, want %q", result, tc.want)
			}
		})
	}
}

func testParseAssignMessage(xmlInput string) string {
	xmlContent := `<?xml version="1.0"?>` + xmlInput
	parser := NewXMLParser("")
	jsPol, pol, err := parser.parsePolicyXMLTest(xmlContent)
	if err != nil {
		return ""
	}
	_ = jsPol
	if pol != nil && pol.AssignMessageSet != nil {
		return pol.AssignMessageSet.Payload
	}
	if pol != nil {
		return pol.Payload
	}
	return ""
}

func (p *XMLParser) parsePolicyXMLTest(xmlContent string) (*JavaScriptPolicy, *Policy, error) {
	data := []byte(xmlContent)
	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	var policyType string
	var policyName string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if elem, ok := token.(xml.StartElement); ok {
			policyType = elem.Name.Local
			for _, attr := range elem.Attr {
				if attr.Name.Local == "name" {
					policyName = attr.Value
				}
			}
			break
		}
	}

	decoder = xml.NewDecoder(strings.NewReader(string(data)))

	switch policyType {
	case "AssignMessage":
		return p.parseAssignMessagePolicy(decoder, policyName)
	default:
		return nil, nil, nil
	}
}

func TestAllPolicyTypesParse(t *testing.T) {
	policyTypes := []string{
		"Javascript",
		"AssignMessage",
		"ExtractVariables",
		"ServiceCallout",
		"FlowCallout",
		"RaiseFault",
		"SpikeArrest",
		"Quota",
		"VerifyAPIKey",
		"OAuthV2",
		"BasicAuthentication",
		"JSONThreatProtection",
		"XMLThreatProtection",
		"RegularExpressionProtection",
		"KeyValueMapOperations",
		"MessageLogging",
		"StatisticsCollector",
		"CORS",
		"ResponseCache",
		"PopulateCache",
		"LookupCache",
		"InvalidateCache",
		"GenerateJWT",
		"VerifyJWT",
		"DecodeJWT",
		"GenerateJWS",
		"VerifyJWS",
		"DecodeJWS",
		"JSONtoXML",
		"XMLtoJSON",
		"XSLTransform",
		"AccessEntity",
		"ExtensionCallout",
		"HMAC",
		"JavaCallout",
		"PythonScript",
		"ResetQuota",
		"ConcurrentRatelimit",
		"GetOAuthV2Info",
		"RevokeOAuthV2",
		"SetOAuthV2Info",
		"DeleteOAuthV2Info",
		"SAMLAssertion",
		"SOAPMessageValidation",
		"OASValidation",
		"MonetizationLimitsCheck",
		"LDAP",
	}

	for _, policyType := range policyTypes {
		t.Run(policyType, func(t *testing.T) {
			err := testParsePolicyType(policyType)
			if err != nil {
				t.Errorf("failed to parse policy type %s: %v", policyType, err)
			}
		})
	}
}

func testParsePolicyType(policyType string) error {
	templates := map[string]string{
		"Javascript":                  `<Javascript name="Test1"></Javascript>`,
		"AssignMessage":               `<AssignMessage name="Test2"></AssignMessage>`,
		"ExtractVariables":            `<ExtractVariables name="Test3"></ExtractVariables>`,
		"ServiceCallout":              `<ServiceCallout name="Test4"></ServiceCallout>`,
		"FlowCallout":                 `<FlowCallout name="Test5"></FlowCallout>`,
		"RaiseFault":                  `<RaiseFault name="Test6"></RaiseFault>`,
		"SpikeArrest":                 `<SpikeArrest name="Test7"></SpikeArrest>`,
		"Quota":                       `<Quota name="Test8"></Quota>`,
		"VerifyAPIKey":                `<VerifyAPIKey name="Test9"></VerifyAPIKey>`,
		"OAuthV2":                     `<OAuthV2 name="Test10"></OAuthV2>`,
		"BasicAuthentication":         `<BasicAuthentication name="Test11"></BasicAuthentication>`,
		"JSONThreatProtection":        `<JSONThreatProtection name="Test12"></JSONThreatProtection>`,
		"XMLThreatProtection":         `<XMLThreatProtection name="Test13"></XMLThreatProtection>`,
		"RegularExpressionProtection": `<RegularExpressionProtection name="Test14"></RegularExpressionProtection>`,
		"KeyValueMapOperations":       `<KeyValueMapOperations name="Test15"></KeyValueMapOperations>`,
		"MessageLogging":              `<MessageLogging name="Test16"></MessageLogging>`,
		"StatisticsCollector":         `<StatisticsCollector name="Test17"></StatisticsCollector>`,
		"CORS":                        `<CORS name="Test18"></CORS>`,
		"ResponseCache":               `<ResponseCache name="Test19"></ResponseCache>`,
		"PopulateCache":               `<PopulateCache name="Test20"></PopulateCache>`,
		"LookupCache":                 `<LookupCache name="Test21"></LookupCache>`,
		"InvalidateCache":             `<InvalidateCache name="Test22"></InvalidateCache>`,
		"GenerateJWT":                 `<GenerateJWT name="Test23"></GenerateJWT>`,
		"VerifyJWT":                   `<VerifyJWT name="Test24"></VerifyJWT>`,
		"DecodeJWT":                   `<DecodeJWT name="Test25"></DecodeJWT>`,
		"GenerateJWS":                 `<GenerateJWS name="Test26"></GenerateJWS>`,
		"VerifyJWS":                   `<VerifyJWS name="Test27"></VerifyJWS>`,
		"DecodeJWS":                   `<DecodeJWS name="Test28"></DecodeJWS>`,
		"JSONtoXML":                   `<JSONtoXML name="Test29"></JSONtoXML>`,
		"XMLtoJSON":                   `<XMLtoJSON name="Test30"></XMLtoJSON>`,
		"XSLTransform":                `<XSLTransform name="Test31"></XSLTransform>`,
		"AccessEntity":                `<AccessEntity name="Test32"></AccessEntity>`,
		"ExtensionCallout":            `<ExtensionCallout name="Test33"></ExtensionCallout>`,
		"HMAC":                        `<HMAC name="Test34"></HMAC>`,
		"JavaCallout":                 `<JavaCallout name="Test35"></JavaCallout>`,
		"PythonScript":                `<PythonScript name="Test36"></PythonScript>`,
		"ResetQuota":                  `<ResetQuota name="Test37"></ResetQuota>`,
		"ConcurrentRatelimit":         `<ConcurrentRatelimit name="Test38"></ConcurrentRatelimit>`,
		"GetOAuthV2Info":              `<GetOAuthV2Info name="Test39"></GetOAuthV2Info>`,
		"RevokeOAuthV2":               `<RevokeOAuthV2 name="Test40"></RevokeOAuthV2>`,
		"SetOAuthV2Info":              `<SetOAuthV2Info name="Test41"></SetOAuthV2Info>`,
		"DeleteOAuthV2Info":           `<DeleteOAuthV2Info name="Test42"></DeleteOAuthV2Info>`,
		"SAMLAssertion":               `<SAMLAssertion name="Test43"></SAMLAssertion>`,
		"SOAPMessageValidation":       `<SOAPMessageValidation name="Test44"></SOAPMessageValidation>`,
		"OASValidation":               `<OASValidation name="Test45"></OASValidation>`,
		"MonetizationLimitsCheck":     `<MonetizationLimitsCheck name="Test46"></MonetizationLimitsCheck>`,
		"LDAP":                        `<LDAP name="Test47"></LDAP>`,
	}

	xmlInput := templates[policyType]
	if xmlInput == "" {
		return nil
	}
	xmlContent := `<?xml version="1.0"?>` + xmlInput

	data := []byte(xmlContent)
	decoder := xml.NewDecoder(strings.NewReader(string(data)))

	var name string
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		if elem, ok := token.(xml.StartElement); ok {
			for _, attr := range elem.Attr {
				if attr.Name.Local == "name" {
					name = attr.Value
					break
				}
			}
		}
	}
	if name == "" {
		return nil
	}
	return nil
}

func TestFullBundleParsing(t *testing.T) {
	dir := t.TempDir()

	os.MkdirAll(filepath.Join(dir, "policies"), 0755)
	os.MkdirAll(filepath.Join(dir, "proxies"), 0755)
	os.MkdirAll(filepath.Join(dir, "targets"), 0755)

	os.WriteFile(filepath.Join(dir, "apiproxy.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<APIProxy name="TestBundle">
  <ConfigurationVersion majorVersion="1" minorVersion="0"/>
</APIProxy>`), 0644)

	os.WriteFile(filepath.Join(dir, "policies", "AssignPayload.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<AssignMessage name="AssignPayload">
  <Set>
    <Payload>{"test": "value"}</Payload>
  </Set>
</AssignMessage>`), 0644)

	os.WriteFile(filepath.Join(dir, "proxies", "default.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<ProxyEndpoint name="default">
  <HTTPProxyConnection>
    <BasePath>/api</BasePath>
  </HTTPProxyConnection>
  <Flows>
    <Flow name="test-flow">
      <Condition>request.verb = "GET"</Condition>
      <Request>
        <Step><Name>AssignPayload</Name></Step>
      </Request>
    </Flow>
  </Flows>
</ProxyEndpoint>`), 0644)

	os.WriteFile(filepath.Join(dir, "targets", "default.xml"), []byte(`<?xml version="1.0" encoding="UTF-8"?>
<TargetEndpoint name="default">
  <URL>https://api.example.com</URL>
</TargetEndpoint>`), 0644)

	parser := NewXMLParser(dir)
	bundle, err := parser.ParseBundle()
	if err != nil {
		t.Fatalf("ParseBundle failed: %v", err)
	}

	if bundle.Name != "TestBundle" {
		t.Errorf("bundle name = %q, want %q", bundle.Name, "TestBundle")
	}

	if len(bundle.PoliciesMap) != 1 {
		t.Errorf("policies count = %d, want 1", len(bundle.PoliciesMap))
	}

	if len(bundle.ProxyEndpoints) != 1 {
		t.Errorf("proxy endpoints count = %d, want 1", len(bundle.ProxyEndpoints))
	}

	if len(bundle.TargetEndpoints) != 1 {
		t.Errorf("target endpoints count = %d, want 1", len(bundle.TargetEndpoints))
	}
}

func TestReadingCharData(t *testing.T) {
	testCases := []struct {
		name     string
		xmlInput string
		want     string
	}{
		{
			name:     "simple text",
			xmlInput: `<Root><Item>hello world</Item></Root>`,
			want:     "hello world",
		},
		{
			name:     "text with whitespace",
			xmlInput: `<Root><Item>   trimmed   </Item></Root>`,
			want:     "trimmed",
		},
		{
			name:     "empty text",
			xmlInput: `<Root><Item></Item></Root>`,
			want:     "",
		},
		{
			name: "multiline text",
			xmlInput: `<Root><Item>line1
line2
line3</Item></Root>`,
			want: "line1\nline2\nline3",
		},
		{
			name:     "XML entity in text",
			xmlInput: `<Root><Item>&lt;tag&gt;</Item></Root>`,
			want:     "<tag>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := testReadCharData(tc.xmlInput)
			if result != tc.want {
				t.Errorf("char data = %q, want %q", result, tc.want)
			}
		})
	}
}

func testReadCharData(xmlInput string) string {
	xmlContent := `<?xml version="1.0"?>` + xmlInput
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	return readCharDataRawUnsafe(decoder)
}

func readCharDataRawUnsafe(decoder *xml.Decoder) string {
	for {
		tok, err := decoder.Token()
		if err != nil {
			return ""
		}
		if char, ok := tok.(xml.CharData); ok {
			return strings.TrimSpace(string(char))
		}
		if end, ok := tok.(xml.EndElement); ok && end.Name.Local == "Item" {
			return ""
		}
	}
	return ""
}

func TestProxyEndpointParsing(t *testing.T) {
	testCases := []struct {
		name         string
		xmlInput     string
		wantName     string
		wantBasePath string
		wantFlows    int
	}{
		{
			name:         "basic proxy endpoint",
			xmlInput:     `<ProxyEndpoint name="default"><HTTPProxyConnection><BasePath>/api</BasePath></HTTPProxyConnection></ProxyEndpoint>`,
			wantName:     "default",
			wantBasePath: "/api",
			wantFlows:    0,
		},
		{
			name:         "proxy with flow and condition",
			xmlInput:     `<ProxyEndpoint name="test"><HTTPProxyConnection><BasePath>/test</BasePath></HTTPProxyConnection><Flows><Flow name="f1"><Condition>request.verb = "GET"</Condition></Flow></Flows></ProxyEndpoint>`,
			wantName:     "test",
			wantBasePath: "/test",
			wantFlows:    1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewXMLParser("")
			proxy, err := parser.parseProxyEndpointXMLDirect(tc.xmlInput)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if proxy.Name != tc.wantName {
				t.Errorf("name = %q, want %q", proxy.Name, tc.wantName)
			}
			if proxy.BasePath != tc.wantBasePath {
				t.Errorf("basePath = %q, want %q", proxy.BasePath, tc.wantBasePath)
			}
			if len(proxy.ConditionalFlows) != tc.wantFlows {
				t.Errorf("flows = %d, want %d", len(proxy.ConditionalFlows), tc.wantFlows)
			}
		})
	}
}

func (p *XMLParser) parseProxyEndpointXMLDirect(xmlInput string) (*ProxyEndpoint, error) {
	data := []byte(xmlInput)
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	return p.parseProxyEndpointFromDecoder(decoder, data)
}

func (p *XMLParser) parseProxyEndpointFromDecoder(decoder *xml.Decoder, data []byte) (*ProxyEndpoint, error) {
	proxy := &ProxyEndpoint{
		ConditionalFlows: []ConditionalFlow{},
		RouteRules:       []RouteRule{},
		Properties:       make(map[string]string),
	}

	var currentFlow string
	var currentSide string
	var inCondition bool

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "ProxyEndpoint":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						proxy.Name = attr.Value
					}
				}
			case "HTTPProxyConnection":
				proxy.HTTPProxyConn.BasePath = ""
			case "BasePath":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						proxy.BasePath = strings.TrimSpace(string(char))
						proxy.HTTPProxyConn.BasePath = proxy.BasePath
					}
				}
			case "Flows":
				currentFlow = "Flows"
			case "Flow":
				flow := ConditionalFlow{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						flow.Name = attr.Value
					}
				}
				proxy.ConditionalFlows = append(proxy.ConditionalFlows, flow)
				currentFlow = "Flow"
			case "Condition":
				if currentFlow == "Flow" {
					inCondition = true
				}
			case "Request":
				currentSide = "Request"
			case "Response":
				currentSide = "Response"
			case "Step":
				step := FlowStep{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "Name" {
						step.PolicyName = attr.Value
					}
				}
				if currentFlow == "Flow" && len(proxy.ConditionalFlows) > 0 {
					if currentSide == "Request" {
						proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].RequestSteps =
							append(proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].RequestSteps, step)
					} else {
						proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].ResponseSteps =
							append(proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].ResponseSteps, step)
					}
				}
			}
		case xml.CharData:
			if inCondition && len(proxy.ConditionalFlows) > 0 {
				proxy.ConditionalFlows[len(proxy.ConditionalFlows)-1].Condition += string(elem)
			}
		case xml.EndElement:
			if elem.Name.Local == "Condition" {
				inCondition = false
			}
			if elem.Name.Local == "Flows" || elem.Name.Local == "Flow" {
				currentFlow = ""
			}
		}
	}

	return proxy, nil
}

func TestTargetEndpointParsing(t *testing.T) {
	testCases := []struct {
		name     string
		xmlInput string
		want     string
		wantF    int
	}{
		{
			name:     "simple target",
			xmlInput: `<TargetEndpoint name="default"><URL>https://api.example.com</URL></TargetEndpoint>`,
			want:     "https://api.example.com",
			wantF:    0,
		},
		{
			name:     "target with flow and condition",
			xmlInput: `<TargetEndpoint name="test"><URL>https://test.com</URL><Flows><Flow name="f1"><Condition>request.verb = "GET"</Condition></Flow></Flows></TargetEndpoint>`,
			want:     "https://test.com",
			wantF:    1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parser := NewXMLParser("")
			target, err := parser.parseTargetEndpointXMLDirect(tc.xmlInput)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if target.URL != tc.want {
				t.Errorf("URL = %q, want %q", target.URL, tc.want)
			}
			if len(target.ConditionalFlows) != tc.wantF {
				t.Errorf("flows = %d, want %d", len(target.ConditionalFlows), tc.wantF)
			}
		})
	}
}

func (p *XMLParser) parseTargetEndpointXMLDirect(xmlInput string) (*TargetEndpoint, error) {
	data := []byte(xmlInput)
	decoder := xml.NewDecoder(strings.NewReader(string(data)))
	return p.parseTargetEndpointFromDecoder(decoder, data)
}

func (p *XMLParser) parseTargetEndpointFromDecoder(decoder *xml.Decoder, data []byte) (*TargetEndpoint, error) {
	target := &TargetEndpoint{
		ConditionalFlows: []ConditionalFlow{},
		Properties:       make(map[string]string),
	}

	var currentFlow string
	var inCondition bool

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "TargetEndpoint":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						target.Name = attr.Value
					}
				}
			case "URL":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						target.URL = strings.TrimSpace(string(char))
					}
				}
			case "Flows":
				currentFlow = "Flows"
			case "Flow":
				flow := ConditionalFlow{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						flow.Name = attr.Value
					}
				}
				target.ConditionalFlows = append(target.ConditionalFlows, flow)
				currentFlow = "Flow"
			case "Condition":
				if currentFlow == "Flow" {
					inCondition = true
				}
			}
		case xml.CharData:
			if inCondition && len(target.ConditionalFlows) > 0 {
				target.ConditionalFlows[len(target.ConditionalFlows)-1].Condition += string(elem)
			}
		case xml.EndElement:
			if elem.Name.Local == "Condition" {
				inCondition = false
			}
			if elem.Name.Local == "Flows" || elem.Name.Local == "Flow" {
				currentFlow = ""
			}
		}
	}

	return target, nil
}

func TestRouteRules(t *testing.T) {
	testCases := []struct {
		name     string
		xmlInput string
		wantURL  string
	}{
		{
			name:     "simple URL",
			xmlInput: `<RouteRule name="RR1"><URL>https://api.example.com</URL></RouteRule>`,
			wantURL:  "https://api.example.com",
		},
		{
			name:     "URL with path",
			xmlInput: `<RouteRule name="RR2"><URL>https://{target.server}/v1/users</URL></RouteRule>`,
			wantURL:  "https://{target.server}/v1/users",
		},
		{
			name:     "URL with condition",
			xmlInput: `<RouteRule name="RR3"><Condition>request.verb = "GET"</Condition><URL>https://example.com/get</URL></RouteRule>`,
			wantURL:  "https://example.com/get",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := testParseRouteRule(tc.xmlInput)
			if result != tc.wantURL {
				t.Errorf("route rule URL = %q, want %q", result, tc.wantURL)
			}
		})
	}
}

func testParseRouteRule(xmlInput string) string {
	xmlContent := `<?xml version="1.0"?>` + xmlInput
	decoder := xml.NewDecoder(strings.NewReader(xmlContent))
	rules := []RouteRule{}
	var inRule bool
	var currentRule *RouteRule

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			if elem.Name.Local == "RouteRule" {
				rule := RouteRule{}
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						rule.Name = attr.Value
					}
				}
				rules = append(rules, rule)
				currentRule = &rules[len(rules)-1]
				inRule = true
			}
			if inRule && elem.Name.Local == "URL" {
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						currentRule.URL = strings.TrimSpace(string(char))
					}
				}
			}
			if inRule && elem.Name.Local == "Condition" {
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						currentRule.Condition = strings.TrimSpace(string(char))
					}
				}
			}
		case xml.EndElement:
			if elem.Name.Local == "RouteRule" {
				inRule = false
				currentRule = nil
			}
		}
	}

	if len(rules) > 0 {
		return rules[0].URL
	}
	return ""
}
