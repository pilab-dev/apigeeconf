package apigeeconf

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// parseJavaScriptPolicy parses a JavaScript policy
func (p *XMLParser) parseJavaScriptPolicy(decoder *xml.Decoder, policyName string) (*JavaScriptPolicy, error) {
	policy := &JavaScriptPolicy{
		Name:       policyName,
		Properties: make(map[string]string),
		Includes:   []string{},
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "Javascript":
				for _, attr := range elem.Attr {
					if attr.Name.Local == "timeLimit" {
						fmt.Sscanf(attr.Value, "%d", &policy.TimeLimit)
					}
				}
			case "Properties":
				// Continue
			case "Property":
				var propValue, propName string
				for _, attr := range elem.Attr {
					if attr.Name.Local == "name" {
						propName = attr.Value
					}
				}
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						propValue = string(char)
					}
				}
				if propName != "" {
					policy.Properties[propName] = strings.TrimSpace(propValue)
				}
			case "IncludeURL":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						url := strings.TrimSpace(string(char))
						if url != "" {
							policy.Includes = append(policy.Includes, url)
						}
					}
				}
			case "ResourceURL":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						policy.ScriptURL = strings.TrimSpace(string(char))
					}
				}
			case "Source":
				if tok, err := decoder.Token(); err == nil {
					if char, ok := tok.(xml.CharData); ok {
						policy.Source = string(char)
					}
				}
			}
		}
	}

	if policy.TimeLimit == 0 {
		policy.TimeLimit = 200
	}

	return policy, nil
}
