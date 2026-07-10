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
		TimeLimit:  200, // Default
	}

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch elem := token.(type) {
		case xml.StartElement:
			switch {
			case strings.EqualFold(elem.Name.Local, "Javascript"):
				if tl := p.getAttributeValue(elem.Attr, "timeLimit"); tl != "" {
					var t int
					fmt.Sscanf(tl, "%d", &t)
					if t > 0 {
						policy.TimeLimit = t
					}
				}
			case strings.EqualFold(elem.Name.Local, "Properties"):
				p.parseProperties(decoder, policy.Properties)
			case strings.EqualFold(elem.Name.Local, "IncludeURL"):
				if txt, err := p.readCharData(decoder); err == nil && txt != "" {
					policy.Includes = append(policy.Includes, txt)
				}
			case strings.EqualFold(elem.Name.Local, "ResourceURL"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.ScriptURL = txt
				}
			case strings.EqualFold(elem.Name.Local, "Source"):
				if txt, err := p.readCharData(decoder); err == nil {
					policy.Source = txt
				}
			}
		case xml.EndElement:
			if strings.EqualFold(elem.Name.Local, "Javascript") {
				return policy, nil
			}
		}
	}

	return policy, nil
}
