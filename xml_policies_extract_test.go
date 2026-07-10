package apigeeconf

import (
	"encoding/xml"
	"strings"
	"testing"
)

func TestParseExtractVariablesVariableElement(t *testing.T) {
	tests := []struct {
		name     string
		xml      string
		expected VariableConfig
	}{
		{
			name: "Variable with Pattern",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<ExtractVariables name="GetVariable-MaximusRestData">
    <Variable name="maximus.rest.data">
        <Pattern>&lt;{data}/&gt;</Pattern>
    </Variable>
    <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
    <Source clearPayload="false">request</Source>
    <VariablePrefix>maximus.rest.escaped</VariablePrefix>
</ExtractVariables>`,
			expected: VariableConfig{
				Name:    "maximus.rest.data",
				Type:    "Variable",
				Pattern: "<{data}/>",
			},
		},
		{
			name: "Variable with Source",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<ExtractVariables name="TestPolicy">
    <Variable name="test.var">
        <Source>request</Source>
        <Pattern>test-pattern</Pattern>
    </Variable>
</ExtractVariables>`,
			expected: VariableConfig{
				Name:    "test.var",
				Type:    "Variable",
				Pattern: "test-pattern",
				Source:  "request",
			},
		},
		{
			name: "Multiple Variables",
			xml: `<?xml version="1.0" encoding="UTF-8"?>
<ExtractVariables name="MultiVar">
    <Variable name="var1">
        <Pattern>p1</Pattern>
    </Variable>
    <Variable name="var2">
        <Pattern>p2</Pattern>
    </Variable>
</ExtractVariables>`,
			expected: VariableConfig{
				Name:    "var2",
				Type:    "Variable",
				Pattern: "p2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := &XMLParser{}
			decoder := xml.NewDecoder(strings.NewReader(tt.xml))

			_, policy, err := parser.parseExtractVariablesPolicy(decoder, "test")
			if err != nil {
				t.Fatalf("parseExtractVariablesPolicy error: %v", err)
			}

			if len(policy.VariableConfigs) == 0 {
				t.Fatal("Expected VariableConfigs to have at least one entry")
			}

			vc := policy.VariableConfigs[len(policy.VariableConfigs)-1]
			if vc.Name != tt.expected.Name {
				t.Errorf("Name = %q; want %q", vc.Name, tt.expected.Name)
			}
			if vc.Type != tt.expected.Type {
				t.Errorf("Type = %q; want %q", vc.Type, tt.expected.Type)
			}
			if vc.Pattern != tt.expected.Pattern {
				t.Errorf("Pattern = %q; want %q", vc.Pattern, tt.expected.Pattern)
			}
			if tt.expected.Source != "" && vc.Source != tt.expected.Source {
				t.Errorf("Source = %q; want %q", vc.Source, tt.expected.Source)
			}
		})
	}
}

func TestLoadBundleWithVariableElement(t *testing.T) {
	bundle, err := LoadBundle("/Users/paalgyula/wspace/yettel/apigee-to-tyk-etl/get-apiproxies-artifacts/import_zip/Maximus_rev11.zip")
	if err != nil {
		t.Fatalf("LoadBundle error: %v", err)
	}

	policy, ok := bundle.PoliciesMap["GetVariable-MaximusRestData"]
	if !ok {
		t.Fatal("Policy GetVariable-MaximusRestData not found")
	}

	if policy.VariablePrefix != "maximus.rest.escaped" {
		t.Errorf("VariablePrefix = %q; want %q", policy.VariablePrefix, "maximus.rest.escaped")
	}

	if len(policy.VariableConfigs) != 1 {
		t.Fatalf("Expected 1 VariableConfig, got %d", len(policy.VariableConfigs))
	}

	vc := policy.VariableConfigs[0]
	if vc.Name != "maximus.rest.data" {
		t.Errorf("Name = %q; want %q", vc.Name, "maximus.rest.data")
	}
	if vc.Type != "Variable" {
		t.Errorf("Type = %q; want %q", vc.Type, "Variable")
	}
	if vc.Pattern != "<{data}/>" {
		t.Errorf("Pattern = %q; want %q", vc.Pattern, "<{data}/>")
	}
}
