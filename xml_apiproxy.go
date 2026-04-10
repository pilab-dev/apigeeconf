package apigeeconf

import "encoding/xml"

// apiproxyRoot represents the root apiproxy.xml structure
type apiproxyRoot struct {
	XMLName         xml.Name             `xml:"APIProxy"`
	Name            string               `xml:"name,attr"`
	Revision        string               `xml:"revision,attr"`
	Description     string               `xml:"Description"`
	DisplayName     string               `xml:"DisplayName"`
	ConfigVersion   ConfigurationVersion `xml:"ConfigurationVersion"`
	Policies        manifestList         `xml:"Policies"`
	ProxyEndpoints  manifestList         `xml:"ProxyEndpoints"`
	TargetEndpoints manifestList         `xml:"TargetEndpoints"`
	Resources       manifestList         `xml:"Resources"`
	TargetServers   manifestList         `xml:"TargetServers"`
	Spec            string               `xml:"Spec"`
}

type manifestList struct {
	Items []string `xml:",any"`
}

// parseApiproxyXML parses the root apiproxy.xml file
func (p *XMLParser) parseApiproxyXML(data []byte, bundle *APIProxyBundle) error {
	var root apiproxyRoot
	if err := xml.Unmarshal(data, &root); err != nil {
		return err
	}

	bundle.Name = root.Name
	bundle.Revision = root.Revision
	bundle.Description = root.Description
	bundle.DisplayName = root.DisplayName
	bundle.ConfigVersion = root.ConfigVersion
	bundle.Spec = root.Spec

	// Extract manifest items
	for _, item := range root.Policies.Items {
		bundle.Manifest.Policies = append(bundle.Manifest.Policies, item)
	}
	for _, item := range root.ProxyEndpoints.Items {
		bundle.Manifest.ProxyEndpoints = append(bundle.Manifest.ProxyEndpoints, item)
	}
	for _, item := range root.TargetEndpoints.Items {
		bundle.Manifest.TargetEndpoints = append(bundle.Manifest.TargetEndpoints, item)
	}
	for _, item := range root.Resources.Items {
		bundle.Manifest.Resources = append(bundle.Manifest.Resources, item)
	}
	for _, item := range root.TargetServers.Items {
		bundle.Manifest.TargetServers = append(bundle.Manifest.TargetServers, item)
	}

	return nil
}
