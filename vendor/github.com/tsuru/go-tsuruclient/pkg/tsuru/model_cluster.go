/*
 * Tsuru
 *
 * Open source, extensible and Docker-based Platform as a Service (PaaS)
 *
 * API version: 1.6
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package tsuru

type Cluster struct {
	Name        string            `json:"name,omitempty"`
	Addresses   []string          `json:"addresses,omitempty"`
	Provisioner string            `json:"provisioner,omitempty"`
	Cacert      []byte            `json:"cacert,omitempty"`
	Clientcert  []byte            `json:"clientcert,omitempty"`
	Clientkey   []byte            `json:"clientkey,omitempty"`
	Pools       []string          `json:"pools,omitempty"`
	CustomData  map[string]string `json:"custom_data,omitempty"`
	CreateData  map[string]string `json:"create_data,omitempty"`
	Default     bool              `json:"default,omitempty"`
}
