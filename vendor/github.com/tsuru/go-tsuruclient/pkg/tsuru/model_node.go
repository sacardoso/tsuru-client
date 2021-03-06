/*
 * Tsuru
 *
 * Open source, extensible and Docker-based Platform as a Service (PaaS)
 *
 * API version: 1.6
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package tsuru

type Node struct {
	Address     string            `json:"address,omitempty"`
	Iaasid      string            `json:"iaasid,omitempty"`
	Status      string            `json:"status,omitempty"`
	Pool        string            `json:"pool,omitempty"`
	Provisioner string            `json:"provisioner,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
