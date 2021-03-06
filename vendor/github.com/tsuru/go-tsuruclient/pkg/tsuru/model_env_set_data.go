/*
 * Tsuru
 *
 * Open source, extensible and Docker-based Platform as a Service (PaaS)
 *
 * API version: 1.6
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package tsuru

// Data sent to the environment set endpoint.
type EnvSetData struct {
	Envs      []Env `json:"envs,omitempty"`
	Norestart bool  `json:"norestart,omitempty"`
	Private   bool  `json:"private,omitempty"`
}
