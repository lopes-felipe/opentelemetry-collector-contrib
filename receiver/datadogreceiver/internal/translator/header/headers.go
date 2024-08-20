// Package header defines HTTP headers known convention used by the Trace Agent and Datadog's APM intake.
package header

const (
	// Lang specifies the name of the header which contains the language from
	// which the traces originate.
	Lang = "Datadog-Meta-Lang"

	// LangVersion specifies the name of the header which contains the origin
	// language's version.
	LangVersion = "Datadog-Meta-Lang-Version"

	// TracerVersion specifies the name of the header which contains the version
	// of the tracer sending the payload.
	TracerVersion = "Datadog-Meta-Tracer-Version"
)
