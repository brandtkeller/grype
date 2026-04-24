package pkg

import (
	"sort"

	"github.com/anchore/syft/syft/source/sourceproviders"
)

// CompletionHint tells callers (shell completion, docs generators) what kind
// of value follows a scheme prefix.
type CompletionHint int

const (
	// CompletionHintNone means no useful completion is possible — either the
	// argument is a freeform literal (pkg:, cpe:) or the value would require
	// a remote lookup that is too expensive to perform on Tab.
	CompletionHintNone CompletionHint = iota

	// CompletionHintFilePath means the argument is a path on disk; shells
	// should fall back to their native file completion.
	CompletionHintFilePath

	// CompletionHintLocalImage means the argument is an image reference
	// resolvable from a local container runtime (docker daemon, podman, etc).
	CompletionHintLocalImage
)

// Scheme describes one input scheme grype accepts and how its argument should
// be completed by a shell.
type Scheme struct {
	Prefix string // includes the trailing colon, e.g. "zarf:"
	Hint   CompletionHint
}

// syftSchemeOverride maps a syft source provider's Name() to the user-facing
// scheme prefix grype exposes, plus the completion hint. An empty prefix means
// "skip" — typically because the provider overlaps with another that grype
// prefers to surface.
type syftSchemeOverride struct {
	prefix string
	hint   CompletionHint
}

var syftSchemeOverrides = map[string]syftSchemeOverride{
	"docker":          {"docker:", CompletionHintLocalImage},
	"podman":          {"podman:", CompletionHintLocalImage},
	"containerd":      {"containerd:", CompletionHintLocalImage},
	"docker-archive":  {"docker-archive:", CompletionHintFilePath},
	"oci-archive":     {"oci-archive:", CompletionHintFilePath},
	"oci-dir":         {"oci-dir:", CompletionHintFilePath},
	"singularity":     {"singularity:", CompletionHintFilePath},
	"snap":            {"snap:", CompletionHintNone}, // local path OR remote snap name — ambiguous; don't guess
	"local-directory": {"dir:", CompletionHintFilePath},
	"local-file":      {"file:", CompletionHintFilePath},
	"oci-registry":    {"registry:", CompletionHintNone},
	"oci-model":       {"", CompletionHintNone}, // overlaps with oci-registry on the "registry" tag
}

// grypeLocalSchemes are handled by grype's provider chain before syft is
// consulted (see provide() in provider.go). They don't flow through
// sourceproviders.All() so they must be enumerated explicitly.
var grypeLocalSchemes = []Scheme{
	{"sbom:", CompletionHintFilePath},
	{"purl:", CompletionHintFilePath},
	{"pkg:", CompletionHintNone},
	{"cpe:", CompletionHintNone},
	{"cpes:", CompletionHintFilePath},
	{"zarf:", CompletionHintFilePath},
}

// Schemes returns every input scheme grype accepts that is worth surfacing in
// shell completion, annotated with a hint describing what follows the prefix.
//
// The result combines:
//   - grype-local schemes handled by grype's provider chain (sbom:, purl:, zarf:, …)
//   - a curated projection of syft's registered source providers
//
// Unknown syft providers (ones grype hasn't classified yet) are surfaced with
// their raw Name() and CompletionHintNone so newly added sources upstream still
// appear in completion without a grype-side code change.
func Schemes() []Scheme {
	out := make([]Scheme, 0, len(grypeLocalSchemes)+len(syftSchemeOverrides))
	seen := make(map[string]bool)

	for _, s := range grypeLocalSchemes {
		out = append(out, s)
		seen[s.Prefix] = true
	}

	for _, tv := range sourceproviders.All("", nil) {
		name := tv.Value.Name()
		override, known := syftSchemeOverrides[name]
		if !known {
			prefix := name + ":"
			if seen[prefix] {
				continue
			}
			out = append(out, Scheme{Prefix: prefix, Hint: CompletionHintNone})
			seen[prefix] = true
			continue
		}
		if override.prefix == "" {
			continue
		}
		if seen[override.prefix] {
			continue
		}
		out = append(out, Scheme{Prefix: override.prefix, Hint: override.hint})
		seen[override.prefix] = true
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Prefix < out[j].Prefix })
	return out
}
