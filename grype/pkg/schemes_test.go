package pkg

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemes_includesAllGrypeLocalSchemes(t *testing.T) {
	got := Schemes()
	index := make(map[string]CompletionHint, len(got))
	for _, s := range got {
		index[s.Prefix] = s.Hint
	}

	for _, want := range grypeLocalSchemes {
		hint, ok := index[want.Prefix]
		require.Truef(t, ok, "expected Schemes() to include grype-local prefix %q", want.Prefix)
		assert.Equalf(t, want.Hint, hint, "hint mismatch for %q", want.Prefix)
	}
}

func TestSchemes_surfacesExpectedSyftProjections(t *testing.T) {
	got := Schemes()
	index := make(map[string]CompletionHint, len(got))
	for _, s := range got {
		index[s.Prefix] = s.Hint
	}

	// These prefixes should be present regardless of syft provider ordering.
	// The list is intentionally narrower than syft's full tag set — it's the
	// curated projection posture described in schemes.go.
	wantPresent := map[string]CompletionHint{
		"docker:":         CompletionHintLocalImage,
		"podman:":         CompletionHintLocalImage,
		"containerd:":     CompletionHintLocalImage,
		"docker-archive:": CompletionHintFilePath,
		"oci-archive:":    CompletionHintFilePath,
		"oci-dir:":        CompletionHintFilePath,
		"singularity:":    CompletionHintFilePath,
		"dir:":            CompletionHintFilePath,
		"file:":           CompletionHintFilePath,
		"registry:":       CompletionHintNone,
	}
	for prefix, wantHint := range wantPresent {
		hint, ok := index[prefix]
		require.Truef(t, ok, "expected %q in Schemes()", prefix)
		assert.Equalf(t, wantHint, hint, "hint mismatch for %q", prefix)
	}
}

func TestSchemes_suppressesInternalSyftNames(t *testing.T) {
	// These are syft's internal provider names that grype exposes under
	// friendlier prefixes. They must NOT appear in Schemes() so users don't
	// see both "dir:" and "local-directory:" as options.
	got := Schemes()
	index := make(map[string]bool, len(got))
	for _, s := range got {
		index[s.Prefix] = true
	}

	for _, suppressed := range []string{"local-directory:", "local-file:", "oci-registry:", "oci-model:"} {
		assert.Falsef(t, index[suppressed], "prefix %q should be suppressed in Schemes()", suppressed)
	}
}

func TestSchemes_prefixesAreUniqueAndSorted(t *testing.T) {
	got := Schemes()
	seen := make(map[string]bool, len(got))
	var prev string
	for i, s := range got {
		require.Falsef(t, seen[s.Prefix], "duplicate prefix %q in Schemes()", s.Prefix)
		seen[s.Prefix] = true
		if i > 0 {
			assert.Lessf(t, prev, s.Prefix, "Schemes() output must be sorted")
		}
		prev = s.Prefix
		assert.NotEmpty(t, s.Prefix)
		assert.Truef(t, s.Prefix[len(s.Prefix)-1] == ':', "prefix %q must end with ':'", s.Prefix)
	}
}
