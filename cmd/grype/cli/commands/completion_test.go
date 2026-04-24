package commands

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/pkg"
)

func TestDetectScheme(t *testing.T) {
	schemes := []pkg.Scheme{
		{Prefix: "zarf:", Hint: pkg.CompletionHintFilePath},
		{Prefix: "docker:", Hint: pkg.CompletionHintLocalImage},
		{Prefix: "pkg:", Hint: pkg.CompletionHintNone},
	}

	tests := []struct {
		name        string
		args        []string
		toComplete  string
		wantMatched bool
		wantPrefix  string
		wantRest    string
	}{
		{
			name:        "bash colon-split, known scheme",
			args:        []string{"zarf", ":"},
			toComplete:  "/tm",
			wantMatched: true,
			wantPrefix:  "zarf:",
			wantRest:    "/tm",
		},
		{
			name:        "bash colon-split, empty suffix",
			args:        []string{"docker", ":"},
			toComplete:  "",
			wantMatched: true,
			wantPrefix:  "docker:",
			wantRest:    "",
		},
		{
			name:        "bash colon-split, unknown scheme",
			args:        []string{"mystery", ":"},
			toComplete:  "abc",
			wantMatched: false,
		},
		{
			name:        "zsh/fish single-token, known scheme",
			args:        nil,
			toComplete:  "zarf:/tm",
			wantMatched: true,
			wantPrefix:  "zarf:",
			wantRest:    "/tm",
		},
		{
			name:        "zsh/fish single-token, prefix only",
			args:        nil,
			toComplete:  "zarf:",
			wantMatched: true,
			wantPrefix:  "zarf:",
			wantRest:    "",
		},
		{
			name:        "single-token, partial scheme name (not yet committed)",
			args:        nil,
			toComplete:  "zar",
			wantMatched: false,
		},
		{
			name:        "single-token, literal PURL",
			args:        nil,
			toComplete:  "pkg:apk/openssl@3.2.1",
			wantMatched: true,
			wantPrefix:  "pkg:",
			wantRest:    "apk/openssl@3.2.1",
		},
		{
			name:        "empty",
			args:        nil,
			toComplete:  "",
			wantMatched: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			scheme, rest, matched := detectScheme(tc.args, tc.toComplete, schemes)
			assert.Equal(t, tc.wantMatched, matched)
			if tc.wantMatched {
				assert.Equal(t, tc.wantPrefix, scheme.Prefix)
				assert.Equal(t, tc.wantRest, rest)
			}
		})
	}
}

func TestRootArgsCompletion_matchedSchemes(t *testing.T) {
	// Directive-only assertions. File-path single-token globbing is covered
	// separately (TestCompleteFilePath_singleToken) because it touches the
	// filesystem.
	tests := []struct {
		name          string
		args          []string
		toComplete    string
		wantDirective cobra.ShellCompDirective
		wantEmpty     bool
	}{
		{
			name:          "file-path scheme, bash-split shape → delegate to shell",
			args:          []string{"zarf", ":"},
			toComplete:    "/tm",
			wantDirective: cobra.ShellCompDirectiveDefault,
			wantEmpty:     true,
		},
		{
			name:          "none-hint scheme (single-token)",
			args:          nil,
			toComplete:    "pkg:apk/openssl@3.2.1",
			wantDirective: cobra.ShellCompDirectiveNoFileComp,
			wantEmpty:     true,
		},
		{
			name:          "none-hint scheme (bash split)",
			args:          []string{"cpe", ":"},
			toComplete:    "",
			wantDirective: cobra.ShellCompDirectiveNoFileComp,
			wantEmpty:     true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidates, directive := rootArgsCompletion(nil, tc.args, tc.toComplete)
			assert.Equal(t, tc.wantDirective, directive)
			if tc.wantEmpty {
				assert.Empty(t, candidates)
			}
		})
	}
}

func TestCompleteFilePath_bashShape_returnsDefault(t *testing.T) {
	// bash has already consumed the "zarf:" prefix via COMP_WORDBREAKS, so
	// toComplete is just the path suffix. The handler should delegate to the
	// shell's native file completion.
	candidates, directive := completeFilePath("/tm", "/tm", "zarf:")
	assert.Equal(t, cobra.ShellCompDirectiveDefault, directive)
	assert.Empty(t, candidates)
}

func TestCompleteFilePath_singleToken_globsAndPrefixes(t *testing.T) {
	// Set up a scratch directory with a known layout.
	tmp := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(tmp, "subdir"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "pkg.tar.zst"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "other.txt"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, ".hidden"), []byte("x"), 0o644))

	// zsh shape: toComplete still carries the scheme prefix.
	toComplete := "zarf:" + tmp + "/"
	pathPart := tmp + "/"
	candidates, directive := completeFilePath(toComplete, pathPart, "zarf:")

	assert.Equal(t, cobra.ShellCompDirectiveNoSpace, directive)

	got := map[string]bool{}
	for _, c := range candidates {
		got[c] = true
	}
	assert.Truef(t, got["zarf:"+tmp+"/pkg.tar.zst"], "expected pkg.tar.zst in %v", candidates)
	assert.Truef(t, got["zarf:"+tmp+"/other.txt"], "expected other.txt in %v", candidates)
	assert.Truef(t, got["zarf:"+tmp+"/subdir/"], "expected subdir/ in %v", candidates)
	// dotfile must be filtered because user didn't type a leading "."
	assert.Falsef(t, got["zarf:"+tmp+"/.hidden"], "dotfile should be hidden, got %v", candidates)
}

func TestCompleteFilePath_singleToken_prefixFilter(t *testing.T) {
	tmp := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "alpha.tar.zst"), []byte("x"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "beta.tar.zst"), []byte("x"), 0o644))

	// User has typed enough of the filename to narrow it — glob must respect that.
	toComplete := "zarf:" + tmp + "/al"
	pathPart := tmp + "/al"
	candidates, _ := completeFilePath(toComplete, pathPart, "zarf:")

	got := map[string]bool{}
	for _, c := range candidates {
		got[c] = true
	}
	assert.Truef(t, got["zarf:"+tmp+"/alpha.tar.zst"], "expected alpha.tar.zst, got %v", candidates)
	assert.Falsef(t, got["zarf:"+tmp+"/beta.tar.zst"], "beta.tar.zst should be filtered, got %v", candidates)
}

func TestRootArgsCompletion_unmatchedPositional(t *testing.T) {
	// A positional is present but doesn't match any scheme and isn't a
	// bash colon-split tail. The handler should not suggest anything.
	candidates, directive := rootArgsCompletion(nil, []string{"already-given-arg"}, "")
	assert.Empty(t, candidates)
	assert.Equal(t, cobra.ShellCompDirectiveNoFileComp, directive)
}

func TestRootArgsCompletion_firstTokenPrefixSuggestions(t *testing.T) {
	// Empty input — should return the full scheme list (plus any local
	// docker images, which we can't assert on without a daemon). At minimum
	// the well-known grype-local prefixes should be present.
	candidates, directive := rootArgsCompletion(nil, nil, "")
	assert.Equal(t, cobra.ShellCompDirectiveNoSpace, directive)

	index := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		index[c] = true
	}
	for _, want := range []string{"zarf:", "sbom:", "dir:", "file:", "purl:", "pkg:"} {
		assert.Truef(t, index[want], "expected %q in first-token suggestions, got %v", want, candidates)
	}
}

func TestRootArgsCompletion_firstTokenPrefixFilter(t *testing.T) {
	// Partial prefix — shell does the final filtering, but the handler still
	// returns all candidates that begin with toComplete (schemes + images).
	// Here we assert only the scheme filtering behavior.
	candidates, directive := rootArgsCompletion(nil, nil, "zar")
	assert.Equal(t, cobra.ShellCompDirectiveNoSpace, directive)

	// "zarf:" must be present; schemes that don't start with "zar" must not.
	index := make(map[string]bool, len(candidates))
	for _, c := range candidates {
		index[c] = true
	}
	assert.Truef(t, index["zarf:"], "expected zarf: in suggestions, got %v", candidates)
	assert.Falsef(t, index["docker:"], "docker: should not appear when prefix is zar, got %v", candidates)
	assert.Falsef(t, index["sbom:"], "sbom: should not appear when prefix is zar, got %v", candidates)
}
