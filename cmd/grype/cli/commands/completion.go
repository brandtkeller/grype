package commands

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/spf13/cobra"

	"github.com/anchore/clio"
	"github.com/anchore/grype/grype/pkg"
)

// Completion returns a command to provide completion to various terminal shells
func Completion(app clio.Application) *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish]",
		Short: "Generate a shell completion script for Grype",
		Long: `Generate a shell completion script for grype. The script provides
scheme-aware completion for grype's positional input argument: it suggests
scheme prefixes (docker:, dir:, sbom:, zarf:, …), completes local docker
images when no scheme is typed or after docker:/podman:/containerd:, and
falls through to native filesystem completion after file-based schemes.

Bash:

$ source <(grype completion bash)

# To load completions for each session, execute once:
Linux:
  $ grype completion bash > /etc/bash_completion.d/grype
MacOS:
  $ grype completion bash > /usr/local/etc/bash_completion.d/grype

Zsh:

# If shell completion is not already enabled in your environment you will need
# to enable it.  You can execute the following once:

$ echo "autoload -U compinit; compinit" >> ~/.zshrc

# To load completions for each session, execute once:
$ grype completion zsh > "${fpath[1]}/_grype"

# You will need to start a new shell for this setup to take effect.

Fish:

$ grype completion fish | source

# To load completions for each session, execute once:
$ grype completion fish > ~/.config/fish/completions/grype.fish
`,
		DisableFlagsInUseLine: true,
		ValidArgs:             []string{"bash", "fish", "zsh"},
		PreRunE:               disableUI(app),
		Args:                  cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			switch args[0] {
			case "zsh":
				err = cmd.Root().GenZshCompletion(os.Stdout)
			case "bash":
				err = cmd.Root().GenBashCompletion(os.Stdout)
			case "fish":
				err = cmd.Root().GenFishCompletion(os.Stdout, true)
			}
			return err
		},
	}
}

// rootArgsCompletion is the ValidArgsFunction for the root grype command.
// It dispatches completion based on the scheme prefix (if any) the user has
// committed to. The handler must normalize across shell tokenization
// differences: bash word-splits on ':' by default (so "zarf:/tmp" arrives as
// args=["zarf", ":"] toComplete="/tmp"), while zsh and fish preserve the
// colon as part of the word.
func rootArgsCompletion(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	schemes := pkg.Schemes()

	if scheme, rest, matched := detectScheme(args, toComplete, schemes); matched {
		switch scheme.Hint {
		case pkg.CompletionHintLocalImage:
			return completeLocalDockerImages(rest)
		case pkg.CompletionHintFilePath:
			return completeFilePath(toComplete, rest, scheme.Prefix)
		default:
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
	}

	// If a full positional is already present and it doesn't match any
	// known scheme, there's nothing left to suggest.
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	return rootFirstTokenSuggestions(toComplete, schemes), cobra.ShellCompDirectiveNoSpace
}

// detectScheme identifies whether the user has committed to a known scheme
// prefix and returns the scheme + the suffix after the prefix.
//
// Case A (bash colon-split): args ends with "<name>", ":"
// Case B (zsh/fish single-token): toComplete begins with "<name>:"
func detectScheme(args []string, toComplete string, schemes []pkg.Scheme) (pkg.Scheme, string, bool) {
	if len(args) >= 2 && args[len(args)-1] == ":" {
		candidate := args[len(args)-2] + ":"
		for _, s := range schemes {
			if s.Prefix == candidate {
				return s, toComplete, true
			}
		}
	}
	for _, s := range schemes {
		if rest, ok := strings.CutPrefix(toComplete, s.Prefix); ok {
			return s, rest, true
		}
	}
	return pkg.Scheme{}, toComplete, false
}

// completeFilePath produces file-path completions for a scheme like dir:,
// zarf:, sbom:. It handles both shell tokenization shapes:
//
//   - bash word-splits on ':', so by the time the handler runs, the scheme
//     prefix has already been consumed; the path portion is what bash thinks
//     it's completing. We return ShellCompDirectiveDefault so bash does its
//     own native file completion on that path.
//
//   - zsh and fish keep the whole "scheme:path" as one word. Their native
//     file completers would try to match files literally starting with
//     "scheme:" and find nothing, so we must glob the directory ourselves
//     and return candidates with the scheme prefix re-attached.
func completeFilePath(toComplete, pathPart, schemePrefix string) ([]string, cobra.ShellCompDirective) {
	if !strings.HasPrefix(toComplete, schemePrefix) {
		return nil, cobra.ShellCompDirectiveDefault
	}
	return globFilesWithPrefix(pathPart, schemePrefix), cobra.ShellCompDirectiveNoSpace
}

// globFilesWithPrefix lists filesystem entries matching pathPart (treated as
// a path prefix, not a glob pattern) and returns each as "<schemePrefix><path>",
// with a trailing "/" on directories so repeated Tabs can descend.
func globFilesWithPrefix(pathPart, schemePrefix string) []string {
	dir, base := filepath.Split(pathPart)
	listDir := dir
	if listDir == "" {
		listDir = "."
	}
	entries, err := os.ReadDir(listDir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, base) {
			continue
		}
		// hide dotfiles unless the user has asked for them
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".") {
			continue
		}
		full := dir + name
		// Stat (not Lstat) so symlinks to directories like /tmp on macOS
		// get a trailing "/" for continued Tab descent.
		if info, err := os.Stat(full); err == nil && info.IsDir() {
			full += "/"
		}
		out = append(out, schemePrefix+full)
	}
	return out
}

// rootFirstTokenSuggestions returns scheme prefixes that begin with toComplete,
// merged with any local docker images that match the same prefix. Used when
// the user hasn't yet committed to a scheme — preserves the pre-existing
// "grype <image>" tab-completion UX as a fallback.
func rootFirstTokenSuggestions(toComplete string, schemes []pkg.Scheme) []string {
	out := make([]string, 0, len(schemes))
	for _, s := range schemes {
		if strings.HasPrefix(s.Prefix, toComplete) {
			out = append(out, s.Prefix)
		}
	}
	if images, err := listLocalDockerImages(toComplete); err == nil {
		out = append(out, images...)
	}
	return out
}

// completeLocalDockerImages returns candidates for the argument that follows
// a local-image scheme prefix (docker:, podman:, containerd:). The returned
// candidates intentionally do NOT include the scheme prefix — bash has
// already consumed it as a word-break, so the shell will insert only what
// we return at the cursor position.
func completeLocalDockerImages(prefix string) ([]string, cobra.ShellCompDirective) {
	images, err := listLocalDockerImages(prefix)
	if err != nil || len(images) == 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return images, cobra.ShellCompDirectiveNoFileComp
}

func listLocalDockerImages(prefix string) ([]string, error) {
	var repoTags = make([]string, 0)
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return repoTags, err
	}

	// Only want to return tagged images
	imageListArgs := filters.NewArgs()
	imageListArgs.Add("dangling", "false")
	images, err := cli.ImageList(ctx, image.ListOptions{All: false, Filters: imageListArgs})
	if err != nil {
		return repoTags, err
	}

	for _, image := range images {
		// image may have multiple tags
		for _, tag := range image.RepoTags {
			if strings.HasPrefix(tag, prefix) {
				repoTags = append(repoTags, tag)
			}
		}
	}
	return repoTags, nil
}
