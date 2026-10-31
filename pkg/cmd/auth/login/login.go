package login

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/v2/git"
	"github.com/cli/cli/v2/internal/authflow"
	"github.com/cli/cli/v2/internal/browser"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/gh/ghtelemetry"
	"github.com/cli/cli/v2/internal/ghinstance"
	"github.com/cli/cli/v2/pkg/cmd/auth/shared"
	"github.com/cli/cli/v2/pkg/cmd/auth/shared/gitcredentials"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	ghauth "github.com/cli/go-gh/v2/pkg/auth"
	"github.com/spf13/cobra"
)

type LoginOptions struct {
	IO              *iostreams.IOStreams
	Config          func() (gh.Config, error)
	HttpClient      func() (*http.Client, error)
	PlainHttpClient func() (*http.Client, error)
	GitClient       *git.Client
	Prompter        shared.Prompt
	Browser         browser.Browser
	Telemetry       ghtelemetry.InvocationRecorder

	MainExecutable string

	Interactive bool

	Hostname         string
	Scopes           []string
	Token            string
	Web              bool
	GitProtocol      string
	InsecureStorage  bool
	SkipSSHKeyPrompt bool
	Expiring         *bool
	Clipboard        *bool
	AppID            int64
	InstallationID   int64
	PrivateKeyFile   string

	// AuthFlow is indirected so tests can stub the interactive authorization. When nil, the shared login flow uses
	// the real authflow.AuthFlow.
	AuthFlow func(*http.Client, string, *iostreams.IOStreams, string, []string, bool, browser.Browser, bool, bool) (*authflow.AuthResult, error)

	// helperConfig overrides git credential helper inspection and configuration. It is nil in production, where
	// runLogin builds the real HelperConfig from GitClient; tests set a fake to avoid shelling out to git.
	helperConfig shared.HelperConfig
}

func NewCmdLogin(f *cmdutil.Factory, telemetry ghtelemetry.InvocationRecorder, runF func(*LoginOptions) error) *cobra.Command {
	opts := &LoginOptions{
		IO:              f.IOStreams,
		Config:          f.Config,
		HttpClient:      f.HttpClient,
		PlainHttpClient: f.PlainHttpClient,
		GitClient:       f.GitClient,
		Prompter:        f.Prompter,
		Browser:         f.Browser,
		Telemetry:       telemetry,
	}

	var tokenStdin bool

	cmd := &cobra.Command{
		Use:   "login",
		Args:  cobra.ExactArgs(0),
		Short: "Log in to a GitHub account",
		Long: heredoc.Docf(`
			Authenticate with a GitHub host.

			The default hostname is %[1]sgithub.com%[1]s. This can be overridden using the %[1]s--hostname%[1]s
			flag.

			The default authentication mode is a web-based browser flow. After completion, an
			authentication token will be stored securely in the system credential store.
			If a credential store is not found or there is an issue using it gh will fallback
			to writing the token to a plain text file. See %[1]sgh auth status%[1]s for its
			stored location.

			Alternatively, use %[1]s--with-token%[1]s to pass in a personal access token (classic) on standard input.
			The minimum required scopes for the token are: %[1]srepo%[1]s, %[1]sread:org%[1]s, and %[1]sgist%[1]s.
			Take care when passing a fine-grained personal access token to %[1]s--with-token%[1]s
			as the inherent scoping to certain resources may cause confusing behaviour when interacting with other
			resources. Favour setting %[1]sGH_TOKEN%[1]s for fine-grained personal access token usage.

			Alternatively, gh will use the authentication token found in environment variables.
			This method is most suitable for "headless" use of gh such as in automation. See
			%[1]sgh help environment%[1]s for more info.

			To use gh in GitHub Actions, add %[1]sGH_TOKEN: ${{ github.token }}%[1]s to %[1]senv%[1]s.

			Alternatively, use %[1]s--app-id%[1]s, %[1]s--installation-id%[1]s, and %[1]s--private-key-file%[1]s together
			to authenticate as an installation of a GitHub App. Only the path of the private key is stored,
			so the file must stay in place for gh to renew the installation token, which expires after one
			hour. The app's %[1]sNAME[bot]%[1]s account becomes the active account on the host; use
			%[1]sgh auth switch%[1]s to go back to another account.

			The git protocol to use for git operations on this host can be set with %[1]s--git-protocol%[1]s,
			or during the interactive prompting. Although login is for a single account on a host, setting
			the git protocol will take effect for all users on the host.

			Specifying %[1]sssh%[1]s for the git protocol will detect existing SSH keys to upload,
			prompting to create and upload a new key if one is not found. This can be skipped with
			%[1]s--skip-ssh-key%[1]s flag.

			Use %[1]s--expiring%[1]s to prefer expiring credentials that gh refreshes automatically.
			This is a preference, not a guarantee: whether expiring tokens are issued depends on the
			host and the OAuth app configuration. A host without support issues a non-expiring token
			instead, and a host configured for them may issue expiring tokens even without the flag.
			Enable the %[1]sexpiring_credentials%[1]s configuration to prefer expiring credentials
			without passing %[1]s--expiring%[1]s every time, and pass %[1]s--expiring=false%[1]s to request a
			non-expiring token even when that configuration is enabled.
			When using expiring credentials for git operations, git 2.46 or newer is recommended so
			gh can mark the token as non-cacheable; with older git a credential caching helper may store
			and reuse an expired token.

			For more information on OAuth scopes, see
			<https://docs.github.com/en/developers/apps/building-oauth-apps/scopes-for-oauth-apps/>.
		`, "`"),
		Example: heredoc.Doc(`
			# Start interactive setup
			$ gh auth login

			# Open a browser to authenticate and copy one-time OAuth code to clipboard
			$ gh auth login --web --clipboard

			# Authenticate against github.com by reading the token from a file
			$ gh auth login --with-token < mytoken.txt

			# Authenticate with specific host
			$ gh auth login --hostname enterprise.internal

			# Authenticate as an installation of a GitHub App
			$ gh auth login --app-id 123 --installation-id 456 --private-key-file app.pem
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.Telemetry != nil {
				opts.Telemetry.SetSampleRate(ghtelemetry.SAMPLE_ALL)
			}

			if tokenStdin && opts.Web {
				return cmdutil.FlagErrorf("specify only one of `--web` or `--with-token`")
			}
			if tokenStdin && len(opts.Scopes) > 0 {
				return cmdutil.FlagErrorf("specify only one of `--scopes` or `--with-token`")
			}
			if tokenStdin && opts.Expiring != nil && *opts.Expiring {
				return cmdutil.FlagErrorf("specify only one of `--expiring` or `--with-token`")
			}
			if cmd.Flags().Changed("app-id") && (opts.AppID <= 0 || opts.InstallationID <= 0) {
				return cmdutil.FlagErrorf("`--app-id` and `--installation-id` must be positive numbers")
			}
			if opts.AppID != 0 && (tokenStdin || opts.Web || len(opts.Scopes) > 0 || opts.Expiring != nil) {
				return cmdutil.FlagErrorf("`--app-id` cannot be combined with `--with-token`, `--web`, `--scopes`, or `--expiring`")
			}

			if tokenStdin {
				defer opts.IO.In.Close()
				token, err := io.ReadAll(opts.IO.In)
				if err != nil {
					return fmt.Errorf("failed to read token from standard input: %w", err)
				}
				opts.Token = strings.TrimSpace(string(token))
			}

			if opts.IO.CanPrompt() && opts.Token == "" && opts.AppID == 0 {
				opts.Interactive = true
			}

			if cmd.Flags().Changed("hostname") {
				if err := ghinstance.HostnameValidator(opts.Hostname); err != nil {
					return cmdutil.FlagErrorf("error parsing hostname: %w", err)
				}
			}

			if opts.Hostname == "" && (!opts.Interactive || opts.Web) {
				opts.Hostname, _ = ghauth.DefaultHost()
			}

			opts.MainExecutable = f.ExecutablePath
			if runF != nil {
				return runF(opts)
			}

			return loginRun(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "", "The hostname of the GitHub instance to authenticate with")
	cmd.Flags().StringSliceVarP(&opts.Scopes, "scopes", "s", nil, "Additional authentication scopes to request")
	cmd.Flags().BoolVar(&tokenStdin, "with-token", false, "Read token from standard input")
	cmd.Flags().BoolVarP(&opts.Web, "web", "w", false, "Open a browser to authenticate")
	cmdutil.NilBoolFlag(cmd, &opts.Clipboard, "clipboard", "c", "Copy one-time OAuth device code to clipboard")
	cmdutil.StringEnumFlag(cmd, &opts.GitProtocol, "git-protocol", "p", "", []string{"ssh", "https"}, "The protocol to use for git operations on this host")

	// secure storage became the default on 2023/4/04; this flag is left as a no-op for backwards compatibility
	var secureStorage bool
	cmd.Flags().BoolVar(&secureStorage, "secure-storage", false, "Save authentication credentials in secure credential store")
	_ = cmd.Flags().MarkHidden("secure-storage")

	cmd.Flags().BoolVar(&opts.InsecureStorage, "insecure-storage", false, "Save authentication credentials in plain text instead of credential store")
	cmd.Flags().BoolVar(&opts.SkipSSHKeyPrompt, "skip-ssh-key", false, "Skip generate/upload SSH key prompt")
	cmdutil.NilBoolFlag(cmd, &opts.Expiring, "expiring", "", "Prefer expiring credentials that gh refreshes automatically, if the host supports them")
	cmd.Flags().Int64Var(&opts.AppID, "app-id", 0, "The ID of the GitHub App to authenticate as")
	cmd.Flags().Int64Var(&opts.InstallationID, "installation-id", 0, "The ID of the GitHub App installation to authenticate as")
	cmd.Flags().StringVar(&opts.PrivateKeyFile, "private-key-file", "", "The path to the private key of the GitHub App")
	cmd.MarkFlagsRequiredTogether("app-id", "installation-id", "private-key-file")

	return cmd
}

func loginRun(opts *LoginOptions) error {
	cfg, err := opts.Config()
	if err != nil {
		return err
	}
	authCfg := cfg.Authentication()
	copyToClipboard := shared.ShouldCopyToClipboard(cfg, opts.Clipboard)

	hostname := opts.Hostname
	if opts.Interactive && hostname == "" {
		var err error
		hostname, err = promptForHostname(opts)
		if err != nil {
			return err
		}
	}

	// The go-gh Config object currently does not support case-insensitive lookups for host names,
	// so normalize the host name case here before performing any lookups with it or persisting it.
	// https://github.com/cli/go-gh/pull/105
	hostname = strings.ToLower(hostname)

	if src, writeable := shared.AuthTokenWriteable(authCfg, hostname); !writeable {
		fmt.Fprintf(opts.IO.ErrOut, "The value of the %s environment variable is being used for authentication.\n", src)
		fmt.Fprint(opts.IO.ErrOut, "To have GitHub CLI store credentials instead, first clear the value from the environment.\n")
		return cmdutil.SilentError
	}

	plainHTTPClient, err := opts.PlainHttpClient()
	if err != nil {
		return err
	}

	httpClient, err := opts.HttpClient()
	if err != nil {
		return err
	}

	if opts.Token != "" {
		if err := shared.HasMinimumScopes(httpClient, hostname, opts.Token); err != nil {
			return fmt.Errorf("error validating token: %w", err)
		}
		username, err := shared.GetCurrentLogin(httpClient, hostname, opts.Token)
		if err != nil {
			return fmt.Errorf("error retrieving current user: %w", err)
		}

		// Adding a user key ensures that a nonempty host section gets written to the config file.
		_, loginErr := authCfg.Login(hostname, username, opts.Token, opts.GitProtocol, !opts.InsecureStorage)
		return loginErr
	}

	if opts.AppID != 0 {
		username, credential, err := authflow.LoginWithApp(plainHTTPClient, hostname, opts.AppID, opts.InstallationID, opts.PrivateKeyFile)
		if err != nil {
			return fmt.Errorf("error authenticating as GitHub App: %w", err)
		}
		insecureStorageUsed, err := authCfg.LoginRefreshable(hostname, username, credential, opts.GitProtocol, !opts.InsecureStorage)
		if err != nil {
			return err
		}
		cs := opts.IO.ColorScheme()
		if insecureStorageUsed {
			fmt.Fprintf(opts.IO.ErrOut, "%s Authentication credentials saved in plain text\n", cs.Yellow("!"))
		}
		fmt.Fprintf(opts.IO.ErrOut, "%s Logged in as %s\n", cs.SuccessIcon(), cs.Bold(username))
		return nil
	}

	// Nudge users towards expiring tokens unless they have already expressed a preference, either with the flag or
	// the config. Enterprise Server hosts are skipped because they may not support expiring tokens.
	if opts.IO.IsStderrTTY() && opts.Expiring == nil && !ghauth.IsEnterprise(hostname) && !shared.ShouldUseExpiring(cfg, nil, hostname) {
		cs := opts.IO.ColorScheme()
		fmt.Fprintf(opts.IO.ErrOut, "%s Did you know that expiring tokens can be requested with %s? Read more at %s\n",
			cs.WarningIcon(), cs.Bold("--expiring"), "https://gh.io/gh-expiring-tokens")
	}

	helperConfig := opts.helperConfig
	if helperConfig == nil {
		helperConfig = &gitcredentials.HelperConfig{
			SelfExecutablePath: opts.MainExecutable,
			GitClient:          opts.GitClient,
		}
	}

	return shared.Login(&shared.LoginOptions{
		IO:              opts.IO,
		Config:          authCfg,
		HTTPClient:      httpClient,
		PlainHTTPClient: plainHTTPClient,
		Hostname:        hostname,
		Interactive:     opts.Interactive,
		Web:             opts.Web,
		Scopes:          opts.Scopes,
		GitProtocol:     opts.GitProtocol,
		Prompter:        opts.Prompter,
		Browser:         opts.Browser,
		CredentialFlow: &shared.GitCredentialFlow{
			Prompter:     opts.Prompter,
			IO:           opts.IO,
			HelperConfig: helperConfig,
			Updater: &gitcredentials.Updater{
				GitClient: opts.GitClient,
			},
		},
		SecureStorage:               !opts.InsecureStorage,
		SkipSSHKeyPrompt:            opts.SkipSSHKeyPrompt,
		CopyToClipboard:             copyToClipboard,
		Expiring:                    shared.ShouldUseExpiring(cfg, opts.Expiring, hostname),
		ExpiringExplicitlyRequested: opts.Expiring != nil && *opts.Expiring,
		Telemetry:                   opts.Telemetry,
		AuthFlow:                    opts.AuthFlow,
	})
}

func promptForHostname(opts *LoginOptions) (string, error) {
	options := []string{"GitHub.com", "Other"}
	hostType, err := opts.Prompter.Select(
		"Where do you use GitHub?",
		options[0],
		options)
	if err != nil {
		return "", err
	}

	isGitHubDotCom := hostType == 0
	if isGitHubDotCom {
		return ghinstance.Default(), nil
	}

	return opts.Prompter.InputHostname()
}
