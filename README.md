# GitHub CLI with GitHub App login

This is a personal fork of [GitHub CLI](https://github.com/cli/cli) (`gh`). It adds one feature: `gh` can log in as a GitHub App installation and keep working as that app, with the token renewed automatically.

Everything else is the upstream `gh`. For general usage see the [original repository](https://github.com/cli/cli) and the [manual](https://cli.github.com/manual/).

## What this fork adds

Upstream `gh` accepts an installation token (`ghs_...`) through `GH_TOKEN`, but such a token lives one hour and `gh` cannot create or renew it. This fork adds:

- `gh auth login --app-id <id> --installation-id <id> --private-key-file <path>`: creates an installation token from the app's private key and saves the account as `<app-slug>[bot]`.
- Automatic renewal: when the token is about to expire, `gh` creates a new one, both for API calls and for git through `gh auth git-credential`.
- `gh auth status` shows the app account and reports when renewal fails.
- `gh auth refresh` refuses app accounts, because the browser flow does not apply to them.

## Usage

```shell
gh auth login --app-id 123456 --installation-id 7890123 --private-key-file ~/keys/my-app.private-key.pem
gh auth setup-git   # optional: let git use the app token for HTTPS remotes
gh auth status
```

`--hostname`, `--git-protocol` and `--insecure-storage` work as with the regular login.

- **App ID** identifies the app itself. It is shown on the app's settings page.
- **Installation ID** identifies one installation of the app on an account or organization. It is the number at the end of the installation settings URL, for example `https://github.com/settings/installations/7890123` or `https://github.com/organizations/ORG/settings/installations/7890123`. The token only reaches the repositories and permissions of that installation.
- **Private key** is the `.pem` file generated on the app's settings page, in the PKCS#1 format GitHub issues.

The app account becomes the active account on the host. Use `gh auth switch` to go back to your user.

## How it works

- Only the absolute path to the private key is stored, never the key. If you move or delete the key, renewal stops until you log in again.
- A failed renewal (missing key, network error, rejected key) does not log you out. `gh` prints a warning and tries again on the next call.
- For git, the token is sent with the username `x-access-token`. Remotes with no username, `x-access-token` or the bot name work. Remotes naming another user are refused.

## Known limitations

- Commands that need a user (`/user`, `@me`) may not work with an installation token.
- What the app can do is set by its permissions and the repositories selected for the installation.
- One app account per host keeps one installation. Logging in with another installation of the same app replaces it.

<!-- this anchor is linked to from elsewhere, so avoid renaming it -->
## Installation

Build from source with the Go version declared in [go.mod](go.mod):

```shell
make install prefix=$HOME/.local
gh --version
```

Make sure `$HOME/.local/bin` comes before any other `gh` in your `PATH`. See [building from source](docs/install_source.md) for details.

## Upstream

Original project: https://github.com/cli/cli. Releases, packages and support come from there; this fork has no releases of its own.
