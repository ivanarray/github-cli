package authflow

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cli/cli/v2/api"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/safeurl"
	oauthapi "github.com/cli/oauth/api"
)

// appRefreshTokenPrefix marks a stored refresh token as GitHub App credentials rather than an OAuth refresh token. The
// full form is ghapp:<app ID>:<installation ID>:<absolute private key path>. Reusing the refresh token slot lets
// installation tokens, which live for an hour and have no refresh token of their own, flow through the existing
// refreshable credential storage, locking and renewal. Only the key's path is stored, never the key itself.
const appRefreshTokenPrefix = "ghapp:"

// IsAppCredential reports whether refreshToken holds GitHub App credentials rather than an OAuth refresh token.
func IsAppCredential(refreshToken string) bool {
	return strings.HasPrefix(refreshToken, appRefreshTokenPrefix)
}

// LoginWithApp authenticates as an installation of a GitHub App. It returns the app's bot login and a refreshable
// credential holding a new installation access token. The provided HTTP client should be a plain client that sets no
// auth headers.
func LoginWithApp(httpClient *http.Client, hostname string, appID, installationID int64, keyPath string) (string, gh.Credential, error) {
	keyPath, err := filepath.Abs(keyPath)
	if err != nil {
		return "", gh.Credential{}, err
	}

	jwt, err := appJWT(strconv.FormatInt(appID, 10), keyPath, timeNow())
	if err != nil {
		return "", gh.Credential{}, err
	}
	var app struct {
		Slug string `json:"slug"`
	}
	if err := appRequest(httpClient, hostname, jwt, http.MethodGet, "app", &app); err != nil {
		return "", gh.Credential{}, err
	}

	requestedAt := timeNow().UTC()
	refreshToken := fmt.Sprintf("%s%d:%d:%s", appRefreshTokenPrefix, appID, installationID, keyPath)
	token, err := mintInstallationToken(httpClient, hostname, refreshToken, requestedAt)
	if err != nil {
		return "", gh.Credential{}, err
	}
	return app.Slug + "[bot]", credentialFromAccessToken(token, requestedAt), nil
}

// mintInstallationToken requests a new installation access token using the app credentials encoded in refreshToken.
// The returned token keeps refreshToken, because the app credentials stay valid across renewals.
func mintInstallationToken(httpClient *http.Client, hostname, refreshToken string, requestedAt time.Time) (*oauthapi.AccessToken, error) {
	parts := strings.SplitN(strings.TrimPrefix(refreshToken, appRefreshTokenPrefix), ":", 3)
	if len(parts) != 3 {
		return nil, errors.New("malformed GitHub App credentials")
	}
	appID, installationID, keyPath := parts[0], parts[1], parts[2]

	jwt, err := appJWT(appID, keyPath, requestedAt)
	if err != nil {
		return nil, err
	}
	path, err := safeurl.JoinPath("app", "installations", installationID, "access_tokens")
	if err != nil {
		return nil, err
	}
	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := appRequest(httpClient, hostname, jwt, http.MethodPost, path.String(), &result); err != nil {
		return nil, err
	}
	return &oauthapi.AccessToken{
		Token:        result.Token,
		RefreshToken: refreshToken,
		ExpiresIn:    result.ExpiresAt.Sub(requestedAt),
	}, nil
}

// appRequest performs a REST request authenticated as the app itself and decodes the JSON response into data. The
// transport only sets Authorization when it is absent, so the header set here wins.
func appRequest(httpClient *http.Client, hostname, jwt, method, path string, data any) error {
	res, err := api.NewClientFromHTTP(httpClient).Request(hostname, method, path, nil,
		api.WithHeader("Authorization", "Bearer "+jwt))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	return json.NewDecoder(res.Body).Decode(data)
}

// appJWT builds the short-lived RS256 JSON Web Token that authenticates as a GitHub App, signed with the PKCS#1 key
// GitHub issues. GitHub rejects a lifetime over 10 minutes, and iat is backdated to tolerate clock drift.
func appJWT(appID, keyPath string, now time.Time) (string, error) {
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return "", fmt.Errorf("failed to read GitHub App private key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return "", fmt.Errorf("failed to parse GitHub App private key %s: no PEM data found", keyPath)
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse GitHub App private key %s: %w", keyPath, err)
	}

	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	if err != nil {
		return "", err
	}
	encoding := base64.RawURLEncoding
	unsigned := encoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + encoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign GitHub App token: %w", err)
	}
	return unsigned + "." + encoding.EncodeToString(signature), nil
}
