package authflow

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/pkg/httpmock"
	oauthapi "github.com/cli/oauth/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeAppKey generates a throwaway RSA key and writes it in the PKCS#1 PEM format GitHub issues. The directory name
// contains a colon to prove key paths survive the colon-separated refresh token.
func writeAppKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	dir := filepath.Join(t.TempDir(), "with:colon")
	require.NoError(t, os.Mkdir(dir, 0o700))
	path := filepath.Join(dir, "app.pem")
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	require.NoError(t, os.WriteFile(path, keyPEM, 0o600))
	return key, path
}

func TestAppJWT(t *testing.T) {
	key, path := writeAppKey(t)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	jwt, err := appJWT("123", path, now)
	require.NoError(t, err)

	parts := strings.Split(jwt, ".")
	require.Len(t, parts, 3)

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	assert.JSONEq(t, `{"alg":"RS256","typ":"JWT"}`, string(header))

	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var got struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	require.NoError(t, json.Unmarshal(claims, &got))
	assert.Equal(t, "123", got.Iss)
	assert.Equal(t, now.Add(-time.Minute).Unix(), got.Iat)
	assert.Equal(t, now.Add(9*time.Minute).Unix(), got.Exp)

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	assert.NoError(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signature))
}

func TestAppJWTInvalidKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	tests := []struct {
		name     string
		contents []byte
		wantErr  string
	}{
		{name: "missing file", wantErr: "failed to read GitHub App private key"},
		{name: "not PEM", contents: []byte("not a key"), wantErr: "no PEM data found"},
		{
			name:     "PKCS#8",
			contents: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}),
			wantErr:  "failed to parse GitHub App private key",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "app.pem")
			if tt.contents != nil {
				require.NoError(t, os.WriteFile(path, tt.contents, 0o600))
			}
			_, err := appJWT("123", path, time.Now())
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestLoginWithApp(t *testing.T) {
	tests := []struct {
		name       string
		hostname   string
		pathPrefix string
	}{
		{name: "github.com", hostname: "github.com"},
		{name: "enterprise host", hostname: "ghe.example.com", pathPrefix: "api/v3/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixedNow := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
			timeNow = func() time.Time { return fixedNow }
			t.Cleanup(func() { timeNow = time.Now })

			_, path := writeAppKey(t)
			reg := &httpmock.Registry{}
			defer reg.Verify(t)
			reg.Register(
				httpmock.WithHost(httpmock.REST("GET", tt.pathPrefix+"app"), restHost(tt.hostname)),
				httpmock.JSONResponse(map[string]any{"slug": "myapp"}))
			reg.Register(
				httpmock.WithHost(httpmock.REST("POST", tt.pathPrefix+"app/installations/456/access_tokens"), restHost(tt.hostname)),
				httpmock.JSONResponse(map[string]any{"token": "ghs_NEW", "expires_at": "2026-01-02T04:04:05Z"}))

			username, credential, err := LoginWithApp(&http.Client{Transport: reg}, tt.hostname, 123, 456, path)
			require.NoError(t, err)

			assert.Equal(t, "myapp[bot]", username)
			assert.Equal(t, "ghs_NEW", credential.Token)
			assert.Equal(t, "ghapp:123:456:"+path, credential.RefreshToken)
			assert.Equal(t, 3600, credential.ExpiresIn)
			require.NotNil(t, credential.ExpiresAt)
			assert.Equal(t, fixedNow.Add(time.Hour), *credential.ExpiresAt)
			assert.Nil(t, credential.RefreshTokenExpiresAt)

			require.Len(t, reg.Requests, 2)
			for _, req := range reg.Requests {
				assert.Truef(t, strings.HasPrefix(req.Header.Get("Authorization"), "Bearer "), "request %s", req.URL)
			}
		})
	}
}

func restHost(hostname string) string {
	if hostname == "github.com" {
		return "api.github.com"
	}
	return hostname
}

func TestLoginWithAppRelativeKeyPath(t *testing.T) {
	_, path := writeAppKey(t)
	t.Chdir(filepath.Dir(path))
	absolute, err := filepath.Abs("app.pem")
	require.NoError(t, err)

	reg := &httpmock.Registry{}
	defer reg.Verify(t)
	reg.Register(httpmock.REST("GET", "app"), httpmock.JSONResponse(map[string]any{"slug": "myapp"}))
	reg.Register(
		httpmock.REST("POST", "app/installations/456/access_tokens"),
		httpmock.JSONResponse(map[string]any{"token": "ghs_NEW", "expires_at": "2099-01-01T00:00:00Z"}))

	_, credential, err := LoginWithApp(&http.Client{Transport: reg}, "github.com", 123, 456, "app.pem")
	require.NoError(t, err)
	assert.Equal(t, "ghapp:123:456:"+absolute, credential.RefreshToken)
}

func TestLoginWithAppHTTPError(t *testing.T) {
	_, path := writeAppKey(t)
	reg := &httpmock.Registry{}
	defer reg.Verify(t)
	reg.Register(httpmock.REST("GET", "app"), httpmock.StatusStringResponse(http.StatusUnauthorized, `{"message":"bad JWT"}`))

	_, _, err := LoginWithApp(&http.Client{Transport: reg}, "github.com", 123, 456, path)
	assert.ErrorContains(t, err, "401")
}

func TestTokenRefresherRefreshApp(t *testing.T) {
	fixedNow := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	timeNow = func() time.Time { return fixedNow }
	t.Cleanup(func() { timeNow = time.Now })

	_, path := writeAppKey(t)
	reg := &httpmock.Registry{}
	defer reg.Verify(t)
	reg.Register(
		httpmock.REST("POST", "app/installations/456/access_tokens"),
		httpmock.JSONResponse(map[string]any{"token": "ghs_NEW", "expires_at": "2026-01-02T04:04:05Z"}))

	refreshToken := "ghapp:123:456:" + path
	credential, err := NewTokenRefresher(&http.Client{Transport: reg}).Refresh(refreshToken, "github.com")
	require.NoError(t, err)

	assert.Equal(t, "ghs_NEW", credential.AccessToken)
	// The credential store rejects a renewal without a refresh token, so the app credentials must be carried forward.
	assert.Equal(t, refreshToken, credential.RefreshToken)
	require.NotNil(t, credential.ExpiresAt)
	assert.Equal(t, fixedNow.Add(time.Hour), *credential.ExpiresAt)
}

// A rejected refresh token deletes the stored credential, so no app failure may be reported as one.
func TestTokenRefresherRefreshAppFailures(t *testing.T) {
	_, path := writeAppKey(t)
	tests := []struct {
		name         string
		refreshToken string
		stubs        func(*httpmock.Registry)
	}{
		{name: "malformed", refreshToken: "ghapp:123"},
		{name: "missing key", refreshToken: "ghapp:123:456:" + path + ".missing"},
		{
			name:         "rejected by the server",
			refreshToken: "ghapp:123:456:" + path,
			stubs: func(reg *httpmock.Registry) {
				reg.Register(
					httpmock.REST("POST", "app/installations/456/access_tokens"),
					httpmock.StatusStringResponse(http.StatusUnauthorized, `{"message":"bad JWT"}`))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := &httpmock.Registry{}
			defer reg.Verify(t)
			if tt.stubs != nil {
				tt.stubs(reg)
			}
			_, err := NewTokenRefresher(&http.Client{Transport: reg}).Refresh(tt.refreshToken, "github.com")
			require.Error(t, err)
			assert.NotErrorIs(t, err, gh.ErrRefreshTokenInvalid)
		})
	}
}

// A server issuing an app-shaped refresh token would otherwise receive a JWT signed with a local key on the next renewal.
func TestOAuthServerCannotIssueAppCredentials(t *testing.T) {
	malicious := "ghapp:123:456:/path/to/app.pem"

	t.Run("refresh", func(t *testing.T) {
		stub := &stubRoundTripper{
			body: "access_token=gho_NEW&refresh_token=" + url.QueryEscape(malicious) + "&token_type=bearer&expires_in=28800",
		}
		_, err := NewTokenRefresher(&http.Client{Transport: stub}).Refresh("ghr_OLD", "github.com")
		assert.ErrorContains(t, err, "invalid refresh token")
	})

	t.Run("login", func(t *testing.T) {
		token := &oauthapi.AccessToken{Token: "gho_NEW", RefreshToken: malicious}
		result := authResultFromToken(token, "monalisa", time.Now())
		assert.Equal(t, "gho_NEW", result.Token)
		assert.Nil(t, result.Refreshable)
	})
}
