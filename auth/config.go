package auth

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// Config holds all configuration options for the auth service.
type Config struct {
	// DatabaseDir is the directory where tenant SQLite databases are stored.
	// Each tenant gets a file named "{tenant_id}.db" in this directory.
	DatabaseDir string

	// TenantExtractor defines how to extract the tenant ID from requests.
	// Use the native Fiber extractors: extractors.FromHeader, extractors.FromQuery, etc.
	TenantExtractor extractors.Extractor

	// JWTSecret is the secret key used to sign JWT tokens.
	// In production, use a strong, randomly generated secret.
	JWTSecret []byte

	// JWTAccessExpiration is how long access tokens are valid.
	// Default: 15 minutes
	JWTAccessExpiration time.Duration

	// JWTRefreshExpiration is how long refresh tokens are valid.
	// Default: 7 days
	JWTRefreshExpiration time.Duration

	// APIKeyLength is the length of generated API keys (in bytes, before encoding).
	// Default: 32 (produces ~43 character base64 string)
	APIKeyLength int

	// APIKeyPrefix is prepended to generated API keys for identification.
	// Example: "sk_live_" produces keys like "sk_live_abc123..."
	// Default: "sk_"
	APIKeyPrefix string

	// BcryptCost is the cost factor for bcrypt password hashing.
	// Higher values are more secure but slower. Default: 12
	BcryptCost int

	// CookieSecure sets the Secure flag on cookies (HTTPS only).
	// Default: true (should be true in production)
	CookieSecure bool

	// CookieHTTPOnly sets the HttpOnly flag on cookies (no JS access).
	// Default: true
	CookieHTTPOnly bool

	// CookieSameSite sets the SameSite attribute on cookies.
	// Options: "Strict", "Lax", "None". Default: "Lax"
	CookieSameSite string

	// CookieDomain sets the domain for cookies.
	// Leave empty for the current domain only.
	CookieDomain string

	// AllowTenantCreation determines if new tenant databases are created automatically.
	// If false, requests for non-existent tenants will fail.
	// Default: true
	AllowTenantCreation bool

	// OAuth provider configurations
	// Each provider requires ClientID, ClientSecret, and RedirectURL to be set.
	// Leave a provider nil to disable it.

	// GoogleOAuth configures Google OAuth2 authentication.
	GoogleOAuth *OAuthProviderConfig

	// GitHubOAuth configures GitHub OAuth2 authentication.
	GitHubOAuth *OAuthProviderConfig

	// OAuthSuccessRedirect is the URL to redirect to after successful OAuth login.
	// The access token will be included as a query parameter or fragment.
	// Default: "/" (root path)
	OAuthSuccessRedirect string

	// OAuthErrorRedirect is the URL to redirect to after OAuth errors.
	// The error message will be included as a query parameter.
	// Default: "/login?error=oauth_failed"
	OAuthErrorRedirect string

	// OAuthAutoCreateUser determines if new users should be created automatically
	// when they authenticate via OAuth for the first time with an unknown email.
	// If false, OAuth login will fail for users that don't already exist.
	// Default: true
	OAuthAutoCreateUser bool

	// OAuthLinkByEmail determines if OAuth providers should be automatically
	// linked to existing users with matching email addresses.
	// Default: true
	OAuthLinkByEmail bool

	// OnAuthSuccess is called after successful authentication.
	// Use this for logging, metrics, etc.
	OnAuthSuccess func(c fiber.Ctx, authType string, userID uint)

	// OnAuthFailure is called after failed authentication attempts.
	// Use this for logging, rate limiting, etc.
	OnAuthFailure func(c fiber.Ctx, err error)

	// Logger is an optional logger for the auth service.
	// If nil, no logging is performed.
	Logger Logger
}

// Logger interface for optional logging support.
type Logger interface {
	Debug(msg string, args ...interface{})
	Info(msg string, args ...interface{})
	Warn(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// OAuthProviderConfig holds configuration for a single OAuth provider.
type OAuthProviderConfig struct {
	// ClientID is the OAuth client ID from the provider.
	ClientID string

	// ClientSecret is the OAuth client secret from the provider.
	ClientSecret string

	// RedirectURL is the callback URL registered with the provider.
	// Example: "https://yourapp.com/auth/google/callback"
	RedirectURL string

	// Scopes are the OAuth scopes to request.
	// If empty, default scopes for the provider will be used.
	Scopes []string
}

// IsConfigured returns true if the provider has required fields set.
func (c *OAuthProviderConfig) IsConfigured() bool {
	return c != nil && c.ClientID != "" && c.ClientSecret != "" && c.RedirectURL != ""
}

// ToOAuth2Config converts this config to an oauth2.Config for the specified provider.
func (c *OAuthProviderConfig) ToOAuth2Config(provider string) *oauth2.Config {
	if c == nil {
		return nil
	}

	cfg := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURL,
		Scopes:       c.Scopes,
	}

	switch provider {
	case "google":
		cfg.Endpoint = google.Endpoint
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			}
		}
	case "github":
		cfg.Endpoint = github.Endpoint
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{"user:email", "read:user"}
		}
	}

	return cfg
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		DatabaseDir:          "./data/tenants",
		TenantExtractor:      extractors.FromHeader("X-Tenant-ID"),
		JWTAccessExpiration:  15 * time.Minute,
		JWTRefreshExpiration: 7 * 24 * time.Hour,
		APIKeyLength:         32,
		APIKeyPrefix:         "sk_",
		BcryptCost:           12,
		CookieSecure:         true,
		CookieHTTPOnly:       true,
		CookieSameSite:       "Lax",
		AllowTenantCreation:  true,
		OAuthSuccessRedirect: "/",
		OAuthErrorRedirect:   "/login?error=oauth_failed",
		OAuthAutoCreateUser:  true,
		OAuthLinkByEmail:     true,
	}
}

// Validate checks the configuration for required fields and valid values.
func (c *Config) Validate() error {
	if c.DatabaseDir == "" {
		return ErrInvalidConfig{Field: "DatabaseDir", Reason: "cannot be empty"}
	}
	if c.TenantExtractor.Extract == nil {
		return ErrInvalidConfig{Field: "TenantExtractor", Reason: "cannot be nil"}
	}
	if len(c.JWTSecret) == 0 {
		return ErrInvalidConfig{Field: "JWTSecret", Reason: "cannot be empty"}
	}
	if len(c.JWTSecret) < 32 {
		return ErrInvalidConfig{Field: "JWTSecret", Reason: "should be at least 32 bytes"}
	}
	if c.JWTAccessExpiration <= 0 {
		c.JWTAccessExpiration = 15 * time.Minute
	}
	if c.JWTRefreshExpiration <= 0 {
		c.JWTRefreshExpiration = 7 * 24 * time.Hour
	}
	if c.APIKeyLength <= 0 {
		c.APIKeyLength = 32
	}
	if c.BcryptCost <= 0 {
		c.BcryptCost = 12
	}
	return nil
}
