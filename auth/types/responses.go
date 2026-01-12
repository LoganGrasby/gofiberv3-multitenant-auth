package types

import "time"

// =============================================================================
// Authentication Responses
// =============================================================================

// UserResponse represents a user in API responses.
type UserResponse struct {
	ID          uint       `json:"id"`
	Email       string     `json:"email"`
	Name        string     `json:"name"`
	Role        string     `json:"role,omitempty"`
	CreatedAt   time.Time  `json:"created_at,omitempty"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// TokenResponse represents token data in API responses.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    int64  `json:"expires_at"`
}

// LoginResponse represents the response for successful login.
type LoginResponse struct {
	TokenResponse
	User UserResponse `json:"user"`
}

// =============================================================================
// API Key Responses
// =============================================================================

// APIKeyResponse represents an API key in list responses.
type APIKeyResponse struct {
	ID          uint       `json:"id"`
	Name        string     `json:"name"`
	KeyPrefix   string     `json:"key_prefix"`
	Scopes      []string   `json:"scopes,omitempty"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	UsageCount  int        `json:"usage_count"`
	Revoked     bool       `json:"revoked"`
	CreatedAt   time.Time  `json:"created_at"`
}

// CreateAPIKeyResponse represents the response when creating an API key.
type CreateAPIKeyResponse struct {
	APIKey  APIKeyResponse `json:"api_key"`
	RawKey  string         `json:"key"`
	Warning string         `json:"warning"`
}

// =============================================================================
// OAuth Responses
// =============================================================================

// OAuthProviderResponse represents a linked OAuth provider.
type OAuthProviderResponse struct {
	Provider  string    `json:"provider"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

// AvailableProviderResponse represents an available OAuth provider.
type AvailableProviderResponse struct {
	Provider string `json:"provider"`
	Name     string `json:"name"`
}

// =============================================================================
// Authorization Responses
// =============================================================================

// PolicyResponse represents a policy in API responses.
type PolicyResponse struct {
	Subject string `json:"subject"`
	Domain  string `json:"domain"`
	Object  string `json:"object"`
	Action  string `json:"action"`
}

// PermissionsResponse represents user permissions in API responses.
type PermissionsResponse struct {
	UserID      uint             `json:"user_id"`
	Roles       []string         `json:"roles"`
	Permissions []PolicyResponse `json:"permissions"`
}
