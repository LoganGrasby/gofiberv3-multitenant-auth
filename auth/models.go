package auth

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user account within a tenant.
type User struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	Email        string         `gorm:"uniqueIndex;size:255;not null" json:"email"`
	PasswordHash string         `gorm:"size:255;not null" json:"-"`
	Name         string         `gorm:"size:255" json:"name"`
	Role         string         `gorm:"size:50;default:user" json:"role"`
	Active       bool           `gorm:"default:true" json:"active"`
	LastLoginAt  *time.Time     `json:"last_login_at,omitempty"`
	Metadata     string         `gorm:"type:text" json:"metadata,omitempty"` // JSON string for custom data
}

// TableName specifies the table name for User.
func (User) TableName() string {
	return "users"
}

// RefreshToken stores refresh tokens for JWT authentication.
type RefreshToken struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	UserID    uint           `gorm:"index;not null" json:"user_id"`
	User      User           `gorm:"foreignKey:UserID" json:"-"`
	TokenHash string         `gorm:"size:64;uniqueIndex;not null" json:"-"`
	ExpiresAt time.Time      `gorm:"not null" json:"expires_at"`
	UserAgent string         `gorm:"size:512" json:"user_agent,omitempty"`
	IPAddress string         `gorm:"size:45" json:"ip_address,omitempty"`
	Revoked   bool           `gorm:"default:false" json:"revoked"`
	RevokedAt *time.Time     `json:"revoked_at,omitempty"`
}

// TableName specifies the table name for RefreshToken.
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// IsExpired checks if the refresh token has expired.
func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// IsValid checks if the refresh token is usable.
func (r *RefreshToken) IsValid() bool {
	return !r.Revoked && !r.IsExpired()
}

// APIKey represents an API key for programmatic access.
type APIKey struct {
	ID          uint           `gorm:"primarykey" json:"id"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
	UserID      uint           `gorm:"index;not null" json:"user_id"`
	User        User           `gorm:"foreignKey:UserID" json:"-"`
	Name        string         `gorm:"size:255;not null" json:"name"`
	KeyPrefix   string         `gorm:"size:12;not null" json:"key_prefix"` // First 8 chars for identification
	KeyHash     string         `gorm:"size:64;uniqueIndex;not null" json:"-"`
	Scopes      string         `gorm:"size:1024" json:"scopes,omitempty"` // Comma-separated scopes
	ExpiresAt   *time.Time     `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time     `json:"last_used_at,omitempty"`
	LastUsedIP  string         `gorm:"size:45" json:"last_used_ip,omitempty"`
	Revoked     bool           `gorm:"default:false" json:"revoked"`
	RevokedAt   *time.Time     `json:"revoked_at,omitempty"`
	UsageCount  int64          `gorm:"default:0" json:"usage_count"`
	RateLimit   int            `gorm:"default:0" json:"rate_limit,omitempty"` // Requests per minute, 0 = unlimited
	Description string         `gorm:"size:1024" json:"description,omitempty"`
}

// TableName specifies the table name for APIKey.
func (APIKey) TableName() string {
	return "api_keys"
}

// IsExpired checks if the API key has expired.
func (a *APIKey) IsExpired() bool {
	if a.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*a.ExpiresAt)
}

// IsValid checks if the API key is usable.
func (a *APIKey) IsValid() bool {
	return !a.Revoked && !a.IsExpired()
}

// HasScope checks if the API key has a specific scope.
func (a *APIKey) HasScope(scope string) bool {
	if a.Scopes == "" {
		return true // No scopes means all access
	}
	scopes := SplitScopes(a.Scopes)
	for _, s := range scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// OAuthProvider tracks OAuth provider connections to users.
// A user can have multiple OAuth providers linked (e.g., Google, GitHub).
// Users with the same email can authenticate via any linked provider.
type OAuthProvider struct {
	ID           uint           `gorm:"primarykey" json:"id"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    gorm.DeletedAt `gorm:"index" json:"-"`
	UserID       uint           `gorm:"index;not null" json:"user_id"`
	User         User           `gorm:"foreignKey:UserID" json:"-"`
	Provider     string         `gorm:"size:50;not null;index" json:"provider"`          // google, github, etc.
	ProviderID   string         `gorm:"size:255;not null" json:"provider_id"`            // Unique ID from the provider
	Email        string         `gorm:"size:255;index" json:"email"`                     // Email from provider (may differ from user email)
	AccessToken  string         `gorm:"size:2048" json:"-"`                              // Encrypted access token
	RefreshToken string         `gorm:"size:2048" json:"-"`                              // Encrypted refresh token
	TokenExpiry  *time.Time     `json:"token_expiry,omitempty"`                          // When the access token expires
	Metadata     string         `gorm:"type:text" json:"metadata,omitempty"`             // JSON with provider-specific data (name, avatar, etc.)
}

// TableName specifies the table name for OAuthProvider.
func (OAuthProvider) TableName() string {
	return "oauth_providers"
}

// AuditLog records authentication events for security auditing.
type AuditLog struct {
	ID        uint      `gorm:"primarykey"`
	CreatedAt time.Time `gorm:"index"`
	UserID    *uint     `gorm:"index"`
	Action    string    `gorm:"size:50;not null;index"` // login, logout, login_failed, api_key_used, etc.
	IPAddress string    `gorm:"size:45"`
	UserAgent string    `gorm:"size:512"`
	Details   string    `gorm:"type:text"` // JSON with additional details
	Success   bool
}

// TableName specifies the table name for AuditLog.
func (AuditLog) TableName() string {
	return "audit_logs"
}

// AllModels returns all models for auto-migration.
func AllModels() []interface{} {
	return []interface{}{
		&User{},
		&RefreshToken{},
		&APIKey{},
		&OAuthProvider{},
		&AuditLog{},
	}
}
