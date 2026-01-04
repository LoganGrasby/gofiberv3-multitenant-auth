package tests

import (
	"testing"
	"time"

	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func TestUser_TableName(t *testing.T) {
	user := auth.User{}
	assertEqual(t, user.TableName(), "users")
}

func TestRefreshToken_TableName(t *testing.T) {
	rt := auth.RefreshToken{}
	assertEqual(t, rt.TableName(), "refresh_tokens")
}

func TestRefreshToken_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(time.Hour),
			want:      false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-time.Hour),
			want:      true,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-time.Second),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rt := auth.RefreshToken{ExpiresAt: tt.expiresAt}
			assertEqual(t, rt.IsExpired(), tt.want)
		})
	}
}

func TestRefreshToken_IsValid(t *testing.T) {
	tests := []struct {
		name      string
		rt        auth.RefreshToken
		wantValid bool
	}{
		{
			name: "valid token",
			rt: auth.RefreshToken{
				ExpiresAt: time.Now().Add(time.Hour),
				Revoked:   false,
			},
			wantValid: true,
		},
		{
			name: "expired token",
			rt: auth.RefreshToken{
				ExpiresAt: time.Now().Add(-time.Hour),
				Revoked:   false,
			},
			wantValid: false,
		},
		{
			name: "revoked token",
			rt: auth.RefreshToken{
				ExpiresAt: time.Now().Add(time.Hour),
				Revoked:   true,
			},
			wantValid: false,
		},
		{
			name: "revoked and expired",
			rt: auth.RefreshToken{
				ExpiresAt: time.Now().Add(-time.Hour),
				Revoked:   true,
			},
			wantValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertEqual(t, tt.rt.IsValid(), tt.wantValid)
		})
	}
}

func TestAPIKey_TableName(t *testing.T) {
	key := auth.APIKey{}
	assertEqual(t, key.TableName(), "api_keys")
}

func TestAPIKey_IsExpired(t *testing.T) {
	futureTime := time.Now().Add(time.Hour)
	pastTime := time.Now().Add(-time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{
			name:      "nil expiry - never expires",
			expiresAt: nil,
			want:      false,
		},
		{
			name:      "future expiry - not expired",
			expiresAt: &futureTime,
			want:      false,
		},
		{
			name:      "past expiry - expired",
			expiresAt: &pastTime,
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := auth.APIKey{ExpiresAt: tt.expiresAt}
			assertEqual(t, key.IsExpired(), tt.want)
		})
	}
}

func TestAPIKey_IsValid(t *testing.T) {
	futureTime := time.Now().Add(time.Hour)
	pastTime := time.Now().Add(-time.Hour)

	tests := []struct {
		name string
		key  auth.APIKey
		want bool
	}{
		{
			name: "valid key - no expiry",
			key: auth.APIKey{
				Revoked:   false,
				ExpiresAt: nil,
			},
			want: true,
		},
		{
			name: "valid key - future expiry",
			key: auth.APIKey{
				Revoked:   false,
				ExpiresAt: &futureTime,
			},
			want: true,
		},
		{
			name: "expired key",
			key: auth.APIKey{
				Revoked:   false,
				ExpiresAt: &pastTime,
			},
			want: false,
		},
		{
			name: "revoked key",
			key: auth.APIKey{
				Revoked:   true,
				ExpiresAt: nil,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertEqual(t, tt.key.IsValid(), tt.want)
		})
	}
}

func TestAPIKey_HasScope(t *testing.T) {
	tests := []struct {
		name   string
		scopes string
		scope  string
		want   bool
	}{
		{
			name:   "empty scopes - all access",
			scopes: "",
			scope:  "anything",
			want:   true,
		},
		{
			name:   "wildcard scope",
			scopes: "*",
			scope:  "anything",
			want:   true,
		},
		{
			name:   "exact match",
			scopes: "read,write",
			scope:  "read",
			want:   true,
		},
		{
			name:   "no match",
			scopes: "read,write",
			scope:  "delete",
			want:   false,
		},
		{
			name:   "multiple scopes with wildcard",
			scopes: "read,*",
			scope:  "anything",
			want:   true,
		},
		{
			name:   "single scope match",
			scopes: "admin",
			scope:  "admin",
			want:   true,
		},
		{
			name:   "single scope no match",
			scopes: "admin",
			scope:  "user",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := auth.APIKey{Scopes: tt.scopes}
			assertEqual(t, key.HasScope(tt.scope), tt.want)
		})
	}
}

func TestAuditLog_TableName(t *testing.T) {
	log := auth.AuditLog{}
	assertEqual(t, log.TableName(), "audit_logs")
}

func TestAllModels(t *testing.T) {
	models := auth.AllModels()

	// Should return 5 models
	if len(models) != 5 {
		t.Errorf("expected 5 models, got %d", len(models))
	}

	// Check types
	_, ok := models[0].(*auth.User)
	assertTrue(t, ok, "first model should be *User")

	_, ok = models[1].(*auth.RefreshToken)
	assertTrue(t, ok, "second model should be *RefreshToken")

	_, ok = models[2].(*auth.APIKey)
	assertTrue(t, ok, "third model should be *APIKey")

	_, ok = models[3].(*auth.OAuthProvider)
	assertTrue(t, ok, "fourth model should be *OAuthProvider")

	_, ok = models[4].(*auth.AuditLog)
	assertTrue(t, ok, "fifth model should be *AuditLog")
}
