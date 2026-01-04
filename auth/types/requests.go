package types

import "time"

// =============================================================================
// Authentication Requests
// =============================================================================

// RegisterRequest is the request body for user registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

// LoginRequest is the request body for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest is the request body for token refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// ChangePasswordRequest is the request body for changing password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// =============================================================================
// API Key Requests
// =============================================================================

// CreateAPIKeyRequest is the request body for creating an API key.
type CreateAPIKeyRequest struct {
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Description string     `json:"description,omitempty"`
}

// =============================================================================
// Authorization/Casbin Requests
// =============================================================================

// PolicyRequest represents a request to add or remove a policy.
type PolicyRequest struct {
	Subject string `json:"subject"` // e.g., "user:1" or "admin"
	Object  string `json:"object"`  // e.g., "/api/blog/*" or "blog:create"
	Action  string `json:"action"`  // e.g., "GET", "POST", "*"
}

// RoleRequest represents a request to assign or remove a role.
type RoleRequest struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
}

// BulkPolicyRequest represents a request for bulk policy operations.
type BulkPolicyRequest struct {
	Policies []PolicyRequest `json:"policies"`
}

// CheckPermissionRequest represents a request to check a specific permission.
type CheckPermissionRequest struct {
	UserID uint   `json:"user_id"`
	Object string `json:"object"`
	Action string `json:"action"`
}

// RolePolicyRequest represents a request to add a policy for a role.
type RolePolicyRequest struct {
	Role   string `json:"role"`
	Object string `json:"object"`
	Action string `json:"action"`
}
