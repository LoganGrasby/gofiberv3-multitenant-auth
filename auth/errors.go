package auth

import (
	"errors"
	"fmt"
)

// Sentinel errors for common auth failures.
var (
	ErrTenantNotFound       = errors.New("tenant not found")
	ErrTenantRequired       = errors.New("tenant ID required")
	ErrUserNotFound         = errors.New("user not found")
	ErrUserAlreadyExists    = errors.New("user already exists")
	ErrInvalidCredentials   = errors.New("invalid credentials")
	ErrInvalidToken         = errors.New("invalid or expired token")
	ErrInvalidRefreshToken  = errors.New("invalid or expired refresh token")
	ErrInvalidAPIKey        = errors.New("invalid API key")
	ErrAPIKeyNotFound       = errors.New("API key not found")
	ErrAPIKeyRevoked        = errors.New("API key has been revoked")
	ErrAPIKeyExpired        = errors.New("API key has expired")
	ErrUnauthorized         = errors.New("unauthorized")
	ErrForbidden            = errors.New("forbidden")
	ErrDatabaseNotFound     = errors.New("database not found in context")
	ErrUserNotFoundCtx      = errors.New("user not found in context")
	ErrMissingRequiredField = errors.New("missing required field")
	ErrPasswordTooWeak      = errors.New("password does not meet requirements")

	// OAuth-related errors
	ErrOAuthNotConfigured     = errors.New("OAuth provider not configured")
	ErrOAuthStateMismatch     = errors.New("OAuth state mismatch")
	ErrOAuthTokenExchange     = errors.New("OAuth token exchange failed")
	ErrOAuthProfileFetch      = errors.New("failed to fetch OAuth profile")
	ErrOAuthEmailNotVerified  = errors.New("OAuth email not verified")
	ErrOAuthUserCreationDenied = errors.New("automatic user creation is disabled")
	ErrOAuthProviderNotLinked = errors.New("OAuth provider not linked to any account")
	ErrOAuthProviderAlreadyLinked = errors.New("OAuth provider already linked to another account")
)

// ErrInvalidConfig represents a configuration validation error.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid config: %s - %s", e.Field, e.Reason)
}

// ErrValidation represents a request validation error.
type ErrValidation struct {
	Field   string
	Message string
}

func (e ErrValidation) Error() string {
	return fmt.Sprintf("validation error: %s - %s", e.Field, e.Message)
}

// AuthError wraps an error with additional context.
type AuthError struct {
	Op  string // Operation that failed
	Err error  // Underlying error
}

func (e *AuthError) Error() string {
	return fmt.Sprintf("%s: %v", e.Op, e.Err)
}

func (e *AuthError) Unwrap() error {
	return e.Err
}

// NewAuthError creates a new AuthError.
func NewAuthError(op string, err error) *AuthError {
	return &AuthError{Op: op, Err: err}
}

// IsNotFound returns true if the error indicates a resource was not found.
func IsNotFound(err error) bool {
	return errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrTenantNotFound) ||
		errors.Is(err, ErrAPIKeyNotFound)
}

// IsUnauthorized returns true if the error indicates an authorization failure.
func IsUnauthorized(err error) bool {
	return errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrInvalidToken) ||
		errors.Is(err, ErrInvalidRefreshToken) ||
		errors.Is(err, ErrInvalidAPIKey) ||
		errors.Is(err, ErrAPIKeyRevoked) ||
		errors.Is(err, ErrAPIKeyExpired) ||
		errors.Is(err, ErrUnauthorized)
}
