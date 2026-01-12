package tests

import (
	"errors"
	"testing"

	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func TestErrInvalidConfig_Error(t *testing.T) {
	err := auth.ErrInvalidConfig{
		Field:  "JWTSecret",
		Reason: "cannot be empty",
	}

	got := err.Error()
	want := "invalid config: JWTSecret - cannot be empty"
	assertEqual(t, got, want)
}

func TestErrValidation_Error(t *testing.T) {
	err := auth.ErrValidation{
		Field:   "email",
		Message: "is required",
	}

	got := err.Error()
	want := "validation error: email - is required"
	assertEqual(t, got, want)
}

func TestAuthError_Error(t *testing.T) {
	innerErr := errors.New("database connection failed")
	err := auth.AuthError{
		Op:  "login",
		Err: innerErr,
	}

	got := err.Error()
	want := "login: database connection failed"
	assertEqual(t, got, want)
}

func TestAuthError_Unwrap(t *testing.T) {
	innerErr := errors.New("inner error")
	err := &auth.AuthError{
		Op:  "test",
		Err: innerErr,
	}

	unwrapped := err.Unwrap()
	if unwrapped != innerErr {
		t.Errorf("unwrapped error should be the inner error")
	}

	// Test with errors.Is
	if !errors.Is(err, innerErr) {
		t.Errorf("errors.Is should match inner error")
	}
}

func TestNewAuthError(t *testing.T) {
	innerErr := errors.New("something went wrong")
	err := auth.NewAuthError("operation", innerErr)

	assertEqual(t, err.Op, "operation")
	if err.Err != innerErr {
		t.Errorf("inner error should be preserved")
	}
}

func TestIsNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrUserNotFound", auth.ErrUserNotFound, true},
		{"ErrTenantNotFound", auth.ErrTenantNotFound, true},
		{"ErrAPIKeyNotFound", auth.ErrAPIKeyNotFound, true},
		{"wrapped ErrUserNotFound", auth.NewAuthError("get", auth.ErrUserNotFound), true},
		{"ErrInvalidCredentials", auth.ErrInvalidCredentials, false},
		{"ErrInvalidToken", auth.ErrInvalidToken, false},
		{"generic error", errors.New("some error"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.IsNotFound(tt.err)
			assertEqual(t, got, tt.want)
		})
	}
}

func TestIsUnauthorized(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"ErrInvalidCredentials", auth.ErrInvalidCredentials, true},
		{"ErrInvalidToken", auth.ErrInvalidToken, true},
		{"ErrInvalidRefreshToken", auth.ErrInvalidRefreshToken, true},
		{"ErrInvalidAPIKey", auth.ErrInvalidAPIKey, true},
		{"ErrAPIKeyRevoked", auth.ErrAPIKeyRevoked, true},
		{"ErrAPIKeyExpired", auth.ErrAPIKeyExpired, true},
		{"ErrUnauthorized", auth.ErrUnauthorized, true},
		{"wrapped ErrInvalidToken", auth.NewAuthError("auth", auth.ErrInvalidToken), true},
		{"ErrUserNotFound", auth.ErrUserNotFound, false},
		{"ErrTenantNotFound", auth.ErrTenantNotFound, false},
		{"generic error", errors.New("some error"), false},
		{"nil error", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.IsUnauthorized(tt.err)
			assertEqual(t, got, tt.want)
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	// Ensure all sentinel errors have meaningful messages
	sentinelErrors := []error{
		auth.ErrTenantNotFound,
		auth.ErrTenantRequired,
		auth.ErrUserNotFound,
		auth.ErrUserAlreadyExists,
		auth.ErrInvalidCredentials,
		auth.ErrInvalidToken,
		auth.ErrInvalidRefreshToken,
		auth.ErrInvalidAPIKey,
		auth.ErrAPIKeyNotFound,
		auth.ErrAPIKeyRevoked,
		auth.ErrAPIKeyExpired,
		auth.ErrUnauthorized,
		auth.ErrForbidden,
		auth.ErrDatabaseNotFound,
		auth.ErrUserNotFoundCtx,
		auth.ErrMissingRequiredField,
		auth.ErrPasswordTooWeak,
	}

	for _, err := range sentinelErrors {
		if err.Error() == "" {
			t.Errorf("sentinel error should have a message: %v", err)
		}
	}
}

func TestErrorsAreUnique(t *testing.T) {
	// Ensure sentinel errors are distinct
	sentinelErrors := []error{
		auth.ErrTenantNotFound,
		auth.ErrTenantRequired,
		auth.ErrUserNotFound,
		auth.ErrUserAlreadyExists,
		auth.ErrInvalidCredentials,
		auth.ErrInvalidToken,
		auth.ErrInvalidRefreshToken,
		auth.ErrInvalidAPIKey,
		auth.ErrAPIKeyNotFound,
		auth.ErrAPIKeyRevoked,
		auth.ErrAPIKeyExpired,
		auth.ErrUnauthorized,
		auth.ErrForbidden,
		auth.ErrDatabaseNotFound,
		auth.ErrUserNotFoundCtx,
		auth.ErrMissingRequiredField,
		auth.ErrPasswordTooWeak,
	}

	seen := make(map[string]bool)
	for _, err := range sentinelErrors {
		msg := err.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %s", msg)
		}
		seen[msg] = true
	}
}
