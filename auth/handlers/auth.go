// Package handlers provides grouped HTTP handler functions for the auth service.
// Each handler group organizes related endpoints for better discoverability.
package handlers

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth/types"
)

// ServiceInterface defines the methods required by AuthHandlers.
// This allows for easier testing and decoupling.
type ServiceInterface interface {
	Register(ctx interface{}, db interface{}, input interface{}) (interface{}, error)
	Login(ctx interface{}, db interface{}, input interface{}, tenantID string) (interface{}, interface{}, error)
	RefreshTokens(ctx interface{}, db interface{}, refreshToken, tenantID, userAgent, ip string) (interface{}, error)
	Logout(ctx interface{}, db interface{}, refreshToken string) error
	LogoutAll(ctx interface{}, db interface{}, userID uint) error
	UpdatePassword(ctx interface{}, db interface{}, userID uint, oldPassword, newPassword string) error
	Config() interface{}
}

// AuthHandlers groups authentication-related HTTP handlers.
// Use service.Auth() to obtain an instance.
type AuthHandlers struct {
	service interface{}
}

// NewAuthHandlers creates a new AuthHandlers instance.
func NewAuthHandlers(service interface{}) *AuthHandlers {
	return &AuthHandlers{service: service}
}

// Register returns a handler for user registration.
//
// POST /auth/register
//
// Request body: types.RegisterRequest
// Response: { "user": { "id", "email", "name" } }
func (h *AuthHandlers) Register() fiber.Handler {
	return getServiceMethod(h.service, "RegisterHandler")
}

// Login returns a handler for user login.
//
// POST /auth/login
//
// Request body: types.LoginRequest
// Response: { "access_token", "refresh_token", "token_type", "expires_at", "user" }
func (h *AuthHandlers) Login() fiber.Handler {
	return getServiceMethod(h.service, "LoginHandler")
}

// Refresh returns a handler for refreshing tokens.
//
// POST /auth/refresh
//
// Request body: types.RefreshRequest (or use refresh_token cookie)
// Response: { "access_token", "refresh_token", "token_type", "expires_at" }
func (h *AuthHandlers) Refresh() fiber.Handler {
	return getServiceMethod(h.service, "RefreshHandler")
}

// Logout returns a handler for user logout.
//
// POST /auth/logout
//
// Request body: types.RefreshRequest (optional, uses cookie if not provided)
// Response: { "message": "logged out successfully" }
func (h *AuthHandlers) Logout() fiber.Handler {
	return getServiceMethod(h.service, "LogoutHandler")
}

// LogoutAll returns a handler for logging out all sessions.
// Requires authentication.
//
// POST /auth/logout-all
//
// Response: { "message": "logged out of all sessions" }
func (h *AuthHandlers) LogoutAll() fiber.Handler {
	return getServiceMethod(h.service, "LogoutAllHandler")
}

// Me returns a handler that returns the current user's profile.
// Requires authentication.
//
// GET /me
//
// Response: { "user": { "id", "email", "name", "role", "created_at", "last_login_at" }, "auth_type" }
func (h *AuthHandlers) Me() fiber.Handler {
	return getServiceMethod(h.service, "MeHandler")
}

// ChangePassword returns a handler for changing the user's password.
// Requires authentication.
//
// POST /auth/change-password
//
// Request body: types.ChangePasswordRequest
// Response: { "message": "password changed successfully" }
func (h *AuthHandlers) ChangePassword() fiber.Handler {
	return getServiceMethod(h.service, "ChangePasswordHandler")
}

// getServiceMethod uses reflection to call a handler method on the service.
// This allows AuthHandlers to work with the Service without circular imports.
func getServiceMethod(service interface{}, methodName string) fiber.Handler {
	// Use type assertion with interface that has all handler methods
	type handlerProvider interface {
		RegisterHandler() fiber.Handler
		LoginHandler() fiber.Handler
		RefreshHandler() fiber.Handler
		LogoutHandler() fiber.Handler
		LogoutAllHandler() fiber.Handler
		MeHandler() fiber.Handler
		ChangePasswordHandler() fiber.Handler
		CreateAPIKeyHandler() fiber.Handler
		ListAPIKeysHandler() fiber.Handler
		RevokeAPIKeyHandler() fiber.Handler
		DeleteAPIKeyHandler() fiber.Handler
	}

	if hp, ok := service.(handlerProvider); ok {
		switch methodName {
		case "RegisterHandler":
			return hp.RegisterHandler()
		case "LoginHandler":
			return hp.LoginHandler()
		case "RefreshHandler":
			return hp.RefreshHandler()
		case "LogoutHandler":
			return hp.LogoutHandler()
		case "LogoutAllHandler":
			return hp.LogoutAllHandler()
		case "MeHandler":
			return hp.MeHandler()
		case "ChangePasswordHandler":
			return hp.ChangePasswordHandler()
		case "CreateAPIKeyHandler":
			return hp.CreateAPIKeyHandler()
		case "ListAPIKeysHandler":
			return hp.ListAPIKeysHandler()
		case "RevokeAPIKeyHandler":
			return hp.RevokeAPIKeyHandler()
		case "DeleteAPIKeyHandler":
			return hp.DeleteAPIKeyHandler()
		}
	}

	// Fallback: return a handler that returns an error
	return func(c fiber.Ctx) error {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "handler not available",
		})
	}
}

// Ensure types are used (for import)
var (
	_ types.RegisterRequest
	_ types.LoginRequest
	_ time.Time
	_ = strconv.Itoa
)
