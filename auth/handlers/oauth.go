package handlers

import (
	"github.com/gofiber/fiber/v3"
)

// OAuthHandlers groups OAuth-related HTTP handlers.
// Use service.OAuth() to obtain an instance.
type OAuthHandlers struct {
	service interface{}
}

// NewOAuthHandlers creates a new OAuthHandlers instance.
func NewOAuthHandlers(service interface{}) *OAuthHandlers {
	return &OAuthHandlers{service: service}
}

// oauthHandlerProvider defines the OAuth handler methods we need.
type oauthHandlerProvider interface {
	OAuthRedirectHandler(provider string) fiber.Handler
	OAuthCallbackHandler(provider string) fiber.Handler
	ListOAuthProvidersHandler() fiber.Handler
	UnlinkOAuthProviderHandler() fiber.Handler
	LinkOAuthRedirectHandler(provider string) fiber.Handler
	LinkOAuthCallbackHandler(provider string) fiber.Handler
}

// Redirect returns a handler that initiates the OAuth flow.
// Redirects the user to the OAuth provider's authorization page.
//
// GET /auth/:provider/redirect
// Example: GET /auth/google/redirect
func (h *OAuthHandlers) Redirect(provider string) fiber.Handler {
	if hp, ok := h.service.(oauthHandlerProvider); ok {
		return hp.OAuthRedirectHandler(provider)
	}
	return errorHandler("OAuth redirect not available")
}

// Callback returns a handler that processes the OAuth callback.
// Exchanges the authorization code for tokens and logs in or creates the user.
//
// GET /auth/:provider/callback
// Example: GET /auth/google/callback?code=xxx&state=yyy
func (h *OAuthHandlers) Callback(provider string) fiber.Handler {
	if hp, ok := h.service.(oauthHandlerProvider); ok {
		return hp.OAuthCallbackHandler(provider)
	}
	return errorHandler("OAuth callback not available")
}

// ListProviders returns a handler that lists OAuth providers linked to the current user.
// Requires authentication.
//
// GET /auth/providers
//
// Response: { "linked": [...], "available": [...] }
func (h *OAuthHandlers) ListProviders() fiber.Handler {
	if hp, ok := h.service.(oauthHandlerProvider); ok {
		return hp.ListOAuthProvidersHandler()
	}
	return errorHandler("list providers not available")
}

// UnlinkProvider returns a handler that unlinks an OAuth provider from the current user.
// Requires authentication.
//
// DELETE /auth/providers/:provider
// Example: DELETE /auth/providers/google
func (h *OAuthHandlers) UnlinkProvider() fiber.Handler {
	if hp, ok := h.service.(oauthHandlerProvider); ok {
		return hp.UnlinkOAuthProviderHandler()
	}
	return errorHandler("unlink provider not available")
}

// LinkRedirect returns a handler that initiates OAuth linking for an authenticated user.
// Used when a user wants to add an additional OAuth provider to their account.
// Requires authentication.
//
// GET /auth/providers/:provider/link
// Example: GET /auth/providers/github/link
func (h *OAuthHandlers) LinkRedirect(provider string) fiber.Handler {
	if hp, ok := h.service.(oauthHandlerProvider); ok {
		return hp.LinkOAuthRedirectHandler(provider)
	}
	return errorHandler("OAuth link redirect not available")
}

// LinkCallback returns a handler that processes the OAuth callback for linking.
// Links the OAuth provider to an existing authenticated user.
//
// GET /auth/providers/:provider/callback
// Example: GET /auth/providers/github/callback?code=xxx&state=yyy
func (h *OAuthHandlers) LinkCallback(provider string) fiber.Handler {
	if hp, ok := h.service.(oauthHandlerProvider); ok {
		return hp.LinkOAuthCallbackHandler(provider)
	}
	return errorHandler("OAuth link callback not available")
}

// errorHandler returns a handler that returns an error response.
func errorHandler(message string) fiber.Handler {
	return func(c fiber.Ctx) error {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": message,
		})
	}
}
