package handlers

import (
	"github.com/gofiber/fiber/v3"
)

// APIKeyHandlers groups API key management HTTP handlers.
// Use service.APIKeys() to obtain an instance.
type APIKeyHandlers struct {
	service interface{}
}

// NewAPIKeyHandlers creates a new APIKeyHandlers instance.
func NewAPIKeyHandlers(service interface{}) *APIKeyHandlers {
	return &APIKeyHandlers{service: service}
}

// Create returns a handler for creating API keys.
// Requires JWT authentication (not API key auth).
//
// POST /api-keys
//
// Request body: types.CreateAPIKeyRequest
// Response: { "api_key": {...}, "key": "raw_key", "warning": "..." }
func (h *APIKeyHandlers) Create() fiber.Handler {
	return getServiceMethod(h.service, "CreateAPIKeyHandler")
}

// List returns a handler for listing API keys.
// Requires authentication.
//
// GET /api-keys
//
// Response: { "api_keys": [...] }
func (h *APIKeyHandlers) List() fiber.Handler {
	return getServiceMethod(h.service, "ListAPIKeysHandler")
}

// Revoke returns a handler for revoking API keys.
// Requires authentication.
//
// POST /api-keys/:id/revoke
//
// Response: { "message": "API key revoked successfully" }
func (h *APIKeyHandlers) Revoke() fiber.Handler {
	return getServiceMethod(h.service, "RevokeAPIKeyHandler")
}

// Delete returns a handler for deleting API keys.
// Requires authentication.
//
// DELETE /api-keys/:id
//
// Response: 204 No Content
func (h *APIKeyHandlers) Delete() fiber.Handler {
	return getServiceMethod(h.service, "DeleteAPIKeyHandler")
}
