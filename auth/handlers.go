package auth

import (
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth/types"
)

// RegisterHandler returns a handler for user registration.
func (s *Service) RegisterHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		var req types.RegisterRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		user, err := s.Register(c.Context(), db, RegisterInput{
			Email:    req.Email,
			Password: req.Password,
			Name:     req.Name,
		})

		if err != nil {
			if err == ErrUserAlreadyExists {
				return c.Status(fiber.StatusConflict).JSON(fiber.Map{
					"error": "user already exists",
				})
			}
			if ve, ok := err.(*ErrValidation); ok {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": ve.Message,
					"field": ve.Field,
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "registration failed",
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"user": fiber.Map{
				"id":    user.ID,
				"email": user.Email,
				"name":  user.Name,
			},
		})
	}
}

// LoginHandler returns a handler for user login.
func (s *Service) LoginHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		tenantID := GetTenantID(c)

		var req types.LoginRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		tokens, user, err := s.Login(c.Context(), db, LoginInput{
			Email:     req.Email,
			Password:  req.Password,
			UserAgent: c.Get("User-Agent"),
			IPAddress: c.IP(),
		}, tenantID)

		if err != nil {
			if err == ErrInvalidCredentials {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid credentials",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "login failed",
			})
		}

		// Set refresh token cookie if cookie settings are configured
		if s.config.CookieHTTPOnly {
			c.Cookie(&fiber.Cookie{
				Name:     "refresh_token",
				Value:    tokens.RefreshToken,
				Expires:  time.Now().Add(s.config.JWTRefreshExpiration),
				HTTPOnly: s.config.CookieHTTPOnly,
				Secure:   s.config.CookieSecure,
				SameSite: s.config.CookieSameSite,
				Domain:   s.config.CookieDomain,
				Path:     "/",
			})
		}

		return c.JSON(fiber.Map{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"token_type":    tokens.TokenType,
			"expires_at":    tokens.ExpiresAt,
			"user": fiber.Map{
				"id":    user.ID,
				"email": user.Email,
				"name":  user.Name,
				"role":  user.Role,
			},
		})
	}
}

// RefreshHandler returns a handler for refreshing tokens.
func (s *Service) RefreshHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		tenantID := GetTenantID(c)

		// Try to get refresh token from cookie first, then body
		refreshToken := c.Cookies("refresh_token")
		if refreshToken == "" {
			var req types.RefreshRequest
			if err := c.Bind().JSON(&req); err != nil {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "refresh token required",
				})
			}
			refreshToken = req.RefreshToken
		}

		if refreshToken == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "refresh token required",
			})
		}

		tokens, err := s.RefreshTokens(c.Context(), db, refreshToken, tenantID, c.Get("User-Agent"), c.IP())
		if err != nil {
			if err == ErrInvalidRefreshToken {
				// Clear the cookie if it's invalid
				c.Cookie(&fiber.Cookie{
					Name:     "refresh_token",
					Value:    "",
					Expires:  time.Now().Add(-time.Hour),
					HTTPOnly: true,
					Secure:   s.config.CookieSecure,
					SameSite: s.config.CookieSameSite,
					Domain:   s.config.CookieDomain,
					Path:     "/",
				})
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid or expired refresh token",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "token refresh failed",
			})
		}

		// Update refresh token cookie
		if s.config.CookieHTTPOnly {
			c.Cookie(&fiber.Cookie{
				Name:     "refresh_token",
				Value:    tokens.RefreshToken,
				Expires:  time.Now().Add(s.config.JWTRefreshExpiration),
				HTTPOnly: s.config.CookieHTTPOnly,
				Secure:   s.config.CookieSecure,
				SameSite: s.config.CookieSameSite,
				Domain:   s.config.CookieDomain,
				Path:     "/",
			})
		}

		return c.JSON(fiber.Map{
			"access_token":  tokens.AccessToken,
			"refresh_token": tokens.RefreshToken,
			"token_type":    tokens.TokenType,
			"expires_at":    tokens.ExpiresAt,
		})
	}
}

// LogoutHandler returns a handler for user logout.
func (s *Service) LogoutHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		// Get refresh token from cookie or body
		refreshToken := c.Cookies("refresh_token")
		if refreshToken == "" {
			var req types.RefreshRequest
			if err := c.Bind().JSON(&req); err == nil {
				refreshToken = req.RefreshToken
			}
		}

		if refreshToken != "" {
			_ = s.Logout(c.Context(), db, refreshToken)
		}

		// Clear the cookie
		c.Cookie(&fiber.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   s.config.CookieSecure,
			SameSite: s.config.CookieSameSite,
			Domain:   s.config.CookieDomain,
			Path:     "/",
		})

		return c.JSON(fiber.Map{
			"message": "logged out successfully",
		})
	}
}

// LogoutAllHandler returns a handler for logging out all sessions.
func (s *Service) LogoutAllHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		if err := s.LogoutAll(c.Context(), db, userID); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "logout failed",
			})
		}

		// Clear the cookie
		c.Cookie(&fiber.Cookie{
			Name:     "refresh_token",
			Value:    "",
			Expires:  time.Now().Add(-time.Hour),
			HTTPOnly: true,
			Secure:   s.config.CookieSecure,
			SameSite: s.config.CookieSameSite,
			Domain:   s.config.CookieDomain,
			Path:     "/",
		})

		return c.JSON(fiber.Map{
			"message": "logged out of all sessions",
		})
	}
}

// MeHandler returns a handler that returns the current user's profile.
func (s *Service) MeHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		user := GetUser(c)
		if user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		return c.JSON(fiber.Map{
			"user": fiber.Map{
				"id":            user.ID,
				"email":         user.Email,
				"name":          user.Name,
				"role":          user.Role,
				"created_at":    user.CreatedAt,
				"last_login_at": user.LastLoginAt,
			},
			"auth_type": GetAuthType(c),
		})
	}
}

// ChangePasswordHandler returns a handler for changing the user's password.
func (s *Service) ChangePasswordHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		var req types.ChangePasswordRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		if err := s.UpdatePassword(c.Context(), db, userID, req.OldPassword, req.NewPassword); err != nil {
			if err == ErrInvalidCredentials {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "current password is incorrect",
				})
			}
			if err == ErrPasswordTooWeak {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": "new password does not meet requirements",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "password change failed",
			})
		}

		return c.JSON(fiber.Map{
			"message": "password changed successfully",
		})
	}
}

// =============================================================================
// API Key Handlers
// =============================================================================

// CreateAPIKeyHandler returns a handler for creating API keys.
func (s *Service) CreateAPIKeyHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		var req types.CreateAPIKeyRequest
		if err := c.Bind().JSON(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid request body",
			})
		}

		result, err := s.CreateAPIKey(c.Context(), db, userID, CreateAPIKeyInput{
			Name:        req.Name,
			Scopes:      req.Scopes,
			ExpiresAt:   req.ExpiresAt,
			Description: req.Description,
		})

		if err != nil {
			if ve, ok := err.(*ErrValidation); ok {
				return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
					"error": ve.Message,
					"field": ve.Field,
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to create API key",
			})
		}

		return c.Status(fiber.StatusCreated).JSON(fiber.Map{
			"api_key": fiber.Map{
				"id":          result.APIKey.ID,
				"name":        result.APIKey.Name,
				"key_prefix":  result.KeyPrefix,
				"scopes":      result.APIKey.Scopes,
				"expires_at":  result.APIKey.ExpiresAt,
				"description": result.APIKey.Description,
				"created_at":  result.APIKey.CreatedAt,
			},
			"key":     result.RawKey, // Only shown once!
			"warning": "Store this key securely. It will not be shown again.",
		})
	}
}

// ListAPIKeysHandler returns a handler for listing API keys.
func (s *Service) ListAPIKeysHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		keys, err := s.ListAPIKeys(c.Context(), db, userID)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to list API keys",
			})
		}

		// Transform for response (don't expose hashes)
		apiKeys := make([]fiber.Map, len(keys))
		for i, key := range keys {
			apiKeys[i] = fiber.Map{
				"id":           key.ID,
				"name":         key.Name,
				"key_prefix":   key.KeyPrefix,
				"scopes":       key.Scopes,
				"expires_at":   key.ExpiresAt,
				"last_used_at": key.LastUsedAt,
				"usage_count":  key.UsageCount,
				"revoked":      key.Revoked,
				"created_at":   key.CreatedAt,
			}
		}

		return c.JSON(fiber.Map{
			"api_keys": apiKeys,
		})
	}
}

// RevokeAPIKeyHandler returns a handler for revoking API keys.
func (s *Service) RevokeAPIKeyHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		keyID, err := strconv.Atoi(c.Params("id"))
		if err != nil || keyID <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid key ID",
			})
		}

		if err := s.RevokeAPIKey(c.Context(), db, uint(keyID), userID); err != nil {
			if err == ErrAPIKeyNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "API key not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to revoke API key",
			})
		}

		return c.JSON(fiber.Map{
			"message": "API key revoked successfully",
		})
	}
}

// DeleteAPIKeyHandler returns a handler for deleting API keys.
func (s *Service) DeleteAPIKeyHandler() fiber.Handler {
	return func(c fiber.Ctx) error {
		db := GetTenantDB(c)
		if db == nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "database not available",
			})
		}

		userID := GetUserID(c)
		if userID == 0 {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		keyID, err := strconv.Atoi(c.Params("id"))
		if err != nil || keyID <= 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "invalid key ID",
			})
		}

		if err := s.DeleteAPIKey(c.Context(), db, uint(keyID), userID); err != nil {
			if err == ErrAPIKeyNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "API key not found",
				})
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "failed to delete API key",
			})
		}

		return c.SendStatus(fiber.StatusNoContent)
	}
}
