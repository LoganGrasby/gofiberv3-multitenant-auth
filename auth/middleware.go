package auth

import (
	"slices"
	"strings"

	jwtware "github.com/gofiber/contrib/v3/jwt"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/gofiber/fiber/v3/middleware/keyauth"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"
)

// Context keys for storing auth-related data in Fiber's Locals.
const (
	LocalsTenantID = "tenant_id"
	LocalsTenantDB = "tenant_db"
	LocalsUser     = "auth_user"
	LocalsUserID   = "auth_user_id"
	LocalsAPIKey   = "auth_api_key"
	LocalsAuthType = "auth_type"
	LocalsClaims   = "auth_claims"
)

// Auth type constants.
const (
	AuthTypeJWT    = "jwt"
	AuthTypeAPIKey = "apikey"
	AuthTypeOAuth  = "oauth"
)

// TenantMiddleware creates middleware that extracts and validates the tenant ID,
// then attaches the tenant's database connection to the request context.
func (s *Service[U]) TenantMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Extract tenant ID
		tenantID, err := s.config.TenantExtractor.Extract(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "tenant identification required",
			})
		}

		// Validate tenant ID
		tenantID = strings.TrimSpace(tenantID)
		if tenantID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "tenant ID cannot be empty",
			})
		}

		// Get database connection
		db, err := s.dbManager.GetDB(c.Context(), tenantID)
		if err != nil {
			if err == ErrTenantNotFound {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
					"error": "tenant not found",
				})
			}
			if s.config.Logger != nil {
				s.config.Logger.Error("failed to get tenant database", "tenant", tenantID, "error", err)
			}
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "internal server error",
			})
		}

		// Store in context
		c.Locals(LocalsTenantID, tenantID)
		c.Locals(LocalsTenantDB, db)

		return c.Next()
	}
}

// JWTMiddleware creates middleware that validates JWT tokens.
// It requires TenantMiddleware to be applied first.
func (s *Service[U]) JWTMiddleware() fiber.Handler {
	return jwtware.New(jwtware.Config{
		SigningKey: jwtware.SigningKey{
			Key: s.config.JWTSecret,
		},
		Claims: &Claims{},
		SuccessHandler: func(c fiber.Ctx) error {
			// Get the validated token
			token := jwtware.FromContext(c)
			if token == nil {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid token",
				})
			}

			claims, ok := token.Claims.(*Claims)
			if !ok {
				return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
					"error": "invalid token claims",
				})
			}

			// Verify tenant matches
			tenantID := GetTenantID(c)
			if tenantID != "" && claims.TenantID != tenantID {
				return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
					"error": "token not valid for this tenant",
				})
			}

			// Get the user from the database to ensure they still exist and are active
			db := GetTenantDB(c)
			if db != nil {
				var user U
				if err := db.First(&user, claims.UserID).Error; err != nil {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "user not found",
					})
				}
				if !user.IsActive() {
					return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
						"error": "user account is disabled",
					})
				}
				c.Locals(LocalsUser, user)
			}

			// Store auth info
			c.Locals(LocalsUserID, claims.UserID)
			c.Locals(LocalsClaims, claims)
			c.Locals(LocalsAuthType, AuthTypeJWT)

			if s.config.OnAuthSuccess != nil {
				s.config.OnAuthSuccess(c, AuthTypeJWT, claims.UserID)
			}

			return c.Next()
		},
		ErrorHandler: func(c fiber.Ctx, err error) error {
			if s.config.OnAuthFailure != nil {
				s.config.OnAuthFailure(c, err)
			}
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid or expired token",
			})
		},
	})
}

// APIKeyMiddleware creates middleware that validates API keys.
// It requires TenantMiddleware to be applied first.
func (s *Service[U]) APIKeyMiddleware() fiber.Handler {
	// Secure extractor chain: headers only, no query params for API keys
	apiKeyExtractor := extractors.Chain(
		extractors.FromAuthHeader("ApiKey"), // Standard: "Authorization: ApiKey sk_..."
		extractors.FromAuthHeader("Bearer"), // Alternative: "Authorization: Bearer sk_..."
		extractors.FromHeader("X-API-Key"),  // Alternative: "X-API-Key: sk_..."
	)

	return keyauth.New(keyauth.Config{
		Extractor: apiKeyExtractor,
		Validator: func(c fiber.Ctx, key string) (bool, error) {
			db := GetTenantDB(c)
			if db == nil {
				return false, ErrDatabaseNotFound
			}

			apiKey, user, err := s.ValidateAPIKey(c.Context(), db, key)
			if err != nil {
				if s.config.OnAuthFailure != nil {
					s.config.OnAuthFailure(c, err)
				}
				return false, err
			}

			// Update last used IP
			db.Model(apiKey).Update("last_used_ip", c.IP())

			// Store auth info
			c.Locals(LocalsUser, user)
			c.Locals(LocalsUserID, user.GetID())
			c.Locals(LocalsAPIKey, apiKey)
			c.Locals(LocalsAuthType, AuthTypeAPIKey)

			if s.config.OnAuthSuccess != nil {
				s.config.OnAuthSuccess(c, AuthTypeAPIKey, user.GetID())
			}

			return true, nil
		},
		ErrorHandler: func(c fiber.Ctx, err error) error {
			status := fiber.StatusUnauthorized
			message := "invalid API key"

			switch err {
			case ErrAPIKeyExpired:
				message = "API key has expired"
			case ErrAPIKeyRevoked:
				message = "API key has been revoked"
			}

			return c.Status(status).JSON(fiber.Map{
				"error": message,
			})
		},
	})
}

// AuthMiddleware creates middleware that accepts either JWT or API key authentication.
// It tries JWT first, then falls back to API key if no JWT is present.
// It requires TenantMiddleware to be applied first.
//
// Security: Uses extractors library for RFC-compliant header parsing:
//   - JWT: extractors.FromAuthHeader("Bearer") for standard Bearer tokens
//   - API Key: Secure chain with headers only (no query params)
func (s *Service[U]) AuthMiddleware() fiber.Handler {
	jwtMiddleware := s.JWTMiddleware()
	apiKeyMiddleware := s.APIKeyMiddleware()

	// Use extractors for secure, RFC-compliant token extraction
	jwtExtractor := extractors.FromAuthHeader("Bearer")
	apiKeyExtractor := extractors.Chain(
		extractors.FromAuthHeader("ApiKey"),
		extractors.FromHeader("X-API-Key"),
	)

	return func(c fiber.Ctx) error {
		// Try JWT first using the standard Bearer scheme extractor
		if token, err := jwtExtractor.Extract(c); err == nil && token != "" {
			// Check if it looks like a JWT (has three parts separated by dots)
			if strings.Count(token, ".") == 2 {
				return jwtMiddleware(c)
			}
		}

		// Try API key using secure extractor chain (headers only)
		if key, err := apiKeyExtractor.Extract(c); err == nil && key != "" {
			return apiKeyMiddleware(c)
		}

		// No authentication provided
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "authentication required",
		})
	}
}

// RequireRole creates middleware that requires the authenticated user to have a specific role.
func RequireRole(roles ...string) fiber.Handler {
	return func(c fiber.Ctx) error {
		user := GetUserModel(c)
		if user == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		if slices.Contains(roles, user.GetRole()) {
			return c.Next()
		}

		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "insufficient permissions",
		})
	}
}

// RequireScope creates middleware that requires the API key to have a specific scope.
// This only applies to API key authentication.
func RequireScope(scope string) fiber.Handler {
	return func(c fiber.Ctx) error {
		authType := GetAuthType(c)
		if authType != AuthTypeAPIKey {
			// Not using API key, allow through
			return c.Next()
		}

		apiKey := GetAPIKey(c)
		if apiKey == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "authentication required",
			})
		}

		if !apiKey.HasScope(scope) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "insufficient scope",
			})
		}

		return c.Next()
	}
}

// =============================================================================
// Context Helpers
// =============================================================================

// GetTenantID returns the tenant ID from the request context.
func GetTenantID(c fiber.Ctx) string {
	if id, ok := c.Locals(LocalsTenantID).(string); ok {
		return id
	}
	return ""
}

// GetTenantDB returns the tenant's database connection from the request context.
func GetTenantDB(c fiber.Ctx) *gorm.DB {
	if db, ok := c.Locals(LocalsTenantDB).(*gorm.DB); ok {
		return db
	}
	return nil
}

// GetUserModel returns the authenticated user as a UserModel interface from the request context.
// Use this when you need to access user properties through the interface methods.
func GetUserModel(c fiber.Ctx) UserModel {
	if user, ok := c.Locals(LocalsUser).(UserModel); ok {
		return user
	}
	return nil
}

// GetUser returns the authenticated user as a *User (BaseUser) from the request context.
// This is a convenience function for when you know you're using the default User model.
// For custom user models, use GetUserAs[T] instead.
func GetUser(c fiber.Ctx) *User {
	if user, ok := c.Locals(LocalsUser).(*User); ok {
		return user
	}
	return nil
}

// GetUserAs returns the authenticated user cast to the specified type.
// Use this when you have a custom user model.
//
// Example:
//
//	type MyUser struct {
//	    auth.BaseUser
//	    OrganizationID uint
//	}
//
//	user := auth.GetUserAs[*MyUser](c)
//	if user != nil {
//	    fmt.Println(user.OrganizationID)
//	}
func GetUserAs[U UserModel](c fiber.Ctx) U {
	var zero U
	if user, ok := c.Locals(LocalsUser).(U); ok {
		return user
	}
	return zero
}

// GetUserID returns the authenticated user's ID from the request context.
func GetUserID(c fiber.Ctx) uint {
	if id, ok := c.Locals(LocalsUserID).(uint); ok {
		return id
	}
	return 0
}

// GetAPIKey returns the authenticated API key from the request context.
func GetAPIKey(c fiber.Ctx) *APIKey {
	if key, ok := c.Locals(LocalsAPIKey).(*APIKey); ok {
		return key
	}
	return nil
}

// GetClaims returns the JWT claims from the request context.
func GetClaims(c fiber.Ctx) *Claims {
	if claims, ok := c.Locals(LocalsClaims).(*Claims); ok {
		return claims
	}
	return nil
}

// GetAuthType returns the authentication type used (jwt or apikey).
func GetAuthType(c fiber.Ctx) string {
	if authType, ok := c.Locals(LocalsAuthType).(string); ok {
		return authType
	}
	return ""
}

// IsAuthenticated returns true if the request is authenticated.
func IsAuthenticated(c fiber.Ctx) bool {
	return GetAuthType(c) != ""
}

// compile-time assertion to ensure jwt.Token is used
var _ = (*jwt.Token)(nil)
