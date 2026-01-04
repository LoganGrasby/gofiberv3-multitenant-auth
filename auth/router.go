package auth

import (
	"github.com/gofiber/fiber/v3"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth/handlers"
)

// RouterConfig configures route registration behavior.
type RouterConfig struct {
	// Prefix is the base path for all auth routes (default: "").
	// Example: "/api" results in routes like "/api/auth/login".
	Prefix string

	// AuthPrefix is the path prefix for authentication routes (default: "/auth").
	// Combined with Prefix, "/api" + "/auth" = "/api/auth/login".
	AuthPrefix string

	// APIKeyPrefix is the path prefix for API key routes (default: "/api-keys").
	APIKeyPrefix string

	// EnableOAuth enables OAuth routes (default: true if OAuth is configured).
	EnableOAuth *bool

	// EnableAPIKeys enables API key management routes (default: true).
	EnableAPIKeys *bool

	// EnableCasbin enables Casbin authorization routes (default: false).
	// If true and Authorizer is nil, one is created automatically.
	EnableCasbin bool

	// Authorizer for Casbin routes. If nil and EnableCasbin is true,
	// one is created automatically with default configuration.
	// Access it later via service.Authorizer().
	Authorizer *Authorizer

	// CasbinPolicyPrefix is the path prefix for policy routes (default: "/policies").
	CasbinPolicyPrefix string

	// CasbinRolePrefix is the path prefix for role routes (default: "/roles").
	CasbinRolePrefix string

	// AdminRole is the role required to access admin routes (default: "admin").
	AdminRole string
}

// DefaultRouterConfig returns a RouterConfig with sensible defaults.
func DefaultRouterConfig() RouterConfig {
	enableTrue := true
	return RouterConfig{
		Prefix:             "",
		AuthPrefix:         "/auth",
		APIKeyPrefix:       "/api-keys",
		EnableOAuth:        &enableTrue,
		EnableAPIKeys:      &enableTrue,
		EnableCasbin:       false,
		CasbinPolicyPrefix: "/policies",
		CasbinRolePrefix:   "/roles",
		AdminRole:          "admin",
	}
}

// applyDefaults fills in any unset values with defaults.
func (c *RouterConfig) applyDefaults() {
	defaults := DefaultRouterConfig()
	if c.AuthPrefix == "" {
		c.AuthPrefix = defaults.AuthPrefix
	}
	if c.APIKeyPrefix == "" {
		c.APIKeyPrefix = defaults.APIKeyPrefix
	}
	if c.EnableOAuth == nil {
		c.EnableOAuth = defaults.EnableOAuth
	}
	if c.EnableAPIKeys == nil {
		c.EnableAPIKeys = defaults.EnableAPIKeys
	}
	if c.CasbinPolicyPrefix == "" {
		c.CasbinPolicyPrefix = defaults.CasbinPolicyPrefix
	}
	if c.CasbinRolePrefix == "" {
		c.CasbinRolePrefix = defaults.CasbinRolePrefix
	}
	if c.AdminRole == "" {
		c.AdminRole = defaults.AdminRole
	}
}

// RegisterRoutes registers all authentication routes on the provided router.
// This is the simplest way to set up all auth endpoints with sensible defaults.
//
// Example usage:
//
//	app := fiber.New()
//	authService, _ := auth.New(config)
//
//	// Simple: register all routes with defaults
//	authService.RegisterRoutes(app)
//
//	// Or with custom configuration:
//	authService.RegisterRoutes(app, auth.RouterConfig{
//	    Prefix: "/api/v1",
//	    EnableCasbin: true,
//	    Authorizer: authorizer,
//	})
func (s *Service) RegisterRoutes(router fiber.Router, configs ...RouterConfig) {
	cfg := DefaultRouterConfig()
	if len(configs) > 0 {
		cfg = configs[0]
		cfg.applyDefaults()
	}

	// Create base group with tenant middleware
	var base fiber.Router
	if cfg.Prefix != "" {
		base = router.Group(cfg.Prefix, s.TenantMiddleware())
	} else {
		base = router.Group("", s.TenantMiddleware())
	}

	// Register auth routes
	s.registerAuthRoutes(base, cfg)

	// Register OAuth routes if enabled
	if *cfg.EnableOAuth && (s.IsOAuthConfigured("google") || s.IsOAuthConfigured("github")) {
		s.registerOAuthRoutes(base, cfg)
	}

	// Register API key routes if enabled
	if *cfg.EnableAPIKeys {
		s.registerAPIKeyRoutes(base, cfg)
	}

	// Register Casbin routes if enabled
	if cfg.EnableCasbin {
		// Auto-create authorizer if not provided
		if cfg.Authorizer == nil {
			authorizer, err := s.Authorizer()
			if err == nil {
				cfg.Authorizer = authorizer
			}
		}
		if cfg.Authorizer != nil {
			s.registerCasbinRoutes(base, cfg)
		}
	}
}

// registerAuthRoutes registers the core authentication routes.
func (s *Service) registerAuthRoutes(router fiber.Router, cfg RouterConfig) {
	auth := router.Group(cfg.AuthPrefix)

	// Public routes
	auth.Post("/register", s.RegisterHandler())
	auth.Post("/login", s.LoginHandler())
	auth.Post("/refresh", s.RefreshHandler())
	auth.Post("/logout", s.LogoutHandler())

	// Protected routes
	protected := router.Group("", s.AuthMiddleware())
	protected.Get("/me", s.MeHandler())
	protected.Post(cfg.AuthPrefix+"/logout-all", s.LogoutAllHandler())
	protected.Post(cfg.AuthPrefix+"/change-password", s.ChangePasswordHandler())
}

// registerOAuthRoutes registers OAuth authentication routes.
func (s *Service) registerOAuthRoutes(router fiber.Router, cfg RouterConfig) {
	// OAuth routes need session middleware for CSRF state management
	auth := router.Group(cfg.AuthPrefix, s.SessionMiddleware())

	// Public OAuth routes
	auth.Get("/:provider/redirect", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return s.OAuthRedirectHandler(provider)(c)
	})
	auth.Get("/:provider/callback", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return s.OAuthCallbackHandler(provider)(c)
	})

	// Protected OAuth management routes (also need session for linking)
	protected := router.Group("", s.AuthMiddleware(), s.SessionMiddleware())
	protected.Get(cfg.AuthPrefix+"/providers", s.ListOAuthProvidersHandler())
	protected.Delete(cfg.AuthPrefix+"/providers/:provider", s.UnlinkOAuthProviderHandler())

	// Link new OAuth provider
	protected.Get(cfg.AuthPrefix+"/providers/:provider/link", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return s.LinkOAuthRedirectHandler(provider)(c)
	})
	protected.Get(cfg.AuthPrefix+"/providers/:provider/callback", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return s.LinkOAuthCallbackHandler(provider)(c)
	})
}

// registerAPIKeyRoutes registers API key management routes.
func (s *Service) registerAPIKeyRoutes(router fiber.Router, cfg RouterConfig) {
	// API key routes require JWT auth (not API key auth)
	apiKeys := router.Group(cfg.APIKeyPrefix, s.JWTMiddleware())
	apiKeys.Post("/", s.CreateAPIKeyHandler())
	apiKeys.Get("/", s.ListAPIKeysHandler())
	apiKeys.Post("/:id/revoke", s.RevokeAPIKeyHandler())
	apiKeys.Delete("/:id", s.DeleteAPIKeyHandler())
}

// registerCasbinRoutes registers Casbin authorization routes.
func (s *Service) registerCasbinRoutes(router fiber.Router, cfg RouterConfig) {
	authorizer := cfg.Authorizer

	// Protected permission routes
	protected := router.Group("", s.AuthMiddleware())
	protected.Get("/permissions/me", authorizer.GetMyPermissionsHandler())
	protected.Post("/permissions/check", authorizer.CheckPermissionHandler())

	// Admin policy routes
	policies := router.Group(cfg.CasbinPolicyPrefix, s.JWTMiddleware(), RequireRole(cfg.AdminRole))
	policies.Get("/", authorizer.ListPoliciesHandler())
	policies.Post("/", authorizer.AddPolicyHandler())
	policies.Delete("/", authorizer.RemovePolicyHandler())
	policies.Post("/bulk", authorizer.AddBulkPoliciesHandler())
	policies.Delete("/clear", authorizer.ClearPoliciesHandler())
	policies.Post("/reload", authorizer.ReloadPoliciesHandler())
	policies.Post("/role", authorizer.AddRolePolicyHandler())

	// Admin role routes
	roles := router.Group(cfg.CasbinRolePrefix, s.JWTMiddleware(), RequireRole(cfg.AdminRole))
	roles.Post("/assign", authorizer.AssignRoleHandler())
	roles.Post("/remove", authorizer.RemoveRoleHandler())
	roles.Get("/user/:id", authorizer.GetUserRolesHandler())
	roles.Get("/:role/users", authorizer.GetRoleUsersHandler())
	roles.Get("/user/:id/permissions", authorizer.GetUserPermissionsHandler())
}

// =============================================================================
// Handler Group Accessors
// =============================================================================

// Auth returns the grouped authentication handlers for custom route registration.
// Use this when you need more control over route setup than RegisterRoutes provides.
//
// Example:
//
//	auth := authService.Auth()
//	app.Post("/custom/register", auth.Register())
//	app.Post("/custom/login", auth.Login())
func (s *Service) Auth() *handlers.AuthHandlers {
	return handlers.NewAuthHandlers(s)
}

// APIKeys returns the grouped API key handlers for custom route registration.
//
// Example:
//
//	apiKeys := authService.APIKeys()
//	app.Post("/keys", apiKeys.Create())
//	app.Get("/keys", apiKeys.List())
func (s *Service) APIKeys() *handlers.APIKeyHandlers {
	return handlers.NewAPIKeyHandlers(s)
}

// OAuth returns the grouped OAuth handlers for custom route registration.
//
// Example:
//
//	oauth := authService.OAuth()
//	app.Get("/sso/google", oauth.Redirect("google"))
//	app.Get("/sso/google/callback", oauth.Callback("google"))
func (s *Service) OAuth() *handlers.OAuthHandlers {
	return handlers.NewOAuthHandlers(s)
}

// Handlers returns the grouped Casbin authorization handlers.
// Call this on an Authorizer instance.
//
// Example:
//
//	casbin := authorizer.Handlers()
//	app.Get("/perms", casbin.ListPolicies())
func (a *Authorizer) Handlers() *handlers.CasbinHandlers {
	return handlers.NewCasbinHandlers(a)
}

// =============================================================================
// Route Information (for documentation/introspection)
// =============================================================================

// RouteInfo describes a registered route.
type RouteInfo struct {
	Method      string
	Path        string
	Handler     string
	Auth        string // "public", "jwt", "apikey", "any", "admin"
	Description string
}

// Routes returns information about all routes that would be registered.
// Useful for documentation generation or API introspection.
func (s *Service) Routes(configs ...RouterConfig) []RouteInfo {
	cfg := DefaultRouterConfig()
	if len(configs) > 0 {
		cfg = configs[0]
		cfg.applyDefaults()
	}

	prefix := cfg.Prefix
	authPrefix := prefix + cfg.AuthPrefix

	routes := []RouteInfo{
		// Auth routes
		{Method: "POST", Path: authPrefix + "/register", Handler: "RegisterHandler", Auth: "public", Description: "Register a new user"},
		{Method: "POST", Path: authPrefix + "/login", Handler: "LoginHandler", Auth: "public", Description: "Login and get tokens"},
		{Method: "POST", Path: authPrefix + "/refresh", Handler: "RefreshHandler", Auth: "public", Description: "Refresh access token"},
		{Method: "POST", Path: authPrefix + "/logout", Handler: "LogoutHandler", Auth: "public", Description: "Logout current session"},
		{Method: "GET", Path: prefix + "/me", Handler: "MeHandler", Auth: "any", Description: "Get current user profile"},
		{Method: "POST", Path: authPrefix + "/logout-all", Handler: "LogoutAllHandler", Auth: "any", Description: "Logout all sessions"},
		{Method: "POST", Path: authPrefix + "/change-password", Handler: "ChangePasswordHandler", Auth: "any", Description: "Change password"},
	}

	// OAuth routes
	if *cfg.EnableOAuth {
		routes = append(routes,
			RouteInfo{Method: "GET", Path: authPrefix + "/:provider/redirect", Handler: "OAuthRedirectHandler", Auth: "public", Description: "Start OAuth flow"},
			RouteInfo{Method: "GET", Path: authPrefix + "/:provider/callback", Handler: "OAuthCallbackHandler", Auth: "public", Description: "OAuth callback"},
			RouteInfo{Method: "GET", Path: authPrefix + "/providers", Handler: "ListOAuthProvidersHandler", Auth: "any", Description: "List linked OAuth providers"},
			RouteInfo{Method: "DELETE", Path: authPrefix + "/providers/:provider", Handler: "UnlinkOAuthProviderHandler", Auth: "any", Description: "Unlink OAuth provider"},
			RouteInfo{Method: "GET", Path: authPrefix + "/providers/:provider/link", Handler: "LinkOAuthRedirectHandler", Auth: "any", Description: "Link new OAuth provider"},
			RouteInfo{Method: "GET", Path: authPrefix + "/providers/:provider/callback", Handler: "LinkOAuthCallbackHandler", Auth: "any", Description: "OAuth link callback"},
		)
	}

	// API key routes
	if *cfg.EnableAPIKeys {
		apiKeyPrefix := prefix + cfg.APIKeyPrefix
		routes = append(routes,
			RouteInfo{Method: "POST", Path: apiKeyPrefix, Handler: "CreateAPIKeyHandler", Auth: "jwt", Description: "Create API key"},
			RouteInfo{Method: "GET", Path: apiKeyPrefix, Handler: "ListAPIKeysHandler", Auth: "jwt", Description: "List API keys"},
			RouteInfo{Method: "POST", Path: apiKeyPrefix + "/:id/revoke", Handler: "RevokeAPIKeyHandler", Auth: "jwt", Description: "Revoke API key"},
			RouteInfo{Method: "DELETE", Path: apiKeyPrefix + "/:id", Handler: "DeleteAPIKeyHandler", Auth: "jwt", Description: "Delete API key"},
		)
	}

	// Casbin routes
	if cfg.EnableCasbin {
		policyPrefix := prefix + cfg.CasbinPolicyPrefix
		rolePrefix := prefix + cfg.CasbinRolePrefix
		routes = append(routes,
			RouteInfo{Method: "GET", Path: prefix + "/permissions/me", Handler: "GetMyPermissionsHandler", Auth: "any", Description: "Get my permissions"},
			RouteInfo{Method: "POST", Path: prefix + "/permissions/check", Handler: "CheckPermissionHandler", Auth: "any", Description: "Check permission"},
			RouteInfo{Method: "GET", Path: policyPrefix, Handler: "ListPoliciesHandler", Auth: "admin", Description: "List policies"},
			RouteInfo{Method: "POST", Path: policyPrefix, Handler: "AddPolicyHandler", Auth: "admin", Description: "Add policy"},
			RouteInfo{Method: "DELETE", Path: policyPrefix, Handler: "RemovePolicyHandler", Auth: "admin", Description: "Remove policy"},
			RouteInfo{Method: "POST", Path: policyPrefix + "/bulk", Handler: "AddBulkPoliciesHandler", Auth: "admin", Description: "Add bulk policies"},
			RouteInfo{Method: "DELETE", Path: policyPrefix + "/clear", Handler: "ClearPoliciesHandler", Auth: "admin", Description: "Clear all policies"},
			RouteInfo{Method: "POST", Path: policyPrefix + "/reload", Handler: "ReloadPoliciesHandler", Auth: "admin", Description: "Reload policies"},
			RouteInfo{Method: "POST", Path: policyPrefix + "/role", Handler: "AddRolePolicyHandler", Auth: "admin", Description: "Add role policy"},
			RouteInfo{Method: "POST", Path: rolePrefix + "/assign", Handler: "AssignRoleHandler", Auth: "admin", Description: "Assign role"},
			RouteInfo{Method: "POST", Path: rolePrefix + "/remove", Handler: "RemoveRoleHandler", Auth: "admin", Description: "Remove role"},
			RouteInfo{Method: "GET", Path: rolePrefix + "/user/:id", Handler: "GetUserRolesHandler", Auth: "admin", Description: "Get user roles"},
			RouteInfo{Method: "GET", Path: rolePrefix + "/:role/users", Handler: "GetRoleUsersHandler", Auth: "admin", Description: "Get role users"},
			RouteInfo{Method: "GET", Path: rolePrefix + "/user/:id/permissions", Handler: "GetUserPermissionsHandler", Auth: "admin", Description: "Get user permissions"},
		)
	}

	return routes
}
