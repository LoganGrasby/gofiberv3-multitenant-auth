An sqlite based multi-tenant auth library for Fiber v3.

# GoFiber Auth

A comprehensive, multi-tenant authentication and authorization system for Go Fiber v3 applications. This library provides a robust foundation for building secure web applications with support for OAuth, JWT, API Keys, and granular permission controls using Casbin.

## Features

- **Multi-Tenancy Support**: Built-in tenant isolation with separate SQLite databases per tenant.
- **Authentication Strategies**:
  - **Email/Password**: Secure bcrypt hashing.
  - **OAuth2**: Native support for Google and GitHub providers.
  - **API Keys**: Manageable API keys for machine-to-machine access.
- **Authorization**:
  - **Role-Based Access Control (RBAC)**: Assign roles to users.
  - **Attribute-Based Access Control (ABAC)**: Fine-grained permissions using Casbin.
- **Session Management**: Secure session handling with configurable storage (in-memory by default).
- **Security**:
  - CSRF protection (via state tokens in OAuth).
  - Secure defaults for cookies (HTTPOnly, Secure, SameSite).
  - JWT Access and Refresh token rotation.
- **Easy Integration**: seamless middleware for Fiber v3.

## Installation

```bash
go get github.com/logangrasby/gofiberv3-multitenant-auth
```

## Quick Start

### Option 1: Simple Setup (Recommended)

Use `RegisterRoutes()` to set up all auth endpoints with one line:

```go
package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func main() {
	// 1. Create Auth Service (uses default User model)
	authService, err := auth.New(auth.Config{
		DatabaseDir:         "./data/tenants",
		JWTSecret:           []byte("your-super-secret-key-min-32-chars!!"),
		JWTAccessExpiration: 15 * time.Minute,
		TenantExtractor:     extractors.FromHeader("X-Tenant-ID"),
	})
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}
	defer authService.Close()

	// 2. Create Fiber App
	app := fiber.New()

	// 3. Register all auth routes with one line!
	authService.RegisterRoutes(app, auth.RouterConfig{
		Prefix: "/api",
	})

	// 4. Start Server
	log.Fatal(app.Listen(":3000"))
}
```

### Option 2: Custom User Model

The library supports custom user models using Go generics. Define your own model by embedding `auth.BaseUser`:

```go
package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

// CustomUser extends BaseUser with application-specific fields
type CustomUser struct {
	auth.BaseUser
	OrganizationID uint   `json:"organization_id"`
	Department     string `json:"department"`
	EmployeeID     string `json:"employee_id"`
}

func main() {
	// Create Auth Service with custom user model
	authService, err := auth.NewWithModel[*CustomUser](auth.Config{
		DatabaseDir:         "./data/tenants",
		JWTSecret:           []byte("your-super-secret-key-min-32-chars!!"),
		JWTAccessExpiration: 15 * time.Minute,
		TenantExtractor:     extractors.FromHeader("X-Tenant-ID"),
	})
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}
	defer authService.Close()

	app := fiber.New()

	// Routes work the same way
	authService.RegisterRoutes(app, auth.RouterConfig{
		Prefix: "/api",
	})

	// Access custom fields in handlers
	api := app.Group("/api", authService.TenantMiddleware())
	protected := api.Group("", authService.AuthMiddleware())

	protected.Get("/profile", func(c fiber.Ctx) error {
		// Use GetUserAs to get your custom type
		user := auth.GetUserAs[*CustomUser](c)
		if user == nil {
			return c.Status(401).JSON(fiber.Map{"error": "unauthorized"})
		}

		return c.JSON(fiber.Map{
			"email":           user.GetEmail(),
			"organization_id": user.OrganizationID,
			"department":      user.Department,
			"employee_id":     user.EmployeeID,
		})
	})

	log.Fatal(app.Listen(":3000"))
}
```

The custom user model is automatically migrated to the database, including any additional fields you define.

### Option 3: Custom Route Registration

For more control, use handler groups:

```go
package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/extractors"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func main() {
	authService, err := auth.New(auth.Config{
		DatabaseDir:         "./data/tenants",
		JWTSecret:           []byte("your-super-secret-key-min-32-chars!!"),
		JWTAccessExpiration: 15 * time.Minute,
		TenantExtractor:     extractors.FromHeader("X-Tenant-ID"),
	})
	if err != nil {
		log.Fatalf("Failed to create auth service: %v", err)
	}
	defer authService.Close()

	app := fiber.New()
	api := app.Group("/api", authService.TenantMiddleware())

	// Use handler groups for organized access
	authHandlers := authService.Auth()
	oauthHandlers := authService.OAuth()
	apiKeyHandlers := authService.APIKeys()

	// Public routes
	api.Post("/auth/register", authHandlers.Register())
	api.Post("/auth/login", authHandlers.Login())
	api.Post("/auth/refresh", authHandlers.Refresh())

	// OAuth routes
	api.Get("/auth/google/redirect", oauthHandlers.Redirect("google"))
	api.Get("/auth/google/callback", oauthHandlers.Callback("google"))

	// Protected routes
	protected := api.Group("", authService.AuthMiddleware())
	protected.Get("/me", authHandlers.Me())
	protected.Post("/auth/change-password", authHandlers.ChangePassword())

	// API key management (JWT only)
	keys := api.Group("/api-keys", authService.JWTMiddleware())
	keys.Post("/", apiKeyHandlers.Create())
	keys.Get("/", apiKeyHandlers.List())

	log.Fatal(app.Listen(":3000"))
}
```

### Option 4: With Casbin Authorization

```go
// Register routes with Casbin enabled (authorizer created automatically)
authService.RegisterRoutes(app, auth.RouterConfig{
	Prefix:       "/api",
	EnableCasbin: true,
})

// Access the authorizer for custom route middleware
authorizer, _ := authService.Authorizer()
protected.Get("/blog", authorizer.RequiresPermissions([]string{"blog:read"}), handler)

// Or use Casbin handler groups
casbinHandlers := authorizer.Handlers()
protected.Get("/permissions/me", casbinHandlers.GetMyPermissions())
```

## Custom User Models

The library uses Go generics to support custom user models. This lets you add application-specific fields while inheriting all authentication functionality.

### UserModel Interface

Any custom model must implement the `UserModel` interface by embedding `auth.BaseUser`:

```go
type UserModel interface {
	GetID() uint
	GetEmail() string
	GetPasswordHash() string
	SetPasswordHash(hash string)
	GetName() string
	GetRole() string
	SetRole(role string)
	IsActive() bool
	SetActive(active bool)
	GetLastLoginAt() *time.Time
	SetLastLoginAt(t *time.Time)
}
```

By embedding `auth.BaseUser`, your custom model automatically satisfies this interface.

### Context Helpers

The library provides several helpers to access the authenticated user:

| Helper | Return Type | Description |
|--------|-------------|-------------|
| `GetUser(c)` | `*User` | Get user as default `*User` type |
| `GetUserAs[T](c)` | `T` | Get user as custom type (generic) |
| `GetUserModel(c)` | `UserModel` | Get user as interface |
| `GetUserID(c)` | `uint` | Get just the user ID |

```go
// Default user model
user := auth.GetUser(c)

// Custom user model
customUser := auth.GetUserAs[*MyCustomUser](c)

// Interface access (works with any model)
userModel := auth.GetUserModel(c)
email := userModel.GetEmail()
```

## Configuration

### Service Config

The `auth.Config` struct controls the behavior of the authentication service.

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `DatabaseDir` | `string` | Location for tenant SQLite databases. | required |
| `TenantExtractor` | `extractors.Extractor` | Logic to extract tenant ID from request. | required |
| `JWTSecret` | `[]byte` | Secret key for signing JWTs (min 32 bytes). | required |
| `JWTAccessExpiration` | `time.Duration` | Lifespan of access tokens. | 15m |
| `JWTRefreshExpiration` | `time.Duration` | Lifespan of refresh tokens. | 7d |
| `AllowTenantCreation` | `bool` | Auto-create DB for new tenants. | `true` |
| `APIKeyPrefix` | `string` | Prefix for generated API keys. | `"sk_"` |
| `APIKeyLength` | `int` | Length of generated API keys (bytes). | `32` |
| `BcryptCost` | `int` | Cost factor for password hashing. | `12` |
| `CookieSecure` | `bool` | HTTPS only cookies. | `true` |
| `CookieHTTPOnly` | `bool` | No JS access to cookies. | `true` |
| `CookieSameSite` | `string` | Cookie SameSite attribute. | `"Lax"` |
| `GoogleOAuth` | `*OAuthProviderConfig` | Google OAuth configuration. | `nil` |
| `GitHubOAuth` | `*OAuthProviderConfig` | GitHub OAuth configuration. | `nil` |
| `OAuthSuccessRedirect` | `string` | Redirect after success. | `"/"` |
| `OAuthErrorRedirect` | `string` | Redirect after error. | `"/login..."` |

### Router Config

The `auth.RouterConfig` struct configures route registration:

| Field | Type | Description | Default |
|-------|------|-------------|---------|
| `Prefix` | `string` | Base path for all routes | `""` |
| `AuthPrefix` | `string` | Path prefix for auth routes | `"/auth"` |
| `APIKeyPrefix` | `string` | Path prefix for API key routes | `"/api-keys"` |
| `EnableOAuth` | `*bool` | Enable OAuth routes | `true` |
| `EnableAPIKeys` | `*bool` | Enable API key routes | `true` |
| `EnableCasbin` | `bool` | Enable Casbin authorization routes | `false` |
| `Authorizer` | `*Authorizer` | Required when EnableCasbin is true | `nil` |
| `AdminRole` | `string` | Role required for admin routes | `"admin"` |
| `CasbinPolicyPrefix` | `string` | Prefix for policy routes | `"/policies"` |
| `CasbinRolePrefix` | `string` | Prefix for role routes | `"/roles"` |

## Handler Groups

The library organizes handlers into logical groups for better discoverability:

```go
// Authentication handlers
authHandlers := authService.Auth()
authHandlers.Register()      // POST /auth/register
authHandlers.Login()         // POST /auth/login
authHandlers.Refresh()       // POST /auth/refresh
authHandlers.Logout()        // POST /auth/logout
authHandlers.LogoutAll()     // POST /auth/logout-all
authHandlers.Me()            // GET /me
authHandlers.ChangePassword() // POST /auth/change-password

// OAuth handlers
oauthHandlers := authService.OAuth()
oauthHandlers.Redirect("google")    // GET /auth/google/redirect
oauthHandlers.Callback("google")    // GET /auth/google/callback
oauthHandlers.ListProviders()       // GET /auth/providers
oauthHandlers.UnlinkProvider()      // DELETE /auth/providers/:provider
oauthHandlers.LinkRedirect("github") // GET /auth/providers/github/link

// API Key handlers
apiKeyHandlers := authService.APIKeys()
apiKeyHandlers.Create()  // POST /api-keys
apiKeyHandlers.List()    // GET /api-keys
apiKeyHandlers.Revoke()  // POST /api-keys/:id/revoke
apiKeyHandlers.Delete()  // DELETE /api-keys/:id

// Casbin handlers (via Authorizer)
casbinHandlers := authorizer.Handlers()
casbinHandlers.ListPolicies()      // GET /policies
casbinHandlers.AddPolicy()         // POST /policies
casbinHandlers.AssignRole()        // POST /roles/assign
casbinHandlers.GetMyPermissions()  // GET /permissions/me
casbinHandlers.CheckPermission()   // POST /permissions/check
```

## Project Structure

```
auth/
├── service.go          # Core Service and business logic
├── config.go           # Configuration
├── models.go           # Database models
├── router.go           # RegisterRoutes() and handler group accessors
├── middleware.go       # Authentication middleware
├── handlers.go         # Auth and API key HTTP handlers
├── oauth_handlers.go   # OAuth HTTP handlers
├── casbin_handlers.go  # Casbin authorization handlers
├── handlers/           # Handler group structs
│   ├── auth.go         # AuthHandlers group
│   ├── apikeys.go      # APIKeyHandlers group
│   ├── oauth.go        # OAuthHandlers group
│   └── casbin.go       # CasbinHandlers group
└── types/              # Request/Response DTOs
    ├── requests.go     # All request types
    └── responses.go    # All response types
```

## API Documentation

The library exposes standard handlers for integration:

### Authentication
- `POST /api/auth/register`: Create a new user.
- `POST /api/auth/login`: Authenticate with email/password.
- `POST /api/auth/refresh`: Refresh an expired access token.
- `POST /api/auth/logout`: Revoke tokens and clear session.

### User Management
- `GET /api/me`: Get current user profile.
- `POST /api/auth/change-password`: Update password.

### OAuth
- `GET /api/auth/:provider/redirect`: Initiate OAuth flow.
- `GET /api/auth/:provider/callback`: Handle provider callback.

### Authorization (Casbin)
- `POST /api/permissions/check`: Check if user has permission.
- `GET /api/permissions/me`: Get all permissions for user.

## License

MIT
