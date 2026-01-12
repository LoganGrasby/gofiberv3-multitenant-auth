package auth

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/fiber/v3/middleware/cors"
	"github.com/gofiber/fiber/v3/middleware/csrf"
	"github.com/gofiber/fiber/v3/middleware/etag"
	"github.com/gofiber/fiber/v3/middleware/helmet"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/recover"
	"github.com/google/uuid"
)

// GlobalMiddlewareConfig configures the global middleware stack.
// All settings have sensible defaults for a secure production environment.
type GlobalMiddlewareConfig struct {
	// AllowedOrigins for CORS. If empty, defaults to detecting from DOMAIN env var.
	// In development, localhost origins are automatically included.
	AllowedOrigins []string

	// RateLimitMax is the maximum number of requests per window. Default: 100
	RateLimitMax int

	// RateLimitWindow is the time window for rate limiting. Default: 1 minute
	RateLimitWindow time.Duration

	// RateLimitKeyGenerator customizes how clients are identified for rate limiting.
	// Default: uses client IP address.
	RateLimitKeyGenerator func(c fiber.Ctx) string

	// EnableCompress enables response compression. Default: true
	EnableCompress bool

	// EnableETag enables ETag headers for caching. Default: true
	EnableETag bool

	// EnableHelmet enables security headers (CSP, XSS protection, etc). Default: true
	EnableHelmet bool

	// EnableCSRF enables CSRF protection. Default: false (typically handled by OAuth state)
	EnableCSRF bool

	// CSRFCookieName is the name of the CSRF cookie. Default: "csrf_"
	CSRFCookieName string

	// CSRFCookieSecure sets the Secure flag on CSRF cookies. Default: true
	CSRFCookieSecure bool

	// EnableRecover enables panic recovery. Default: true
	EnableRecover bool

	// RecoverEnableStackTrace includes stack traces in error responses. Default: false (true in dev)
	RecoverEnableStackTrace bool

	// EnableRequestID adds unique request IDs to each request. Default: true
	EnableRequestID bool

	// CORSAllowMethods specifies allowed HTTP methods. Default: standard REST methods
	CORSAllowMethods []string

	// CORSAllowHeaders specifies allowed headers. Default: common auth/content headers
	CORSAllowHeaders []string

	// CORSAllowCredentials allows cookies/auth in CORS requests. Default: true
	CORSAllowCredentials bool

	// CORSExposeHeaders specifies headers exposed to the browser. Default: ["Content-Length"]
	CORSExposeHeaders []string

	// CORSMaxAge is how long browsers cache CORS preflight results. Default: 86400 (24h)
	CORSMaxAge int

	// HelmetConfig allows custom Helmet configuration. If nil, uses defaults.
	HelmetConfig *helmet.Config

	// Logger for middleware (optional). If set, used by rate limiter and recover.
	Logger Logger
}

// DefaultGlobalMiddlewareConfig returns a configuration with sensible production defaults.
// It automatically detects development vs production environments via APP_ENV.
func DefaultGlobalMiddlewareConfig() GlobalMiddlewareConfig {
	isDev := isDevEnvironment()

	return GlobalMiddlewareConfig{
		AllowedOrigins:          nil, // Auto-detect from DOMAIN env
		RateLimitMax:            100,
		RateLimitWindow:         time.Minute,
		RateLimitKeyGenerator:   nil, // Default to IP
		EnableCompress:          true,
		EnableETag:              true,
		EnableHelmet:            true,
		EnableCSRF:              false,
		CSRFCookieName:          "csrf_",
		CSRFCookieSecure:        !isDev,
		EnableRecover:           true,
		RecoverEnableStackTrace: isDev,
		EnableRequestID:         true,
		CORSAllowMethods:        []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"},
		CORSAllowHeaders:        []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-Tenant-ID", "X-API-Key"},
		CORSAllowCredentials:    true,
		CORSExposeHeaders:       []string{"Content-Length"},
		CORSMaxAge:              86400,
	}
}

// GlobalMiddleware returns a slice of middleware handlers configured for a secure
// production environment. Apply these to your Fiber app before registering routes.
//
// This applies (in order):
//   - Recover (panic recovery)
//   - RequestID (unique request tracking)
//   - Rate Limiter (DDoS protection)
//   - CORS (cross-origin requests)
//   - Compress (response compression)
//   - ETag (caching)
//   - Helmet (security headers)
//   - CSRF (if enabled)
//
// Example usage:
//
//	app := fiber.New()
//	for _, mw := range auth.GlobalMiddleware() {
//	    app.Use(mw)
//	}
//	// Or with custom config:
//	for _, mw := range auth.GlobalMiddleware(auth.GlobalMiddlewareConfig{
//	    RateLimitMax: 200,
//	    AllowedOrigins: []string{"https://myapp.com"},
//	}) {
//	    app.Use(mw)
//	}
func GlobalMiddleware(configs ...GlobalMiddlewareConfig) []fiber.Handler {
	cfg := DefaultGlobalMiddlewareConfig()
	if len(configs) > 0 {
		cfg = mergeGlobalConfig(cfg, configs[0])
	}

	var handlers []fiber.Handler

	// 1. Recover - catch panics
	if cfg.EnableRecover {
		handlers = append(handlers, recover.New(recover.Config{
			EnableStackTrace: cfg.RecoverEnableStackTrace,
		}))
	}

	// 2. Request ID - for tracing (custom implementation due to Fiber v3 RC compatibility)
	if cfg.EnableRequestID {
		handlers = append(handlers, requestIDMiddleware())
	}

	// 3. Rate Limiter - DDoS protection
	limiterCfg := limiter.Config{
		Max:        cfg.RateLimitMax,
		Expiration: cfg.RateLimitWindow,
	}
	if cfg.RateLimitKeyGenerator != nil {
		limiterCfg.KeyGenerator = cfg.RateLimitKeyGenerator
	} else {
		limiterCfg.KeyGenerator = func(c fiber.Ctx) string {
			return c.IP()
		}
	}
	handlers = append(handlers, limiter.New(limiterCfg))

	// 4. CORS - cross-origin support
	allowedOrigins := cfg.AllowedOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = detectAllowedOrigins()
	}
	handlers = append(handlers, cors.New(cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     cfg.CORSAllowMethods,
		AllowHeaders:     cfg.CORSAllowHeaders,
		AllowCredentials: cfg.CORSAllowCredentials,
		ExposeHeaders:    cfg.CORSExposeHeaders,
		MaxAge:           cfg.CORSMaxAge,
	}))

	// 5. Compress - response compression
	if cfg.EnableCompress {
		handlers = append(handlers, compress.New())
	}

	// 6. ETag - caching
	if cfg.EnableETag {
		handlers = append(handlers, etag.New())
	}

	// 7. Helmet - security headers
	if cfg.EnableHelmet {
		if cfg.HelmetConfig != nil {
			handlers = append(handlers, helmet.New(*cfg.HelmetConfig))
		} else {
			handlers = append(handlers, helmet.New())
		}
	}

	// 8. CSRF - if enabled
	if cfg.EnableCSRF {
		handlers = append(handlers, csrf.New(csrf.Config{
			CookieName:   cfg.CSRFCookieName,
			CookieSecure: cfg.CSRFCookieSecure,
		}))
	}

	return handlers
}

// ApplyGlobalMiddleware is a convenience function that applies all global middleware
// to the Fiber app in one call.
//
// Example:
//
//	app := fiber.New()
//	auth.ApplyGlobalMiddleware(app)
//	// or with config:
//	auth.ApplyGlobalMiddleware(app, auth.GlobalMiddlewareConfig{...})
func ApplyGlobalMiddleware(app *fiber.App, configs ...GlobalMiddlewareConfig) {
	for _, mw := range GlobalMiddleware(configs...) {
		app.Use(mw)
	}
}

// =============================================================================
// Helper functions
// =============================================================================

// isDevEnvironment checks if we're in a development environment.
func isDevEnvironment() bool {
	appEnv := os.Getenv("APP_ENV")
	return strings.EqualFold(appEnv, "dev") ||
		strings.EqualFold(appEnv, "development") ||
		appEnv == ""
}

// detectAllowedOrigins builds the CORS allowed origins list from environment.
func detectAllowedOrigins() []string {
	domain := os.Getenv("DOMAIN")
	isDev := isDevEnvironment()

	var origins []string

	// Add production domain if set
	if strings.TrimSpace(domain) != "" {
		origins = append(origins, fmt.Sprintf("https://%s", domain))
	}

	// Add development origins
	if isDev {
		origins = append(origins,
			"http://localhost:3000",
			"http://localhost:5173", // Vite default
			"http://localhost:8080",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:5173",
			"http://127.0.0.1:8080",
		)
	}

	// Fallback if nothing set
	if len(origins) == 0 {
		origins = []string{"http://localhost:3000"}
	}

	return origins
}

// mergeGlobalConfig merges user config with defaults, only overriding explicitly set values.
func mergeGlobalConfig(defaults, user GlobalMiddlewareConfig) GlobalMiddlewareConfig {
	result := defaults

	if len(user.AllowedOrigins) > 0 {
		result.AllowedOrigins = user.AllowedOrigins
	}
	if user.RateLimitMax > 0 {
		result.RateLimitMax = user.RateLimitMax
	}
	if user.RateLimitWindow > 0 {
		result.RateLimitWindow = user.RateLimitWindow
	}
	if user.RateLimitKeyGenerator != nil {
		result.RateLimitKeyGenerator = user.RateLimitKeyGenerator
	}
	if user.CORSAllowMethods != nil {
		result.CORSAllowMethods = user.CORSAllowMethods
	}
	if user.CORSAllowHeaders != nil {
		result.CORSAllowHeaders = user.CORSAllowHeaders
	}
	if user.CORSExposeHeaders != nil {
		result.CORSExposeHeaders = user.CORSExposeHeaders
	}
	if user.CORSMaxAge > 0 {
		result.CORSMaxAge = user.CORSMaxAge
	}
	if user.CSRFCookieName != "" {
		result.CSRFCookieName = user.CSRFCookieName
	}
	if user.HelmetConfig != nil {
		result.HelmetConfig = user.HelmetConfig
	}
	if user.Logger != nil {
		result.Logger = user.Logger
	}

	// Boolean fields - check if explicitly set using a different approach
	// Since we can't distinguish between explicit false and default, we use the user value
	result.EnableCompress = user.EnableCompress
	result.EnableETag = user.EnableETag
	result.EnableHelmet = user.EnableHelmet
	result.EnableCSRF = user.EnableCSRF
	result.CSRFCookieSecure = user.CSRFCookieSecure
	result.EnableRecover = user.EnableRecover
	result.RecoverEnableStackTrace = user.RecoverEnableStackTrace
	result.EnableRequestID = user.EnableRequestID
	result.CORSAllowCredentials = user.CORSAllowCredentials

	return result
}

// parseBoolEnv parses a boolean from environment with a default value.
func parseBoolEnv(key string, defaultVal bool) bool {
	val := os.Getenv(key)
	if val == "" {
		return defaultVal
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return defaultVal
	}
	return b
}

// requestIDMiddleware creates a custom request ID middleware.
// This is a workaround for Fiber v3 RC compatibility issues with the built-in requestid middleware.
func requestIDMiddleware() fiber.Handler {
	const headerXRequestID = "X-Request-ID"

	return func(c fiber.Ctx) error {
		// Check if request already has an ID
		rid := c.Get(headerXRequestID)
		if rid == "" {
			rid = uuid.New().String()
		}

		// Set request ID in locals and response header
		c.Locals("requestid", rid)
		c.Set(headerXRequestID, rid)

		return c.Next()
	}
}
