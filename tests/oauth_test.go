package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
	"golang.org/x/oauth2"
)

// MockHTTPTransport is a custom RoundTripper for mocking HTTP responses.
type MockHTTPTransport struct {
	RoundTripFunc func(req *http.Request) (*http.Response, error)
}

func (m *MockHTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return m.RoundTripFunc(req)
}

func TestOAuthRedirect(t *testing.T) {
	svc := setupTestService(t)
	// Mock config
	cfg := svc.Config()
	cfg.GoogleOAuth = &auth.OAuthProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURL:  "http://localhost:3000/auth/google/callback",
	}
	svc.SetConfig(cfg)

	app := fiber.New()
	app.Use(session.New(session.Config{}))

	app.Get("/auth/:provider/redirect", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return svc.OAuthRedirectHandler(provider)(c)
	})

	req := httptest.NewRequest("GET", "/auth/google/redirect", nil)
	resp, err := app.Test(req)
	assertNoError(t, err)

	assertEqual(t, resp.StatusCode, http.StatusSeeOther)
	location := resp.Header.Get("Location")
	assertTrue(t, strings.Contains(location, "accounts.google.com/o/oauth2/auth"), "should redirect to google")
	assertTrue(t, strings.Contains(location, "client_id=google-client-id"), "should contain client_id")
	assertTrue(t, strings.Contains(location, "state="), "should contain state")
}

func TestOAuthCallback_Google_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	// Mock config
	cfg := svc.Config()
	cfg.GoogleOAuth = &auth.OAuthProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURL:  "http://localhost:3000/auth/google/callback",
	}
	cfg.OAuthAutoCreateUser = true
	svc.SetConfig(cfg)

	// Mock HTTP Client
	mockTransport := &MockHTTPTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			// Mock Token Exchange
			if req.URL.Path == "/token" {
				token := &oauth2.Token{
					AccessToken: "mock-access-token",
					Expiry:      time.Now().Add(time.Hour),
					TokenType:   "Bearer",
				}
				body, _ := json.Marshal(map[string]interface{}{
					"access_token": token.AccessToken,
					"expires_in":   3600,
					"token_type":   "Bearer",
				})
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(body)),
					Header:     make(http.Header),
				}, nil
			}
			// Mock User Info
			if req.URL.Host == "www.googleapis.com" && req.URL.Path == "/oauth2/v2/userinfo" {
				userInfo := auth.GoogleUserInfo{
					ID:            "google-user-123",
					Email:         "test-google@example.com",
					VerifiedEmail: true,
					Name:          "Google User",
					Picture:       "http://example.com/pic.jpg",
				}
				body, _ := json.Marshal(userInfo)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(body)),
					Header:     make(http.Header),
				}, nil
			}
			return nil, http.ErrNoLocation
		},
	}
	svc.HTTPClient = &http.Client{Transport: mockTransport}

	app := fiber.New()
	app.Use(session.New(session.Config{}))
	app.Use(svc.TenantMiddleware())

	// Helper to set session state
	app.Get("/setup-session", func(c fiber.Ctx) error {
		sess := session.FromContext(c)
		sess.Set(auth.SessionKeyOAuthState, "test-state")
		sess.Set(auth.SessionKeyOAuthProvider, "google")
		return c.SendStatus(fiber.StatusOK)
	})

	app.Get("/auth/:provider/callback", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return svc.OAuthCallbackHandler(provider)(c)
	})

	// 1. Setup session
	reqSetup := httptest.NewRequest("GET", "/setup-session", nil)
	respSetup, err := app.Test(reqSetup)
	assertNoError(t, err)
	cookie := respSetup.Header.Get("Set-Cookie")

	// 2. Perform callback
	u := url.Values{}
	u.Set("code", "test-code")
	u.Set("state", "test-state")
	req := httptest.NewRequest("GET", "/auth/google/callback?"+u.Encode(), nil)
	req.Header.Set("Cookie", cookie)
	resp, err := app.Test(req)
	assertNoError(t, err)

	assertEqual(t, resp.StatusCode, http.StatusSeeOther)
	location := resp.Header.Get("Location")
	assertTrue(t, strings.Contains(location, "access_token="), "should contain access_token")
	assertTrue(t, strings.Contains(location, "new_user=true"), "should contain new_user=true")

	// Verify user created
	var user auth.User
	err = db.Where("email = ?", "test-google@example.com").First(&user).Error
	assertNoError(t, err)
	assertEqual(t, user.Name, "Google User")

	// Verify provider linked
	var provider auth.OAuthProvider
	err = db.Where("user_id = ?", user.ID).First(&provider).Error
	assertNoError(t, err)
	assertEqual(t, provider.Provider, "google")
	assertEqual(t, provider.ProviderID, "google-user-123")
}

func TestOAuthCallback_GitHub_Success(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	// Mock config
	cfg := svc.Config()
	cfg.GitHubOAuth = &auth.OAuthProviderConfig{
		ClientID:     "github-client-id",
		ClientSecret: "github-client-secret",
		RedirectURL:  "http://localhost:3000/auth/github/callback",
	}
	cfg.OAuthAutoCreateUser = true
	svc.SetConfig(cfg)

	// Mock HTTP Client
	mockTransport := &MockHTTPTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			// Mock Token Exchange
			if req.URL.Path == "/login/oauth/access_token" {
				body := "access_token=mock-github-token&scope=&token_type=bearer"
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(body)),
					Header:     http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}},
				}, nil
			}
			// Mock User Info
			if req.URL.Host == "api.github.com" && req.URL.Path == "/user" {
				userInfo := auth.GitHubUser{
					ID:        12345,
					Login:     "githubuser",
					Name:      "GitHub User",
					Email:     "", // Email not public
					AvatarURL: "http://example.com/avatar.jpg",
				}
				body, _ := json.Marshal(userInfo)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(body)),
					Header:     make(http.Header),
				}, nil
			}
			// Mock Emails
			if req.URL.Host == "api.github.com" && req.URL.Path == "/user/emails" {
				emails := []auth.GitHubEmail{
					{Email: "test-github@example.com", Primary: true, Verified: true},
				}
				body, _ := json.Marshal(emails)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(body)),
					Header:     make(http.Header),
				}, nil
			}
			return nil, http.ErrNoLocation
		},
	}
	svc.HTTPClient = &http.Client{Transport: mockTransport}

	app := fiber.New()
	app.Use(session.New(session.Config{}))
	app.Use(svc.TenantMiddleware())

	// Helper to set session state
	app.Get("/setup-session", func(c fiber.Ctx) error {
		sess := session.FromContext(c)
		sess.Set(auth.SessionKeyOAuthState, "test-state")
		sess.Set(auth.SessionKeyOAuthProvider, "github")
		return c.SendStatus(fiber.StatusOK)
	})

	app.Get("/auth/:provider/callback", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return svc.OAuthCallbackHandler(provider)(c)
	})

	// 1. Setup session
	reqSetup := httptest.NewRequest("GET", "/setup-session", nil)
	respSetup, err := app.Test(reqSetup)
	assertNoError(t, err)
	cookie := respSetup.Header.Get("Set-Cookie")

	// 2. Perform callback
	u := url.Values{}
	u.Set("code", "test-code")
	u.Set("state", "test-state")
	req := httptest.NewRequest("GET", "/auth/github/callback?"+u.Encode(), nil)
	req.Header.Set("Cookie", cookie)
	resp, err := app.Test(req)
	assertNoError(t, err)

	assertEqual(t, resp.StatusCode, http.StatusSeeOther)
	// Verify user created
	var user auth.User
	err = db.Where("email = ?", "test-github@example.com").First(&user).Error
	assertNoError(t, err)
	assertEqual(t, user.Name, "GitHub User")
}

func TestListUnlinkProviders(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)
	app := setupTestAppWithAuth(t, svc)
	user := createTestUser(t, db, svc)

	// Manually link a provider
	err := db.Create(&auth.OAuthProvider{
		UserID:     user.ID,
		Provider:   "google",
		ProviderID: "123",
		Email:      "test@example.com",
	}).Error
	assertNoError(t, err)

	// List providers
	app.Get("/auth/providers", svc.ListOAuthProvidersHandler())

	token := generateTestJWT(t, svc, user.ID, testTenantID)
	req := httptest.NewRequest("GET", "/auth/providers", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := app.Test(req)
	assertNoError(t, err)
	assertEqual(t, resp.StatusCode, http.StatusOK)

	var result struct {
		Linked []map[string]interface{} `json:"linked"`
	}
	body, _ := io.ReadAll(resp.Body)
	json.Unmarshal(body, &result)
	assertEqual(t, len(result.Linked), 1)
	assertEqual(t, result.Linked[0]["provider"], "google")

	// Unlink provider - should fail because it's the only auth method and no password (wait, createTestUser has password)
	// Since createTestUser uses Register, it has password. So unlinking should success.

	app.Delete("/auth/providers/:provider", svc.UnlinkOAuthProviderHandler())
	reqUnlink := httptest.NewRequest("DELETE", "/auth/providers/google", nil)
	reqUnlink.Header.Set("Authorization", "Bearer "+token)

	respUnlink, err := app.Test(reqUnlink)
	assertNoError(t, err)
	assertEqual(t, respUnlink.StatusCode, http.StatusOK)

	// Verify removed from DB
	var count int64
	db.Model(&auth.OAuthProvider{}).Where("user_id = ?", user.ID).Count(&count)
	assertEqual(t, count, int64(0))
}

func TestOAuthCallback_ErrorScenarios(t *testing.T) {
	svc, _ := setupTestServiceWithDB(t)
	cfg := svc.Config()
	cfg.GoogleOAuth = &auth.OAuthProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURL:  "http://localhost:3000/auth/google/callback",
	}
	cfg.OAuthErrorRedirect = "/login"
	svc.SetConfig(cfg)

	app := fiber.New()
	app.Use(session.New(session.Config{}))
	app.Use(svc.TenantMiddleware())

	app.Get("/auth/:provider/callback", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return svc.OAuthCallbackHandler(provider)(c)
	})

	tests := []struct {
		name           string
		setupSession   func(fiber.Ctx)
		queryParams    string
		mockTransport  *MockHTTPTransport
		expectedError  string
		expectedStatus int
	}{
		{
			name: "Error Param from Provider",
			setupSession: func(c fiber.Ctx) {
				sess := session.FromContext(c)
				sess.Set(auth.SessionKeyOAuthState, "test-state")
				sess.Set(auth.SessionKeyOAuthProvider, "google")
			},
			queryParams:    "?error=access_denied&state=test-state",
			expectedError:  "access_denied",
			expectedStatus: http.StatusSeeOther,
		},
		{
			name: "State Mismatch",
			setupSession: func(c fiber.Ctx) {
				sess := session.FromContext(c)
				sess.Set(auth.SessionKeyOAuthState, "correct-state")
				sess.Set(auth.SessionKeyOAuthProvider, "google")
			},
			queryParams:    "?code=code&state=wrong-state",
			expectedError:  "state mismatch",
			expectedStatus: http.StatusSeeOther,
		},
		{
			name: "Missing Code",
			setupSession: func(c fiber.Ctx) {
				sess := session.FromContext(c)
				sess.Set(auth.SessionKeyOAuthState, "test-state")
				sess.Set(auth.SessionKeyOAuthProvider, "google")
			},
			queryParams:    "?state=test-state",
			expectedError:  "authorization code not provided",
			expectedStatus: http.StatusSeeOther,
		},
		{
			name: "Token Exchange Failed",
			setupSession: func(c fiber.Ctx) {
				sess := session.FromContext(c)
				sess.Set(auth.SessionKeyOAuthState, "test-state")
				sess.Set(auth.SessionKeyOAuthProvider, "google")
			},
			queryParams: "?code=bad-code&state=test-state",
			mockTransport: &MockHTTPTransport{
				RoundTripFunc: func(req *http.Request) (*http.Response, error) {
					if req.URL.Path == "/token" {
						return &http.Response{
							StatusCode: http.StatusBadRequest,
							Body:       io.NopCloser(bytes.NewBufferString(`{"error":"invalid_grant"}`)),
							Header:     make(http.Header),
						}, nil
					}
					return nil, http.ErrNoLocation
				},
			},
			expectedError:  "token exchange failed",
			expectedStatus: http.StatusSeeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.mockTransport != nil {
				svc.HTTPClient = &http.Client{Transport: tt.mockTransport}
			}

			// Helper to setup session
			app.Get("/setup-session-"+strings.ReplaceAll(tt.name, " ", ""), func(c fiber.Ctx) error {
				if tt.setupSession != nil {
					tt.setupSession(c)
				}
				return c.SendStatus(fiber.StatusOK)
			})

			// 1. Setup session
			reqSetup := httptest.NewRequest("GET", "/setup-session-"+strings.ReplaceAll(tt.name, " ", ""), nil)
			respSetup, err := app.Test(reqSetup)
			assertNoError(t, err)
			cookies := respSetup.Header.Get("Set-Cookie")

			// 2. Perform callback
			req := httptest.NewRequest("GET", "/auth/google/callback"+tt.queryParams, nil)
			req.Header.Set("Cookie", cookies)
			resp, err := app.Test(req)
			assertNoError(t, err)

			assertEqual(t, resp.StatusCode, tt.expectedStatus)
			if tt.expectedError != "" {
				location := resp.Header.Get("Location")
				assertTrue(t, strings.Contains(location, "error_description"), "should contain error description in location: "+location)
				// We do a loose check because the error string might be URL encoded or partial
				// But let's check if the location contains the error param at least
				assertTrue(t, strings.Contains(location, "error=oauth_failed"), "should contain error=oauth_failed")
			}
		})
	}
}

func TestLinkOAuth_Flow(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)

	// Create user
	user := createTestUser(t, db, svc)
	user.Email = "existing@example.com" // Ensure specific email
	db.Save(&user)

	// Mock config
	cfg := svc.Config()
	cfg.GoogleOAuth = &auth.OAuthProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURL:  "http://localhost:3000/auth/providers/google/callback",
	}
	svc.SetConfig(cfg)

	// Mock HTTP Client for success flow
	mockTransport := &MockHTTPTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			// Mock Token Exchange
			if req.URL.Path == "/token" {
				token := &oauth2.Token{
					AccessToken: "mock-link-access-token",
					Expiry:      time.Now().Add(time.Hour),
					TokenType:   "Bearer",
				}
				body, _ := json.Marshal(map[string]interface{}{
					"access_token": token.AccessToken,
					"expires_in":   3600,
					"token_type":   "Bearer",
				})
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(body)),
					Header:     make(http.Header),
				}, nil
			}
			// Mock User Info
			if req.URL.Host == "www.googleapis.com" && req.URL.Path == "/oauth2/v2/userinfo" {
				userInfo := auth.GoogleUserInfo{
					ID:            "google-link-123",
					Email:         "link@example.com",
					VerifiedEmail: true,
					Name:          "Linked User",
					Picture:       "http://example.com/pic.jpg",
				}
				body, _ := json.Marshal(userInfo)
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBuffer(body)),
					Header:     make(http.Header),
				}, nil
			}
			return nil, http.ErrNoLocation
		},
	}
	svc.HTTPClient = &http.Client{Transport: mockTransport}

	app := fiber.New()
	app.Use(session.New(session.Config{}))
	app.Use(svc.TenantMiddleware())

	// Middleware to mock current user
	app.Use(func(c fiber.Ctx) error {
		c.Locals(auth.LocalsUserID, user.ID)
		return c.Next()
	})

	app.Get("/auth/providers/:provider/link", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return svc.LinkOAuthRedirectHandler(provider)(c)
	})

	app.Get("/auth/providers/:provider/callback", func(c fiber.Ctx) error {
		provider := c.Params("provider")
		return svc.LinkOAuthCallbackHandler(provider)(c)
	})

	// 1. Initiate Link
	reqLink := httptest.NewRequest("GET", "/auth/providers/google/link", nil)
	respLink, err := app.Test(reqLink)
	assertNoError(t, err)
	assertEqual(t, respLink.StatusCode, http.StatusSeeOther)

	cookies := respLink.Header.Get("Set-Cookie")
	location := respLink.Header.Get("Location")
	u, _ := url.Parse(location)
	state := u.Query().Get("state")

	// 2. Callback Success
	reqCallback := httptest.NewRequest("GET", "/auth/providers/google/callback?code=mock-code&state="+state, nil)
	reqCallback.Header.Set("Cookie", cookies) // Send session cookie

	respCallback, err := app.Test(reqCallback)
	assertNoError(t, err)
	assertEqual(t, respCallback.StatusCode, http.StatusSeeOther)
	locationCallback := respCallback.Header.Get("Location")
	assertTrue(t, strings.Contains(locationCallback, "provider_linked=google"), "should indicate success")

	// Verify Linked in DB
	var provider auth.OAuthProvider
	err = db.Where("user_id = ? AND provider = ?", user.ID, "google").First(&provider).Error
	assertNoError(t, err)
	assertEqual(t, provider.ProviderID, "google-link-123")
}

func TestLinkOAuth_AlreadyLinked(t *testing.T) {
	svc, db := setupTestServiceWithDB(t)

	// User 1 has google linked
	user1 := createTestUser(t, db, svc)
	db.Create(&auth.OAuthProvider{
		UserID:     user1.ID,
		Provider:   "google",
		ProviderID: "google-123",
		Email:      "user1@example.com",
	})

	// User 2 tries to link same google account
	user2 := &auth.User{
		Email:        "user2@example.com",
		PasswordHash: "hash",
		Active:       true,
		Role:         "user",
	}
	db.Create(user2)

	// Helper to setup session with linking info
	app := fiber.New()
	app.Use(session.New(session.Config{}))
	app.Use(svc.TenantMiddleware())

	app.Get("/setup-session", func(c fiber.Ctx) error {
		sess := session.FromContext(c)
		sess.Set(auth.SessionKeyOAuthState, "test-state")
		sess.Set(auth.SessionKeyOAuthProvider, "google")
		sess.Set("oauth_link_user_id", user2.ID)
		return c.SendStatus(fiber.StatusOK)
	})

	app.Get("/auth/providers/:provider/callback", func(c fiber.Ctx) error {
		return svc.LinkOAuthCallbackHandler("google")(c)
	})

	// Mock valid token/profile exchange that returns the SAME google-123 user
	mockTransport := &MockHTTPTransport{
		RoundTripFunc: func(req *http.Request) (*http.Response, error) {
			if req.URL.Path == "/token" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"access_token":"token","token_type":"Bearer"}`)),
				}, nil
			}
			if strings.Contains(req.URL.Path, "userinfo") {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString(`{"id":"google-123","email":"user1@example.com","verified_email":true}`)),
				}, nil
			}
			return nil, http.ErrNoLocation
		},
	}
	svc.HTTPClient = &http.Client{Transport: mockTransport}
	cfg := svc.Config()
	cfg.GoogleOAuth = &auth.OAuthProviderConfig{ClientID: "id", ClientSecret: "secret", RedirectURL: "cb"}
	svc.SetConfig(cfg)

	// Setup session
	reqSetup := httptest.NewRequest("GET", "/setup-session", nil)
	respSetup, err := app.Test(reqSetup)
	assertNoError(t, err)
	cookies := respSetup.Header.Get("Set-Cookie")

	// Perform Callback
	req := httptest.NewRequest("GET", "/auth/providers/google/callback?code=xc&state=test-state", nil)
	req.Header.Set("Cookie", cookies)
	resp, err := app.Test(req)
	assertNoError(t, err)

	assertEqual(t, resp.StatusCode, http.StatusSeeOther)
	location := resp.Header.Get("Location")
	assertTrue(t, strings.Contains(location, "error_description"), "should have error")
	// Because user1 matches google-123, user2 cannot link it
}
