package tests

import (
	"testing"

	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email string
		want  bool
	}{
		{"test@example.com", true},
		{"user.name@domain.org", true},
		{"user+tag@example.com", true},
		{"user@sub.domain.com", true},
		{"a@b.co", true},
		{"user123@test.io", true},
		{"", false},
		{"invalid", false},
		{"@example.com", false},
		{"user@", false},
		{"user@.com", false},
		{"user@domain", false},
		{"user @example.com", false},
		{"user@ example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.email, func(t *testing.T) {
			got := auth.IsValidEmail(tt.email)
			assertEqual(t, got, tt.want)
		})
	}
}

func TestGenerateSecureToken(t *testing.T) {
	// Test basic generation
	token1, err := auth.GenerateSecureToken(32)
	assertNoError(t, err)
	assertNotEqual(t, token1, "")

	// Test uniqueness
	token2, err := auth.GenerateSecureToken(32)
	assertNoError(t, err)
	assertNotEqual(t, token1, token2)

	// Test different lengths
	shortToken, err := auth.GenerateSecureToken(8)
	assertNoError(t, err)
	longToken, err := auth.GenerateSecureToken(64)
	assertNoError(t, err)

	// Verify lengths are different (base64 encoded)
	if len(shortToken) >= len(longToken) {
		t.Errorf("short token should be shorter than long token")
	}
}

func TestHashToken(t *testing.T) {
	// Test consistent hashing
	token := "test-token"
	hash1 := auth.HashToken(token)
	hash2 := auth.HashToken(token)
	assertEqual(t, hash1, hash2)

	// Test different inputs produce different hashes
	hash3 := auth.HashToken("different-token")
	assertNotEqual(t, hash1, hash3)

	// Test hash length (SHA-256 produces 64 hex characters)
	assertEqual(t, len(hash1), 64)

	// Test empty string
	emptyHash := auth.HashToken("")
	assertEqual(t, len(emptyHash), 64)
}

func TestSplitScopes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single scope",
			input: "read",
			want:  []string{"read"},
		},
		{
			name:  "multiple scopes",
			input: "read,write,delete",
			want:  []string{"read", "write", "delete"},
		},
		{
			name:  "scopes with whitespace",
			input: "read, write , delete",
			want:  []string{"read", "write", "delete"},
		},
		{
			name:  "trailing comma",
			input: "read,write,",
			want:  []string{"read", "write"},
		},
		{
			name:  "leading comma",
			input: ",read,write",
			want:  []string{"read", "write"},
		},
		{
			name:  "only commas",
			input: ",,,,",
			want:  []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.SplitScopes(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("length mismatch: got %d, want %d", len(got), len(tt.want))
				return
			}
			for i := range got {
				assertEqual(t, got[i], tt.want[i])
			}
		})
	}
}

func TestJoinScopes(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name:  "empty slice",
			input: []string{},
			want:  "",
		},
		{
			name:  "nil slice",
			input: nil,
			want:  "",
		},
		{
			name:  "single scope",
			input: []string{"read"},
			want:  "read",
		},
		{
			name:  "multiple scopes",
			input: []string{"read", "write", "delete"},
			want:  "read,write,delete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.JoinScopes(tt.input)
			assertEqual(t, got, tt.want)
		})
	}
}

func TestMaskAPIKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "short key",
			input: "abc123",
			want:  "******",
		},
		{
			name:  "exactly 12 chars",
			input: "123456789012",
			want:  "************",
		},
		{
			name:  "normal key",
			input: "sk_live_abc123xyz789def456",
			want:  "sk_live_...f456",
		},
		{
			name:  "minimum maskable",
			input: "1234567890123",
			want:  "12345678...0123",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := auth.MaskAPIKey(tt.input)
			assertEqual(t, got, tt.want)
		})
	}
}

func TestRoundTripScopes(t *testing.T) {
	// Test that splitting and joining preserves the data
	original := []string{"read", "write", "admin"}
	joined := auth.JoinScopes(original)
	split := auth.SplitScopes(joined)

	if len(split) != len(original) {
		t.Errorf("length mismatch after round trip: got %d, want %d", len(split), len(original))
		return
	}

	for i := range split {
		assertEqual(t, split[i], original[i])
	}
}
