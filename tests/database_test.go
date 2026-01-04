package tests

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/logangrasby/gofiberv3-multitenant-auth/auth"
)

func TestNewDatabaseManager_CreatesDir(t *testing.T) {
	dir := filepath.Join(os.TempDir(), "test-db-manager-create-"+randString(8))
	defer os.RemoveAll(dir)

	config := auth.Config{
		DatabaseDir:         dir,
		AllowTenantCreation: true,
	}

	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	// Verify directory was created
	info, err := os.Stat(dir)
	assertNoError(t, err)
	assertTrue(t, info.IsDir(), "should create directory")
}

func TestDatabaseManager_GetDB(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	ctx := context.Background()

	// First call should create connection
	db1, err := dm.GetDB(ctx, "tenant-1")
	assertNoError(t, err)
	assertNotNil(t, db1, "should return database")

	// Second call should return cached connection
	db2, err := dm.GetDB(ctx, "tenant-1")
	assertNoError(t, err)
	if db1 != db2 {
		t.Error("should return cached connection")
	}

	// Different tenant should get different connection
	db3, err := dm.GetDB(ctx, "tenant-2")
	assertNoError(t, err)
	if db1 == db3 {
		t.Error("different tenants should get different connections")
	}
}

func TestDatabaseManager_GetDB_EmptyTenantID(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	_, err = dm.GetDB(context.Background(), "")
	if err != auth.ErrTenantRequired {
		t.Errorf("expected auth.ErrTenantRequired, got %v", err)
	}
}

func TestDatabaseManager_GetDB_ClosedManager(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)

	// Close the manager
	dm.Close()

	// Try to get a connection
	_, err = dm.GetDB(context.Background(), "tenant-1")
	if err == nil {
		t.Error("expected error for closed manager")
	}
}

func TestDatabaseManager_TenantExists(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	ctx := context.Background()

	// Tenant doesn't exist yet
	assertFalse(t, dm.TenantExists("new-tenant"), "tenant should not exist yet")

	// Create tenant by getting DB
	_, err = dm.GetDB(ctx, "new-tenant")
	assertNoError(t, err)

	// Now it should exist
	assertTrue(t, dm.TenantExists("new-tenant"), "tenant should exist after creation")
}

func TestDatabaseManager_CreateTenant(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	ctx := context.Background()

	// Create a new tenant
	err = dm.CreateTenant(ctx, "brand-new-tenant")
	assertNoError(t, err)

	// Verify it exists
	assertTrue(t, dm.TenantExists("brand-new-tenant"), "tenant should exist")
}

func TestDatabaseManager_CreateTenant_EmptyID(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	err = dm.CreateTenant(context.Background(), "")
	if err != auth.ErrTenantRequired {
		t.Errorf("expected auth.ErrTenantRequired, got %v", err)
	}
}

func TestDatabaseManager_CreateTenant_InvalidID(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	invalidIDs := []string{
		"tenant with spaces",
		"tenant@special",
		"tenant/slash",
		"tenant\\backslash",
		"tenant..dots",
		"",
	}

	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			err := dm.CreateTenant(context.Background(), id)
			if err == nil && id != "" {
				// Empty ID should return ErrTenantRequired, others should fail validation
				t.Error("expected error for invalid tenant ID")
			}
		})
	}
}

func TestDatabaseManager_CreateTenant_AlreadyExists(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	ctx := context.Background()

	// Create tenant
	err = dm.CreateTenant(ctx, "existing-tenant")
	assertNoError(t, err)

	// Try to create again
	err = dm.CreateTenant(ctx, "existing-tenant")
	if err == nil {
		t.Error("expected error for duplicate tenant")
	}
}

func TestDatabaseManager_DeleteTenant(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	ctx := context.Background()

	// Create and verify tenant
	_, err = dm.GetDB(ctx, "delete-me")
	assertNoError(t, err)
	assertTrue(t, dm.TenantExists("delete-me"), "tenant should exist")

	// Delete tenant
	err = dm.DeleteTenant(ctx, "delete-me")
	assertNoError(t, err)

	// Verify it's gone
	assertFalse(t, dm.TenantExists("delete-me"), "tenant should not exist after deletion")
}

func TestDatabaseManager_DeleteTenant_NonExistent(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	// Delete non-existent tenant should not error
	err = dm.DeleteTenant(context.Background(), "never-existed")
	assertNoError(t, err)
}

func TestDatabaseManager_ListTenants(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	ctx := context.Background()

	// Initially empty
	tenants, err := dm.ListTenants()
	assertNoError(t, err)
	assertEqual(t, len(tenants), 0)

	// Create some tenants
	dm.GetDB(ctx, "tenant-a")
	dm.GetDB(ctx, "tenant-b")
	dm.GetDB(ctx, "tenant-c")

	// List should return all
	tenants, err = dm.ListTenants()
	assertNoError(t, err)
	assertEqual(t, len(tenants), 3)

	// Verify all are present (order may vary)
	found := make(map[string]bool)
	for _, t := range tenants {
		found[t] = true
	}
	assertTrue(t, found["tenant-a"], "should contain tenant-a")
	assertTrue(t, found["tenant-b"], "should contain tenant-b")
	assertTrue(t, found["tenant-c"], "should contain tenant-c")
}

func TestDatabaseManager_Close(t *testing.T) {
	config := setupTestConfig(t)
	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)

	ctx := context.Background()

	// Create some connections
	dm.GetDB(ctx, "tenant-1")
	dm.GetDB(ctx, "tenant-2")

	// Close should not error
	err = dm.Close()
	assertNoError(t, err)

	// Subsequent GetDB should fail
	_, err = dm.GetDB(ctx, "tenant-1")
	if err == nil {
		t.Error("expected error after close")
	}
}

func TestDatabaseManager_TenantCreationDisabled(t *testing.T) {
	dir := setupTestDir(t)
	config := auth.Config{
		DatabaseDir:         dir,
		AllowTenantCreation: false, // Disable auto-creation
	}

	dm, err := auth.NewDatabaseManager(config)
	assertNoError(t, err)
	defer dm.Close()

	// Try to get DB for non-existent tenant
	_, err = dm.GetDB(context.Background(), "new-tenant")
	if err != auth.ErrTenantNotFound {
		t.Errorf("expected auth.ErrTenantNotFound, got %v", err)
	}
}

func TestIsValidTenantID(t *testing.T) {
	tests := []struct {
		id    string
		valid bool
	}{
		{"tenant", true},
		{"tenant-1", true},
		{"tenant_1", true},
		{"Tenant123", true},
		{"a", true},
		{"abc-def_123", true},
		{"", false},
		{"tenant with space", false},
		{"tenant@email.com", false},
		{"tenant/path", false},
		{"tenant\\path", false},
		{"tenant.name", false},
		{"tenant:port", false},
		{string(make([]byte, 65)), false}, // Too long
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := auth.IsValidTenantID(tt.id)
			assertEqual(t, got, tt.valid)
		})
	}
}

// Helper function for generating random strings for test isolation
func randString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[i%len(letters)]
	}
	return string(b)
}
