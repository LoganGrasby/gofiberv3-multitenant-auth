package auth

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DatabaseManager manages per-tenant database connections.
type DatabaseManager struct {
	config      Config
	connections map[string]*gorm.DB
	mu          sync.RWMutex
	closed      bool
}

// NewDatabaseManager creates a new database manager.
func NewDatabaseManager(config Config) (*DatabaseManager, error) {
	// Ensure the database directory exists
	if err := os.MkdirAll(config.DatabaseDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	return &DatabaseManager{
		config:      config,
		connections: make(map[string]*gorm.DB),
	}, nil
}

// GetDB returns the database connection for a tenant.
// If the connection doesn't exist, it creates one.
func (dm *DatabaseManager) GetDB(ctx context.Context, tenantID string) (*gorm.DB, error) {
	if tenantID == "" {
		return nil, ErrTenantRequired
	}

	// Check if connection exists (read lock)
	dm.mu.RLock()
	if dm.closed {
		dm.mu.RUnlock()
		return nil, fmt.Errorf("database manager is closed")
	}
	if db, ok := dm.connections[tenantID]; ok {
		dm.mu.RUnlock()
		return db, nil
	}
	dm.mu.RUnlock()

	// Create new connection (write lock)
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Double-check after acquiring write lock
	if dm.closed {
		return nil, fmt.Errorf("database manager is closed")
	}
	if db, ok := dm.connections[tenantID]; ok {
		return db, nil
	}

	// Check if tenant database file exists (unless creation is allowed)
	dbPath := dm.getDBPath(tenantID)
	if !dm.config.AllowTenantCreation {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			return nil, ErrTenantNotFound
		}
	}

	// Open connection
	db, err := dm.openConnection(dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database for tenant %s: %w", tenantID, err)
	}

	// Run migrations
	if err := dm.migrate(db); err != nil {
		return nil, fmt.Errorf("failed to migrate database for tenant %s: %w", tenantID, err)
	}

	dm.connections[tenantID] = db
	if dm.config.Logger != nil {
		dm.config.Logger.Info("opened database connection", "tenant", tenantID)
	}

	return db, nil
}

// TenantExists checks if a tenant database exists.
func (dm *DatabaseManager) TenantExists(tenantID string) bool {
	dbPath := dm.getDBPath(tenantID)
	_, err := os.Stat(dbPath)
	return err == nil
}

// CreateTenant creates a new tenant database.
func (dm *DatabaseManager) CreateTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return ErrTenantRequired
	}

	// Validate tenant ID (alphanumeric and hyphens only)
	if !IsValidTenantID(tenantID) {
		return &ErrValidation{Field: "tenant_id", Message: "must be alphanumeric with hyphens only"}
	}

	// Check if already exists
	if dm.TenantExists(tenantID) {
		return fmt.Errorf("tenant already exists: %s", tenantID)
	}

	// Create the database by getting a connection
	_, err := dm.GetDB(ctx, tenantID)
	return err
}

// DeleteTenant removes a tenant's database.
// Warning: This permanently deletes all tenant data!
func (dm *DatabaseManager) DeleteTenant(ctx context.Context, tenantID string) error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Close existing connection if any
	if db, ok := dm.connections[tenantID]; ok {
		sqlDB, err := db.DB()
		if err == nil {
			sqlDB.Close()
		}
		delete(dm.connections, tenantID)
	}

	// Delete the database file
	dbPath := dm.getDBPath(tenantID)
	if err := os.Remove(dbPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete tenant database: %w", err)
	}

	if dm.config.Logger != nil {
		dm.config.Logger.Info("deleted tenant database", "tenant", tenantID)
	}

	return nil
}

// ListTenants returns all tenant IDs.
func (dm *DatabaseManager) ListTenants() ([]string, error) {
	entries, err := os.ReadDir(dm.config.DatabaseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant databases: %w", err)
	}

	var tenants []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if filepath.Ext(name) == ".db" {
			tenants = append(tenants, name[:len(name)-3])
		}
	}
	return tenants, nil
}

// Close closes all database connections.
func (dm *DatabaseManager) Close() error {
	dm.mu.Lock()
	defer dm.mu.Unlock()

	dm.closed = true
	var lastErr error
	for tenantID, db := range dm.connections {
		sqlDB, err := db.DB()
		if err != nil {
			lastErr = err
			continue
		}
		if err := sqlDB.Close(); err != nil {
			lastErr = err
			if dm.config.Logger != nil {
				dm.config.Logger.Error("failed to close database", "tenant", tenantID, "error", err)
			}
		}
	}
	dm.connections = make(map[string]*gorm.DB)
	return lastErr
}

// getDBPath returns the file path for a tenant's database.
func (dm *DatabaseManager) getDBPath(tenantID string) string {
	return filepath.Join(dm.config.DatabaseDir, tenantID+".db")
}

// openConnection opens a new SQLite connection.
func (dm *DatabaseManager) openConnection(dbPath string) (*gorm.DB, error) {
	// SQLite connection string with recommended settings
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL&_cache_size=1000000000&_foreign_keys=true", dbPath)

	// Configure GORM logger
	gormLogger := logger.Default.LogMode(logger.Silent)
	if dm.config.Logger != nil {
		gormLogger = logger.Default.LogMode(logger.Warn)
	}

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger:                 gormLogger,
		SkipDefaultTransaction: true,
		PrepareStmt:            true,
	})
	if err != nil {
		return nil, err
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	// SQLite works best with a single connection for writes
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// migrate runs database migrations.
func (dm *DatabaseManager) migrate(db *gorm.DB) error {
	return db.AutoMigrate(AllModels()...)
}

// IsValidTenantID checks if a tenant ID is valid.
func IsValidTenantID(id string) bool {
	if len(id) == 0 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
