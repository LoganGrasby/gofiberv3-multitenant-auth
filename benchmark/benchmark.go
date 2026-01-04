// Package benchmark provides load testing tools for the auth service.
// It simulates extreme traffic scenarios to validate performance under stress.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"
)

// =============================================================================
// Configuration
// =============================================================================

type Config struct {
	BaseURL        string
	TenantID       string
	NumUsers       int           // Number of concurrent simulated users
	Duration       time.Duration // Total test duration
	RampUpTime     time.Duration // Time to ramp up to full load
	Scenario       string        // Scenario type: normal, burst, spike, sustained
	RequestsPerSec int           // Target requests per second (0 = unlimited)
	Verbose        bool          // Enable verbose logging
}

// =============================================================================
// Metrics Collection
// =============================================================================

type RequestMetrics struct {
	Endpoint   string
	Method     string
	StatusCode int
	Duration   time.Duration
	Error      error
	Timestamp  time.Time
}

type AggregatedMetrics struct {
	Endpoint      string
	TotalRequests int64
	SuccessCount  int64
	ErrorCount    int64
	TotalDuration time.Duration
	MinDuration   time.Duration
	MaxDuration   time.Duration
	Latencies     []time.Duration
	StatusCodes   map[int]int64
}

type MetricsCollector struct {
	mu          sync.Mutex
	requests    []RequestMetrics
	byEndpoint  map[string]*AggregatedMetrics
	startTime   time.Time
	totalReqs   atomic.Int64
	successReqs atomic.Int64
	errorReqs   atomic.Int64
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		requests:   make([]RequestMetrics, 0),
		byEndpoint: make(map[string]*AggregatedMetrics),
		startTime:  time.Now(),
	}
}

func (mc *MetricsCollector) Record(m RequestMetrics) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.requests = append(mc.requests, m)
	mc.totalReqs.Add(1)

	endpoint := fmt.Sprintf("%s %s", m.Method, m.Endpoint)
	agg, exists := mc.byEndpoint[endpoint]
	if !exists {
		agg = &AggregatedMetrics{
			Endpoint:    endpoint,
			MinDuration: time.Hour,
			Latencies:   make([]time.Duration, 0),
			StatusCodes: make(map[int]int64),
		}
		mc.byEndpoint[endpoint] = agg
	}

	agg.TotalRequests++
	agg.TotalDuration += m.Duration
	agg.Latencies = append(agg.Latencies, m.Duration)
	agg.StatusCodes[m.StatusCode]++

	if m.Error != nil || m.StatusCode >= 400 {
		agg.ErrorCount++
		mc.errorReqs.Add(1)
	} else {
		agg.SuccessCount++
		mc.successReqs.Add(1)
	}

	if m.Duration < agg.MinDuration {
		agg.MinDuration = m.Duration
	}
	if m.Duration > agg.MaxDuration {
		agg.MaxDuration = m.Duration
	}
}

func (mc *MetricsCollector) Percentile(latencies []time.Duration, p float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	sort.Slice(latencies, func(i, j int) bool {
		return latencies[i] < latencies[j]
	})
	index := int(math.Ceil(p/100*float64(len(latencies)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(latencies) {
		index = len(latencies) - 1
	}
	return latencies[index]
}

func (mc *MetricsCollector) Report() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	elapsed := time.Since(mc.startTime)

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("BENCHMARK RESULTS")
	fmt.Println(strings.Repeat("=", 80))

	// Overall summary
	fmt.Printf("\n📊 Overall Summary\n")
	fmt.Printf("   Duration:         %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("   Total Requests:   %d\n", mc.totalReqs.Load())
	fmt.Printf("   Successful:       %d (%.2f%%)\n",
		mc.successReqs.Load(),
		float64(mc.successReqs.Load())/float64(mc.totalReqs.Load())*100)
	fmt.Printf("   Failed:           %d (%.2f%%)\n",
		mc.errorReqs.Load(),
		float64(mc.errorReqs.Load())/float64(mc.totalReqs.Load())*100)
	fmt.Printf("   Throughput:       %.2f req/s\n",
		float64(mc.totalReqs.Load())/elapsed.Seconds())

	// Per-endpoint breakdown
	fmt.Printf("\n📈 Per-Endpoint Metrics\n\n")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "Endpoint\tReqs\tSuccess\tErrors\tAvg\tp50\tp95\tp99\tMin\tMax\n")
	fmt.Fprintf(w, "--------\t----\t-------\t------\t---\t---\t---\t---\t---\t---\n")

	for _, agg := range mc.byEndpoint {
		avg := agg.TotalDuration / time.Duration(agg.TotalRequests)
		p50 := mc.Percentile(agg.Latencies, 50)
		p95 := mc.Percentile(agg.Latencies, 95)
		p99 := mc.Percentile(agg.Latencies, 99)

		fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%v\t%v\t%v\t%v\t%v\t%v\n",
			agg.Endpoint,
			agg.TotalRequests,
			agg.SuccessCount,
			agg.ErrorCount,
			avg.Round(time.Microsecond),
			p50.Round(time.Microsecond),
			p95.Round(time.Microsecond),
			p99.Round(time.Microsecond),
			agg.MinDuration.Round(time.Microsecond),
			agg.MaxDuration.Round(time.Microsecond),
		)
	}
	w.Flush()

	// Status code breakdown
	fmt.Printf("\n📋 Status Code Distribution\n\n")
	allCodes := make(map[int]int64)
	for _, agg := range mc.byEndpoint {
		for code, count := range agg.StatusCodes {
			allCodes[code] += count
		}
	}

	codes := make([]int, 0, len(allCodes))
	for code := range allCodes {
		codes = append(codes, code)
	}
	sort.Ints(codes)

	for _, code := range codes {
		emoji := "✅"
		if code >= 400 {
			emoji = "❌"
		}
		fmt.Printf("   %s HTTP %d: %d requests\n", emoji, code, allCodes[code])
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
}

// =============================================================================
// HTTP Client
// =============================================================================

type BenchClient struct {
	client   *http.Client
	baseURL  string
	tenantID string
	verbose  bool
}

func NewBenchClient(baseURL, tenantID string, verbose bool) *BenchClient {
	return &BenchClient{
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 1000,
				MaxConnsPerHost:     1000,
				IdleConnTimeout:     90 * time.Second,
			},
		},
		baseURL:  strings.TrimSuffix(baseURL, "/"),
		tenantID: tenantID,
		verbose:  verbose,
	}
}

func (bc *BenchClient) do(method, endpoint string, body interface{}, token string) (*http.Response, time.Duration, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonData, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		bodyReader = bytes.NewBuffer(jsonData)
	}

	req, err := http.NewRequest(method, bc.baseURL+endpoint, bodyReader)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", bc.tenantID)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	start := time.Now()
	resp, err := bc.client.Do(req)
	duration := time.Since(start)

	return resp, duration, err
}

func (bc *BenchClient) Register(email, password, name string) (*http.Response, time.Duration, error) {
	return bc.do("POST", "/api/auth/register", map[string]string{
		"email":    email,
		"password": password,
		"name":     name,
	}, "")
}

func (bc *BenchClient) Login(email, password string) (string, string, *http.Response, time.Duration, error) {
	resp, duration, err := bc.do("POST", "/api/auth/login", map[string]string{
		"email":    email,
		"password": password,
	}, "")
	if err != nil {
		return "", "", resp, duration, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", resp, duration, nil
	}

	accessToken, _ := result["access_token"].(string)
	refreshToken, _ := result["refresh_token"].(string)
	return accessToken, refreshToken, resp, duration, nil
}

func (bc *BenchClient) Refresh(refreshToken string) (string, string, *http.Response, time.Duration, error) {
	resp, duration, err := bc.do("POST", "/api/auth/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, "")
	if err != nil {
		return "", "", resp, duration, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", resp, duration, nil
	}

	accessToken, _ := result["access_token"].(string)
	newRefreshToken, _ := result["refresh_token"].(string)
	return accessToken, newRefreshToken, resp, duration, nil
}

func (bc *BenchClient) GetMe(token string) (*http.Response, time.Duration, error) {
	return bc.do("GET", "/api/me", nil, token)
}

func (bc *BenchClient) Health() (*http.Response, time.Duration, error) {
	return bc.do("GET", "/health", nil, "")
}

// =============================================================================
// Virtual User (simulated client)
// =============================================================================

type VirtualUser struct {
	id           int
	client       *BenchClient
	collector    *MetricsCollector
	accessToken  string
	refreshToken string
	email        string
	wg           *sync.WaitGroup
	stop         chan struct{}
}

func NewVirtualUser(id int, baseClient *BenchClient, collector *MetricsCollector, wg *sync.WaitGroup, stop chan struct{}) *VirtualUser {
	// Create a copy of the client for this user so they can have their own tenantID context
	// We share the underlying http.Client for connection pooling
	clientCopy := *baseClient

	return &VirtualUser{
		id:        id,
		client:    &clientCopy,
		collector: collector,
		email:     fmt.Sprintf("bench-user-%d-%d@test.local", id, time.Now().UnixNano()),
		wg:        wg,
		stop:      stop,
	}
}

func (vu *VirtualUser) recordMetric(endpoint, method string, statusCode int, duration time.Duration, err error) {
	vu.collector.Record(RequestMetrics{
		Endpoint:   endpoint,
		Method:     method,
		StatusCode: statusCode,
		Duration:   duration,
		Error:      err,
		Timestamp:  time.Now(),
	})
}

func (vu *VirtualUser) Setup() error {
	// Register a new user
	resp, duration, err := vu.client.Register(vu.email, "SecurePassword123!", fmt.Sprintf("Benchmark User %d", vu.id))
	statusCode := 0
	if resp != nil {
		statusCode = resp.StatusCode
		resp.Body.Close()
	}
	vu.recordMetric("/api/auth/register", "POST", statusCode, duration, err)

	if err != nil || (statusCode != 200 && statusCode != 201) {
		// User might already exist, try login
	}

	// Login
	accessToken, refreshToken, resp, duration, err := vu.client.Login(vu.email, "SecurePassword123!")
	statusCode = 0
	if resp != nil {
		statusCode = resp.StatusCode
	}
	vu.recordMetric("/api/auth/login", "POST", statusCode, duration, err)

	if err != nil {
		return fmt.Errorf("login failed: %w", err)
	}

	vu.accessToken = accessToken
	vu.refreshToken = refreshToken
	return nil
}

func (vu *VirtualUser) RunWorkload(scenario string) {
	defer vu.wg.Done()

	switch scenario {
	case "burst":
		vu.runBurstWorkload()
	case "spike":
		vu.runSpikeWorkload()
	case "sustained":
		vu.runSustainedWorkload()
	case "mixed":
		vu.runMixedWorkload()
	case "onboarding":
		vu.runTenantOnboardingWorkload()
	default:
		vu.runNormalWorkload()
	}
}

func (vu *VirtualUser) runNormalWorkload() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-vu.stop:
			return
		case <-ticker.C:
			vu.makeRandomRequest()
		}
	}
}

func (vu *VirtualUser) runBurstWorkload() {
	// Burst: Send requests as fast as possible
	for {
		select {
		case <-vu.stop:
			return
		default:
			vu.makeRandomRequest()
		}
	}
}

func (vu *VirtualUser) runSpikeWorkload() {
	// Spike: Alternating high/low traffic periods
	highTraffic := true
	toggleTicker := time.NewTicker(5 * time.Second)
	defer toggleTicker.Stop()

	for {
		select {
		case <-vu.stop:
			return
		case <-toggleTicker.C:
			highTraffic = !highTraffic
		default:
			if highTraffic {
				vu.makeRandomRequest()
			} else {
				time.Sleep(500 * time.Millisecond)
				vu.makeRandomRequest()
			}
		}
	}
}

func (vu *VirtualUser) runSustainedWorkload() {
	// Sustained: Constant moderate load
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-vu.stop:
			return
		case <-ticker.C:
			vu.makeRandomRequest()
		}
	}
}

func (vu *VirtualUser) runMixedWorkload() {
	// Mixed: Realistic user behavior simulation
	actions := []struct {
		weight int
		action func()
	}{
		{50, vu.actionGetMe},
		{20, vu.actionRefresh},
		{10, vu.actionHealth},
		{15, vu.actionLoginLogout},
		{5, vu.actionRegister},
	}

	totalWeight := 0
	for _, a := range actions {
		totalWeight += a.weight
	}

	for {
		select {
		case <-vu.stop:
			return
		default:
			// Pick a weighted random action
			r := rand.Intn(totalWeight)
			for _, a := range actions {
				r -= a.weight
				if r < 0 {
					a.action()
					break
				}
			}
			time.Sleep(time.Duration(50+rand.Intn(150)) * time.Millisecond)
		}
	}
}

func (vu *VirtualUser) runTenantOnboardingWorkload() {
	// Tenant Onboarding: Each user simulates a new tenant signing up
	// 1. Pick a unique tenant ID
	// 2. Register first user (admin)
	// 3. Login
	// 4. Create API Key

	ticker := time.NewTicker(2 * time.Second) // Slower interaction rate
	defer ticker.Stop()

	for {
		select {
		case <-vu.stop:
			return
		case <-ticker.C:
			// Switch to a new tenant context
			newTenantID := fmt.Sprintf("tenant-%d-%d", vu.id, time.Now().UnixNano())
			vu.client.tenantID = newTenantID

			// Register new admin for this tenant
			email := fmt.Sprintf("admin-%d-%d@test.local", vu.id, time.Now().UnixNano())
			resp, duration, err := vu.client.Register(email, "SecurePassword123!", "Tenant Admin")
			vu.recordMetric("/api/auth/register", "POST", statusCodeFromResp(resp), duration, err)
			if resp != nil {
				resp.Body.Close()
			}

			// Login with the new user
			accessToken, _, resp, duration, err := vu.client.Login(email, "SecurePassword123!")
			vu.recordMetric("/api/auth/login", "POST", statusCodeFromResp(resp), duration, err)
			if err == nil && accessToken != "" {
				// We don't update vu.accessToken/refreshToken/email permanently
				// because we want to switch context frequently, but for this iteration
				// we could use them if we wanted to do more actions.

				// Verify access with new token
				resp, duration, err := vu.client.GetMe(accessToken)
				vu.recordMetric("/api/me", "GET", statusCodeFromResp(resp), duration, err)
				if resp != nil {
					resp.Body.Close()
				}
			}
		}
	}
}

func statusCodeFromResp(resp *http.Response) int {
	if resp != nil {
		return resp.StatusCode
	}
	return 0
}

func (vu *VirtualUser) makeRandomRequest() {
	switch rand.Intn(4) {
	case 0:
		vu.actionGetMe()
	case 1:
		vu.actionRefresh()
	case 2:
		vu.actionHealth()
	case 3:
		vu.actionLoginLogout()
	}
}

func (vu *VirtualUser) actionGetMe() {
	resp, duration, err := vu.client.GetMe(vu.accessToken)
	vu.recordMetric("/api/me", "GET", statusCodeFromResp(resp), duration, err)
	if resp != nil {
		resp.Body.Close()
	}
}

func (vu *VirtualUser) actionRefresh() {
	if vu.refreshToken == "" {
		return
	}
	newToken, newRefreshToken, resp, duration, err := vu.client.Refresh(vu.refreshToken)
	vu.recordMetric("/api/auth/refresh", "POST", statusCodeFromResp(resp), duration, err)
	if newToken != "" {
		vu.accessToken = newToken
	}
	if newRefreshToken != "" {
		vu.refreshToken = newRefreshToken
	}
}

func (vu *VirtualUser) actionHealth() {
	resp, duration, err := vu.client.Health()
	vu.recordMetric("/health", "GET", statusCodeFromResp(resp), duration, err)
	if resp != nil {
		resp.Body.Close()
	}
}

func (vu *VirtualUser) actionLoginLogout() {
	accessToken, refreshToken, resp, duration, err := vu.client.Login(vu.email, "SecurePassword123!")
	vu.recordMetric("/api/auth/login", "POST", statusCodeFromResp(resp), duration, err)
	if accessToken != "" {
		vu.accessToken = accessToken
		vu.refreshToken = refreshToken
	}
}

func (vu *VirtualUser) actionRegister() {
	email := fmt.Sprintf("temp-user-%d-%d@test.local", vu.id, time.Now().UnixNano())
	resp, duration, err := vu.client.Register(email, "SecurePassword123!", "Temp User")
	vu.recordMetric("/api/auth/register", "POST", statusCodeFromResp(resp), duration, err)
	if resp != nil {
		resp.Body.Close()
	}
}

// =============================================================================
// Progress Display
// =============================================================================

type ProgressDisplay struct {
	collector *MetricsCollector
	duration  time.Duration
	startTime time.Time
	stop      chan struct{}
}

func NewProgressDisplay(collector *MetricsCollector, duration time.Duration) *ProgressDisplay {
	return &ProgressDisplay{
		collector: collector,
		duration:  duration,
		startTime: time.Now(),
		stop:      make(chan struct{}),
	}
}

func (pd *ProgressDisplay) Start() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pd.stop:
			fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
			return
		case <-ticker.C:
			elapsed := time.Since(pd.startTime)
			remaining := pd.duration - elapsed
			if remaining < 0 {
				remaining = 0
			}

			total := pd.collector.totalReqs.Load()
			success := pd.collector.successReqs.Load()
			errors := pd.collector.errorReqs.Load()
			rps := float64(total) / elapsed.Seconds()

			fmt.Printf("\r⏱️  %v remaining | 📊 %d requests (%.0f/s) | ✅ %d | ❌ %d  ",
				remaining.Round(time.Second), total, rps, success, errors)
		}
	}
}

func (pd *ProgressDisplay) Stop() {
	close(pd.stop)
}

// =============================================================================
// Benchmark Runner
// =============================================================================

type BenchmarkRunner struct {
	config    Config
	collector *MetricsCollector
	client    *BenchClient
	users     []*VirtualUser
	stop      chan struct{}
}

func NewBenchmarkRunner(config Config) *BenchmarkRunner {
	return &BenchmarkRunner{
		config:    config,
		collector: NewMetricsCollector(),
		client:    NewBenchClient(config.BaseURL, config.TenantID, config.Verbose),
		users:     make([]*VirtualUser, 0),
		stop:      make(chan struct{}),
	}
}

func (br *BenchmarkRunner) Run() error {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("🚀 AUTH SERVICE BENCHMARK")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("\n📋 Configuration\n")
	fmt.Printf("   Target:           %s\n", br.config.BaseURL)
	fmt.Printf("   Tenant:           %s\n", br.config.TenantID)
	fmt.Printf("   Virtual Users:    %d\n", br.config.NumUsers)
	fmt.Printf("   Duration:         %v\n", br.config.Duration)
	fmt.Printf("   Ramp-up:          %v\n", br.config.RampUpTime)
	fmt.Printf("   Scenario:         %s\n", br.config.Scenario)
	fmt.Println()

	// Health check
	fmt.Print("🔍 Checking service health... ")
	resp, _, err := br.client.Health()
	if err != nil {
		fmt.Println("❌")
		return fmt.Errorf("service health check failed: %w", err)
	}
	if resp.StatusCode != 200 {
		fmt.Println("❌")
		return fmt.Errorf("service returned status %d", resp.StatusCode)
	}
	resp.Body.Close()
	fmt.Println("✅")

	// Setup virtual users with ramp-up
	fmt.Printf("👥 Setting up %d virtual users...\n", br.config.NumUsers)
	usersPerStep := br.config.NumUsers / 5
	if usersPerStep < 1 {
		usersPerStep = 1
	}
	rampDelay := br.config.RampUpTime / 5

	var wg sync.WaitGroup

	for i := 0; i < br.config.NumUsers; i++ {
		vu := NewVirtualUser(i, br.client, br.collector, &wg, br.stop)
		if err := vu.Setup(); err != nil {
			fmt.Printf("   ⚠️  User %d setup warning: %v\n", i, err)
		}
		br.users = append(br.users, vu)

		// Ramp-up delay
		if i > 0 && i%usersPerStep == 0 && i < br.config.NumUsers-1 {
			fmt.Printf("   📈 Ramping up: %d/%d users ready\n", i, br.config.NumUsers)
			time.Sleep(rampDelay)
		}
	}
	fmt.Printf("✅ All %d users ready\n\n", br.config.NumUsers)

	// Start progress display
	progress := NewProgressDisplay(br.collector, br.config.Duration)
	go progress.Start()

	// Start workload
	fmt.Printf("🔥 Starting %s workload...\n", br.config.Scenario)
	for _, vu := range br.users {
		wg.Add(1)
		go vu.RunWorkload(br.config.Scenario)
	}

	// Run for duration
	time.Sleep(br.config.Duration)

	// Stop all users
	close(br.stop)
	wg.Wait()
	progress.Stop()

	// Generate report
	br.collector.Report()

	return nil
}

// =============================================================================
// Main
// =============================================================================

func main() {
	config := Config{}

	flag.StringVar(&config.BaseURL, "url", "http://localhost:3000", "Base URL of the auth service")
	flag.StringVar(&config.TenantID, "tenant", "benchmark-tenant", "Tenant ID to use")
	flag.IntVar(&config.NumUsers, "users", 50, "Number of virtual users")
	flag.DurationVar(&config.Duration, "duration", 30*time.Second, "Test duration")
	flag.DurationVar(&config.RampUpTime, "rampup", 5*time.Second, "Ramp-up time")
	flag.StringVar(&config.Scenario, "scenario", "mixed", "Scenario: normal, burst, spike, sustained, mixed")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")

	flag.Parse()

	runner := NewBenchmarkRunner(config)
	if err := runner.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ Benchmark failed: %v\n", err)
		os.Exit(1)
	}
}
