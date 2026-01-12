# Auth Service Benchmark

A comprehensive load testing tool for the GoFiber authentication service.

## Features

- 🔥 **Multiple Traffic Scenarios**: Normal, burst, spike, sustained, and mixed workloads
- 👥 **Virtual Users**: Simulates realistic user sessions with authentication
- 📊 **Detailed Metrics**: Latency percentiles (p50, p95, p99), throughput, error rates
- 📈 **Real-time Progress**: Live status updates during benchmark execution
- 🎯 **Endpoint Coverage**: Tests registration, login, token refresh, and protected routes

## Quick Start

```bash
# From the benchmark directory
cd benchmark

# Run with defaults (50 users, 30s duration, mixed scenario)
go run benchmark.go

# Custom configuration
go run benchmark.go -users 100 -duration 60s -scenario burst
```

## Usage

```
Usage of benchmark:
  -url string
        Base URL of the auth service (default "http://localhost:3000")
  -tenant string
        Tenant ID to use (default "benchmark-tenant")
  -users int
        Number of virtual users (default 50)
  -duration duration
        Test duration (default 30s)
  -rampup duration
        Ramp-up time (default 5s)
  -scenario string
        Scenario: normal, burst, spike, sustained, mixed (default "mixed")
  -verbose
        Enable verbose output
```

## Traffic Scenarios

### Normal
Standard traffic pattern with ~10 requests per second per user.

```bash
go run benchmark.go -scenario normal
```

### Burst
Maximum possible request rate - tests the service under extreme load.

```bash
go run benchmark.go -scenario burst -users 100
```

### Spike
Alternating high/low traffic every 5 seconds - simulates traffic spikes.

```bash
go run benchmark.go -scenario spike -duration 1m
```

### Sustained
Constant moderate load (~20 requests/sec per user) - tests service stability.

```bash
go run benchmark.go -scenario sustained -users 200 -duration 2m
```

### Mixed (Default)
Realistic user behavior simulation with weighted random actions:
- 50% Get user profile
- 20% Token refresh
- 15% Login/logout cycles
- 10% Health checks
- 5% New registrations

```bash
go run benchmark.go -scenario mixed -users 100 -duration 1m
```

## Example Runs

### Light Load Test
```bash
go run benchmark.go -users 10 -duration 15s
```

### Extreme Traffic Test
```bash
go run benchmark.go -users 500 -duration 60s -scenario burst
```

### Stability Test (Long Duration)
```bash
go run benchmark.go -users 50 -duration 5m -scenario sustained
```

## Sample Output

```
================================================================================
🚀 AUTH SERVICE BENCHMARK
================================================================================

📋 Configuration
   Target:           http://localhost:3000
   Tenant:           benchmark-tenant
   Virtual Users:    50
   Duration:         30s
   Ramp-up:          5s
   Scenario:         mixed

🔍 Checking service health... ✅
👥 Setting up 50 virtual users...
   📈 Ramping up: 10/50 users ready
   📈 Ramping up: 20/50 users ready
   📈 Ramping up: 30/50 users ready
   📈 Ramping up: 40/50 users ready
✅ All 50 users ready

🔥 Starting mixed workload...

================================================================================
BENCHMARK RESULTS
================================================================================

📊 Overall Summary
   Duration:         30.001s
   Total Requests:   15234
   Successful:       15189 (99.70%)
   Failed:           45 (0.30%)
   Throughput:       507.78 req/s

📈 Per-Endpoint Metrics

Endpoint              Reqs     Success  Errors  Avg       p50       p95       p99       Min       Max
--------              ----     -------  ------  ---       ---       ---       ---       ---       ---
GET /api/me           7523     7500     23      2.341ms   1.892ms   5.234ms   12.456ms  456µs     89.234ms
POST /api/auth/login  2341     2330     11      8.456ms   6.234ms   18.456ms  34.567ms  1.234ms   156.789ms
POST /api/auth/refresh 1523    1519     4       4.567ms   3.456ms   9.234ms   18.234ms  789µs     78.456ms
GET /health           1523     1523     0       234µs     189µs     567µs     1.234ms   89µs      12.345ms
POST /api/auth/register 324    317     7       12.345ms  9.456ms   24.567ms  45.678ms  2.345ms   234.567ms

📋 Status Code Distribution

   ✅ HTTP 200: 14789 requests
   ✅ HTTP 201: 400 requests
   ❌ HTTP 400: 20 requests
   ❌ HTTP 401: 15 requests
   ❌ HTTP 500: 10 requests

================================================================================
```

## Metrics Explained

| Metric | Description |
|--------|-------------|
| **Throughput** | Total requests per second across all users |
| **Avg** | Average response time |
| **p50** | Median response time (50th percentile) |
| **p95** | 95th percentile response time |
| **p99** | 99th percentile response time |
| **Min/Max** | Minimum and maximum observed response times |

## Tips for Accurate Benchmarking

1. **Warm up the service** before running benchmarks
2. **Run multiple iterations** to get consistent results
3. **Monitor server resources** (CPU, memory, connections) during tests
4. **Test in isolation** without other traffic
5. **Use realistic scenarios** for production capacity planning
