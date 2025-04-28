package ratelimiter

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateLimiterMiddleware(t *testing.T) {

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	tests := []struct {
		name          string
		limit         rate.Limit
		burst         int
		requests      int
		expectedCodes []int
		sleep         time.Duration
	}{
		{
			name:          "single request within limit",
			limit:         rate.Limit(1),
			burst:         1,
			requests:      1,
			expectedCodes: []int{http.StatusOK},
			sleep:         0,
		},
		{
			name:          "burst requests partially allowed",
			limit:         rate.Limit(1),
			burst:         2,
			requests:      3,
			expectedCodes: []int{http.StatusOK, http.StatusOK, http.StatusTooManyRequests},
			sleep:         0,
		},
		{
			name:          "requests with delay",
			limit:         rate.Limit(2),
			burst:         1,
			requests:      2,
			expectedCodes: []int{http.StatusOK, http.StatusOK},
			sleep:         time.Second / 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := RateLimiterMiddleware(testHandler, tt.limit, tt.burst)

			for i := 0; i < tt.requests; i++ {
				// Create request with a test IP
				req := httptest.NewRequest("GET", "/test", nil)
				req.RemoteAddr = "192.0.2.1:1234" // Test IP address
				rec := httptest.NewRecorder()

				// Send request
				handler.ServeHTTP(rec, req)

				// Check status code
				if rec.Code != tt.expectedCodes[i] {
					t.Errorf("request %d: expected status code %d, got %d",
						i+1, tt.expectedCodes[i], rec.Code)
				}

				// Check error response for rate limited requests
				if rec.Code == http.StatusTooManyRequests {
					var response map[string]string
					if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
						t.Errorf("failed to decode response: %v", err)
					}
					if msg, ok := response["error"]; !ok || msg != "Too many requests" {
						t.Errorf("expected error message 'Too many requests', got %q", msg)
					}
				}

				if tt.sleep > 0 {
					time.Sleep(tt.sleep)
				}
			}
		})
	}
}
