package ratelimiter

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

/*
	next - next handlerfunction to be served

limit - amount of requests allowed per second
burst - num Events that can happen at once
*/
func RateLimiterMiddleware(next http.Handler, limit rate.Limit, burst int) http.Handler {
	ipLimiterMap := make(map[string]*rate.Limiter)
	var mu sync.Mutex

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "error executing rate limiter middleware: could not retrieve ip address", http.StatusInternalServerError)
		}

		mu.Lock()
		limiter, ok := ipLimiterMap[host]
		if !ok {
			limiter = rate.NewLimiter(limit, burst)
			ipLimiterMap[host] = limiter
		}
		mu.Unlock()

		if !limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{"error": "Too many requests"})
			return
		}
		next.ServeHTTP(w, r)
	})
}
