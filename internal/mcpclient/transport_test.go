package mcpclient

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (call roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return call(request)
}

func TestOnlySessionCleanupGetsShortDeadline(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			var captured context.Context
			transport := cleanupTransport{roundTripFunc(func(request *http.Request) (*http.Response, error) {
				captured = request.Context()
				return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader(""))}, nil
			})}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1/mcp", nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := transport.RoundTrip(request)
			if err != nil {
				t.Fatal(err)
			}
			deadline, ok := captured.Deadline()
			if !ok {
				t.Fatal("request lost deadline")
			}
			if method == http.MethodDelete && time.Until(deadline) > 2*time.Second {
				t.Fatal("session cleanup retained long call timeout")
			}
			if method == http.MethodPost && captured != ctx {
				t.Fatal("normal MCP call context was changed")
			}
			if err := response.Body.Close(); err != nil {
				t.Fatal(err)
			}
			if method == http.MethodDelete && captured.Err() == nil {
				t.Fatal("closed cleanup response retained its timer")
			}
		})
	}
}
