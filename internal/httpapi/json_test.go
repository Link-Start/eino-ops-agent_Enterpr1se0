package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeLimitJSONContract(t *testing.T) {
	tests := []struct {
		name     string
		body     []byte
		maxBytes int64
		wantOK   bool
		wantName string
	}{
		{name: "valid", body: []byte(`{"name":"opsnerva"}`), maxBytes: 64, wantOK: true, wantName: "opsnerva"},
		{name: "unknown field", body: []byte(`{"name":"opsnerva","extra":true}`), maxBytes: 64},
		{name: "case mismatch", body: []byte(`{"Name":"opsnerva"}`), maxBytes: 64},
		{name: "duplicate field", body: []byte(`{"name":"first","name":"second"}`), maxBytes: 64},
		{name: "invalid UTF-8", body: append([]byte(`{"name":"`), 0xff, '"', '}'), maxBytes: 64},
		{name: "multiple values", body: []byte(`{"name":"first"}{"name":"second"}`), maxBytes: 64},
		{name: "empty body", body: nil, maxBytes: 64},
		{name: "oversized", body: []byte(`{"name":"opsnerva"}`), maxBytes: 8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(test.body))
			response := httptest.NewRecorder()
			var input struct {
				Name string `json:"name"`
			}

			if got := decodeLimit(response, request, &input, test.maxBytes); got != test.wantOK {
				t.Fatalf("decodeLimit() = %t, want %t; status=%d body=%s", got, test.wantOK, response.Code, response.Body.String())
			}
			if test.wantOK {
				if input.Name != test.wantName {
					t.Fatalf("name = %q, want %q", input.Name, test.wantName)
				}
				if response.Body.Len() != 0 {
					t.Fatalf("successful decode wrote response body %q", response.Body.String())
				}
				return
			}
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
			}
			if !strings.Contains(response.Body.String(), "invalid JSON:") {
				t.Fatalf("error response = %q", response.Body.String())
			}
		})
	}
}
