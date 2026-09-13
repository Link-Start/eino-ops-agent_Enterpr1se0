package httpapi

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Enterpr1se0/opsnerva/internal/sshtunnel"
)

func TestTunnelNotFoundIsHTTP404(t *testing.T) {
	response := httptest.NewRecorder()
	writeError(response, fmt.Errorf("retry tunnel: %w", sshtunnel.ErrNotFound))
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown tunnel HTTP status = %d", response.Code)
	}
}
