package service

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/mcpclient"
	"github.com/cloudwego/eino/components/tool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"
)

func TestMCPDisableCancelsInFlightCallAndPreservesAudit(t *testing.T) {
	svc, _, _ := newTestService(t)
	entered, gate := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	remote := mcp.NewServer(&mcp.Implementation{Name: "blocking", Version: "1"}, nil)
	mcp.AddTool(remote, &mcp.Tool{Name: "slow"}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		close(entered)
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-gate:
			return &mcp.CallToolResult{}, nil, nil
		}
	})
	httpServer := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return remote }, nil))
	defer httpServer.Close()
	defer release()
	server, err := svc.SaveMCPServer(context.Background(), domain.MCPServerInput{Name: "Blocking MCP", Transport: domain.MCPTransportStreamableHTTP, URL: httpServer.URL, Enabled: true}, "test")
	if err != nil {
		t.Fatal(err)
	}
	invokable := svc.MCPTools()[0].(tool.InvokableTool)
	result := make(chan error, 1)
	go func() {
		_, err := invokable.InvokableRun(WithSessionID(context.Background(), "mcp-cancellation-test"), `{}`)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("tool never entered")
	}
	disableCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	disabled, err := svc.SetMCPServerEnabled(disableCtx, server.ID, false, "test")
	if err != nil || disabled.Status != "disabled" {
		t.Fatalf("disable = %#v, %v", disabled, err)
	}
	select {
	case err := <-result:
		if err == nil || errors.Is(err, context.Canceled) {
			t.Fatalf("in-flight call outcome = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("disabled connection did not release call")
	}
	if _, err := invokable.InvokableRun(context.Background(), `{}`); err == nil {
		t.Fatal("old wrapper remained callable")
	}
	events, err := svc.ListAudit(context.Background(), "", 100)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	for _, event := range events {
		if event.Type == "mcp_tool_called" {
			calls++
			if event.Data["status"] != "failed" || event.Data["session_id"] != "mcp-cancellation-test" {
				t.Fatalf("cancelled call lost audit context: %#v", event)
			}
		}
	}
	if calls != 1 {
		t.Fatalf("call audits = %d, want exactly one dispatched call", calls)
	}
}

func TestMCPConnectingCannotUndoDisable(t *testing.T) {
	svc, _, _ := newTestService(t)
	entered, gate := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	var first sync.Once
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		first.Do(func() { close(entered) })
		select {
		case <-r.Context().Done():
			return
		case <-gate:
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer httpServer.Close()
	defer release()
	server, err := svc.SaveMCPServer(context.Background(), domain.MCPServerInput{Name: "Connecting MCP", Transport: domain.MCPTransportStreamableHTTP, URL: httpServer.URL}, "test")
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, _ = svc.SetMCPServerEnabled(context.Background(), server.ID, true, "test")
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("connection never entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := svc.SetMCPServerEnabled(ctx, server.ID, false, "test"); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case <-finished:
	case <-time.After(3 * time.Second):
		t.Fatal("connecting operation ignored disable")
	}
	current, err := svc.GetMCPServer(context.Background(), server.ID)
	if err != nil || current.Enabled || current.Status != "disabled" || current.LastError != "" || len(svc.MCPTools()) != 0 {
		t.Fatalf("late connection overwrote disabled configuration: %#v, %v", current, err)
	}
}

type oauthTestSession struct {
	closed chan struct{}
	once   sync.Once
}

func (s *oauthTestSession) ListTools(context.Context, *mcp.ListToolsParams) (*mcp.ListToolsResult, error) {
	return &mcp.ListToolsResult{}, nil
}
func (s *oauthTestSession) CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	return &mcp.CallToolResult{}, nil
}
func (s *oauthTestSession) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
func (s *oauthTestSession) Wait() error  { <-s.closed; return nil }

func TestMCPOAuthRefreshSurvivesStartupAndRejectsStaleWrites(t *testing.T) {
	svc, _, _ := newTestService(t)
	server, err := svc.SaveMCPServer(context.Background(), domain.MCPServerInput{Name: "OAuth refresh", Transport: domain.MCPTransportStreamableHTTP, URL: "http://127.0.0.1:8080/mcp"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	startup, cancelStartup := context.WithCancel(context.Background())
	defer cancelStartup()
	generation, err := svc.mcpClients.Begin(startup, server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := generation.Run(func(context.Context) (mcpclient.Session, []tool.BaseTool, error) {
		return &oauthTestSession{closed: make(chan struct{})}, nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	cancelStartup()
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" {
			http.Error(w, "invalid refresh", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"fresh-token","token_type":"Bearer","refresh_token":"next-refresh","expires_in":3600}`))
	}))
	defer tokenServer.Close()
	config := &oauth2.Config{ClientID: "fixture", Endpoint: oauth2.Endpoint{TokenURL: tokenServer.URL, AuthStyle: oauth2.AuthStyleInParams}}
	source := svc.savingMCPOAuthTokenSource(server.ID, tokenServer.Client(), config, &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)}, generation)
	token, err := source.Token()
	if err != nil || token.AccessToken != "fresh-token" {
		t.Fatalf("refresh depended on cancelled startup: %#v, %v", token, err)
	}
	stored, err := svc.store.GetMCPServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored.SecretsCipher, "fresh-token") {
		t.Fatal("refresh token stored in plaintext")
	}
	secrets, err := svc.decryptMCPSecrets(stored.SecretsCipher)
	if err != nil || secrets.OAuth == nil || secrets.OAuth.AccessToken != "fresh-token" {
		t.Fatalf("refresh not persisted: %#v, %v", secrets.OAuth, err)
	}
	if _, err := svc.ClearMCPOAuth(context.Background(), server.ID, "test"); err != nil {
		t.Fatal(err)
	}
	if err := svc.persistMCPOAuthSession(server.ID, config, &oauth2.Token{AccessToken: "late-token"}, generation); !errors.Is(err, context.Canceled) {
		t.Fatalf("stale token write accepted: %v", err)
	}
	stored, err = svc.store.GetMCPServer(context.Background(), server.ID)
	if err != nil {
		t.Fatal(err)
	}
	secrets, err = svc.decryptMCPSecrets(stored.SecretsCipher)
	if err != nil || secrets.OAuth != nil {
		t.Fatalf("late refresh resurrected cleared OAuth: %#v, %v", secrets.OAuth, err)
	}
}
