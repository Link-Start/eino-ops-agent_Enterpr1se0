package service

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/mcpclient"
	"github.com/Enterpr1se0/opsnerva/internal/observability"
	"github.com/cloudwego/eino/components/tool"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func (s *Service) InitializeMCPServers(ctx context.Context) error {
	servers, err := s.store.ListMCPServers(ctx)
	if err != nil {
		return err
	}
	for _, server := range servers {
		if !server.Enabled {
			s.mcpClients.Disconnect(server.ID, "disabled")
			continue
		}
		if err := s.ReconnectMCPServer(ctx, server.ID); err != nil {
			observability.FromContext(ctx).WarnContext(ctx, "MCP server initialization failed", "component", "mcp_client", "server_id", server.ID, "server_name", server.Name, "error", err)
		}
	}
	return nil
}

func (s *Service) ListMCPServers(ctx context.Context) ([]domain.MCPServer, error) {
	servers, err := s.store.ListMCPServers(ctx)
	if err != nil {
		return nil, err
	}
	for index := range servers {
		servers[index] = s.decorateMCPServer(servers[index])
	}
	return servers, nil
}

func (s *Service) GetMCPServer(ctx context.Context, id string) (domain.MCPServer, error) {
	server, err := s.store.GetMCPServer(ctx, id)
	if err != nil {
		return domain.MCPServer{}, err
	}
	return s.decorateMCPServer(server), nil
}

func (s *Service) SetMCPServerEnabled(ctx context.Context, id string, enabled bool, actor string) (domain.MCPServer, error) {
	s.mcpSecretsMu.Lock()
	server, err := s.store.GetMCPServer(ctx, id)
	if err == nil {
		err = s.store.SetMCPServerEnabled(ctx, id, enabled)
	}
	if err == nil && !enabled {
		s.cancelMCPOAuthFlow(id)
		s.mcpClients.Disconnect(id, "disabled")
	}
	s.mcpSecretsMu.Unlock()
	if err != nil {
		return domain.MCPServer{}, err
	}
	if enabled {
		_ = s.ReconnectMCPServer(ctx, id)
	}
	eventType := "mcp_server_disabled"
	if enabled {
		eventType = "mcp_server_enabled"
	}
	s.audit(ctx, "", eventType, actor, map[string]any{"server_id": id, "name": server.Name})
	return s.GetMCPServer(ctx, id)
}

func (s *Service) DeleteMCPServer(ctx context.Context, id, actor string) error {
	s.mcpSecretsMu.Lock()
	server, err := s.store.GetMCPServer(ctx, id)
	if err == nil {
		err = s.store.DeleteMCPServer(ctx, id)
	}
	if err == nil {
		s.cancelMCPOAuthFlow(id)
		s.mcpClients.Forget(id)
	}
	s.mcpSecretsMu.Unlock()
	if err != nil {
		return err
	}
	s.audit(ctx, "", "mcp_server_deleted", actor, map[string]any{"server_id": id, "name": server.Name})
	return nil
}

func (s *Service) ReconnectMCPServer(ctx context.Context, id string) error {
	connectCtx, cancel := context.WithTimeout(ctx, mcpclient.ConnectTimeout)
	defer cancel()
	// Config reads and generation reservation share the same lock as writes.
	// No network operation runs while it is held.
	s.mcpSecretsMu.Lock()
	server, err := s.store.GetMCPServer(connectCtx, id)
	var connection *mcpclient.Connection
	if err == nil && !server.Enabled {
		err = fmt.Errorf("MCP server is disabled")
	}
	if err == nil {
		s.cancelMCPOAuthFlow(id)
		connection, err = s.mcpClients.Begin(connectCtx, id)
	}
	s.mcpSecretsMu.Unlock()
	if err != nil {
		return err
	}
	started := time.Now()
	err = connection.Run(s.openMCPConnection(server, connection))
	if err != nil {
		observability.FromContext(ctx).ErrorContext(ctx, "MCP server connection failed", "component", "mcp_client", "server_id", id, "server_name", server.Name, "transport", server.Transport, "duration_ms", time.Since(started).Milliseconds(), "error", err)
		return err
	}
	observability.FromContext(ctx).InfoContext(ctx, "MCP server ready", "component", "mcp_client", "server_id", id, "server_name", server.Name, "transport", server.Transport, "tool_count", len(s.mcpClients.Snapshot(id).Tools), "duration_ms", time.Since(started).Milliseconds())
	return nil
}

func (s *Service) TestMCPServer(ctx context.Context, id string) (domain.MCPTestResult, error) {
	testCtx, cancel := context.WithTimeout(ctx, mcpclient.ConnectTimeout)
	defer cancel()
	s.mcpSecretsMu.Lock()
	server, err := s.store.GetMCPServer(testCtx, id)
	var connection *mcpclient.Connection
	if err == nil {
		connection, err = s.mcpClients.BeginTest(testCtx, id)
	}
	s.mcpSecretsMu.Unlock()
	if err != nil {
		return domain.MCPTestResult{}, err
	}
	return connection.Test(s.openMCPConnection(server, connection))
}

func (s *Service) MCPTools() []tool.BaseTool { return s.mcpClients.Tools() }

func (s *Service) observeMCPCall(ctx context.Context, info mcpclient.CallInfo) {
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	s.audit(auditCtx, "", "mcp_tool_called", "eino-agent", map[string]any{
		"server_id": info.ServerID, "tool_name": info.ToolName, "status": info.Status,
		"duration_ms": info.Duration.Milliseconds(), "session_id": SessionIDFromContext(ctx),
	})
}

func (s *Service) openMCPConnection(server domain.MCPServer, connection *mcpclient.Connection) mcpclient.Open {
	return func(ctx context.Context) (mcpclient.Session, []tool.BaseTool, error) {
		secrets, err := s.decryptMCPSecrets(server.SecretsCipher)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt MCP secrets: %w", err)
		}
		var handler auth.OAuthHandler
		if server.Transport == domain.MCPTransportStreamableHTTP && secrets.OAuth != nil {
			oauthClient := &http.Client{Timeout: mcpclient.CallTimeout, Transport: http.DefaultTransport}
			handler, err = s.restoredMCPOAuthHandler(server.ID, secrets.OAuth, oauthClient, connection)
			if err != nil {
				return nil, nil, fmt.Errorf("restore MCP OAuth session: %w", err)
			}
		}
		return s.mcpClients.Open(ctx, mcpclient.Config{Server: server, Env: secrets.Env, Headers: secrets.Headers, OAuth: handler})
	}
}

func (s *Service) decorateMCPServer(server domain.MCPServer) domain.MCPServer {
	if secrets, err := s.decryptMCPSecrets(server.SecretsCipher); err == nil && secrets.OAuth != nil {
		server.OAuthConfigured = true
		if !secrets.OAuth.Expiry.IsZero() {
			expiresAt := secrets.OAuth.Expiry
			server.OAuthExpiresAt = &expiresAt
		}
	}
	state := s.mcpClients.Snapshot(server.ID)
	server.Status, server.LastError, server.ConnectedAt = state.Status, state.LastError, state.ConnectedAt
	server.Tools = state.Tools
	server.ToolCount = len(state.Tools)
	if server.Status == "" {
		if server.Enabled {
			server.Status = "disconnected"
		} else {
			server.Status = "disabled"
		}
	}
	server.SecretsCipher = ""
	return server
}
