package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/mcpclient"
	"github.com/cloudwego/eino/components/tool"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

const mcpOAuthFlowTimeout = 10 * time.Minute

type mcpOAuthCallback struct {
	result *auth.AuthorizationResult
	err    error
}

type mcpOAuthFlow struct {
	generation *mcpclient.Connection
	serverID   string
	serverURL  string
	actor      string
	cancel     context.CancelFunc

	mu               sync.Mutex
	authorizationURL string
	state            string
	err              error
	authReady        chan struct{}
	authReadyOnce    sync.Once
	callback         chan mcpOAuthCallback
	done             chan struct{}
}

func (s *Service) BeginMCPOAuth(ctx context.Context, serverID, redirectURL, actorName string) (domain.MCPOAuthStart, error) {
	if err := validateMCPOAuthRedirectURL(redirectURL); err != nil {
		return domain.MCPOAuthStart{}, err
	}
	s.mcpSecretsMu.Lock()
	server, err := s.store.GetMCPServer(ctx, serverID)
	if err == nil && server.Transport != domain.MCPTransportStreamableHTTP {
		err = fmt.Errorf("OAuth is supported only for Streamable HTTP MCP servers")
	}
	if err == nil && !server.Enabled {
		err = fmt.Errorf("MCP server must be enabled before authorization")
	}
	if err != nil {
		s.mcpSecretsMu.Unlock()
		return domain.MCPOAuthStart{}, err
	}
	flowCtx, cancel := context.WithTimeout(s.executionCtx, mcpOAuthFlowTimeout)
	s.mcpOAuthMu.Lock()
	if s.mcpOAuthClosed {
		s.mcpOAuthMu.Unlock()
		s.mcpSecretsMu.Unlock()
		cancel()
		return domain.MCPOAuthStart{}, fmt.Errorf("MCP client is shutting down")
	}
	generation, err := s.mcpClients.Begin(flowCtx, server.ID)
	if err != nil {
		s.mcpOAuthMu.Unlock()
		s.mcpSecretsMu.Unlock()
		cancel()
		return domain.MCPOAuthStart{}, err
	}
	flow := &mcpOAuthFlow{generation: generation, serverID: server.ID, serverURL: server.URL, actor: actorName, cancel: cancel,
		authReady: make(chan struct{}), callback: make(chan mcpOAuthCallback, 1), done: make(chan struct{})}
	if previous := s.mcpOAuthByServer[server.ID]; previous != nil {
		previous.cancel()
	}
	s.mcpOAuthByServer[server.ID] = flow
	s.mcpOAuthWG.Add(1)
	s.mcpOAuthMu.Unlock()
	s.mcpSecretsMu.Unlock()

	go s.runMCPOAuthFlow(flow, server, redirectURL)
	select {
	case <-flow.authReady:
		flow.mu.Lock()
		start := domain.MCPOAuthStart{AuthorizationURL: flow.authorizationURL}
		flow.mu.Unlock()
		return start, nil
	case <-flow.done:
		return domain.MCPOAuthStart{}, flowError(flow)
	case <-ctx.Done():
		cancel()
		return domain.MCPOAuthStart{}, ctx.Err()
	}
}

func (s *Service) CompleteMCPOAuth(ctx context.Context, state, code, issuer, authorizationError string) error {
	if state == "" {
		return fmt.Errorf("OAuth state is required")
	}
	s.mcpOAuthMu.Lock()
	flow := s.mcpOAuthFlows[state]
	s.mcpOAuthMu.Unlock()
	if flow == nil {
		return fmt.Errorf("OAuth flow is invalid or expired")
	}
	callback := mcpOAuthCallback{result: &auth.AuthorizationResult{Code: code, State: state, Iss: issuer}}
	if authorizationError != "" {
		callback.err = fmt.Errorf("OAuth authorization failed: %s", authorizationError)
	} else if code == "" {
		callback.err = fmt.Errorf("OAuth authorization code is required")
	}
	select {
	case flow.callback <- callback:
	case <-flow.done:
		return flowError(flow)
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-flow.done:
		return flowError(flow)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) ClearMCPOAuth(ctx context.Context, serverID, actorName string) (domain.MCPServer, error) {
	s.mcpSecretsMu.Lock()
	server, err := s.store.GetMCPServer(ctx, serverID)
	if err != nil {
		s.mcpSecretsMu.Unlock()
		return domain.MCPServer{}, err
	}
	secrets, err := s.decryptMCPSecrets(server.SecretsCipher)
	if err != nil {
		s.mcpSecretsMu.Unlock()
		return domain.MCPServer{}, err
	}
	secrets.OAuth = nil
	if err := s.persistMCPSecrets(ctx, server.ID, secrets); err != nil {
		s.mcpSecretsMu.Unlock()
		return domain.MCPServer{}, err
	}
	s.cancelMCPOAuthFlow(server.ID)
	status := "disabled"
	if server.Enabled {
		status = "disconnected"
	}
	s.mcpClients.Disconnect(server.ID, status)
	s.mcpSecretsMu.Unlock()
	if server.Enabled {
		_ = s.ReconnectMCPServer(ctx, server.ID)
	}
	s.audit(ctx, "", "mcp_oauth_cleared", actorName, map[string]any{"server_id": server.ID, "name": server.Name})
	return s.GetMCPServer(ctx, server.ID)
}

func (s *Service) runMCPOAuthFlow(flow *mcpOAuthFlow, server domain.MCPServer, redirectURL string) {
	defer s.mcpOAuthWG.Done()
	defer flow.cancel()
	defer close(flow.done)
	defer s.removeMCPOAuthFlow(flow)
	err := flow.generation.Run(func(ctx context.Context) (mcpclient.Session, []tool.BaseTool, error) {
		secrets, err := s.decryptMCPSecrets(server.SecretsCipher)
		if err != nil {
			return nil, nil, err
		}
		oauthClient := &http.Client{Timeout: mcpclient.CallTimeout, Transport: http.DefaultTransport}
		handler, err := auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
			RedirectURL: redirectURL,
			DynamicClientRegistrationConfig: &auth.DynamicClientRegistrationConfig{Metadata: &oauthex.ClientRegistrationMetadata{
				RedirectURIs: []string{redirectURL}, TokenEndpointAuthMethod: "none",
				GrantTypes: []string{"authorization_code", "refresh_token"}, ResponseTypes: []string{"code"}, ClientName: "OpsNerva",
			}},
			AuthorizationCodeFetcher: func(fetchCtx context.Context, args *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
				if err := s.publishMCPOAuthURL(flow, args.URL); err != nil {
					return nil, err
				}
				select {
				case callback := <-flow.callback:
					return callback.result, callback.err
				case <-fetchCtx.Done():
					return nil, fetchCtx.Err()
				}
			},
			RequestRefreshToken: true,
			Client:              oauthClient,
			NewTokenSource: func(_ context.Context, config *oauth2.Config, token *oauth2.Token) (oauth2.TokenSource, error) {
				if err := s.persistMCPOAuthSession(flow.serverID, config, token, flow.generation); err != nil {
					return nil, err
				}
				return s.savingMCPOAuthTokenSource(flow.serverID, oauthClient, config, token, flow.generation), nil
			},
		})
		if err != nil {
			return nil, nil, err
		}

		session, tools, err := s.mcpClients.Open(ctx, mcpclient.Config{Server: server, Headers: secrets.Headers, OAuth: handler})
		if err != nil {
			return nil, nil, err
		}
		current, err := s.store.GetMCPServer(ctx, server.ID)
		if err == nil && (!current.Enabled || current.URL != flow.serverURL || !s.mcpOAuthFlowCurrent(flow)) {
			err = errors.New("MCP server changed during OAuth authorization")
		}
		return session, tools, err
	})
	if err == nil {
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		s.audit(auditCtx, "", "mcp_oauth_authorized", flow.actor, map[string]any{"server_id": server.ID, "name": server.Name})
		cancel()
	}
	s.finishMCPOAuthFlow(flow, err)
}

func (s *Service) publishMCPOAuthURL(flow *mcpOAuthFlow, authorizationURL string) error {
	parsed, err := url.Parse(authorizationURL)
	if err != nil {
		return fmt.Errorf("invalid OAuth authorization URL: %w", err)
	}
	state := parsed.Query().Get("state")
	if state == "" {
		return fmt.Errorf("OAuth authorization URL has no state")
	}
	flow.mu.Lock()
	flow.authorizationURL = authorizationURL
	flow.mu.Unlock()
	s.mcpOAuthMu.Lock()
	if s.mcpOAuthByServer[flow.serverID] != flow {
		s.mcpOAuthMu.Unlock()
		return context.Canceled
	}
	flow.state = state
	s.mcpOAuthFlows[state] = flow
	s.mcpOAuthMu.Unlock()
	flow.authReadyOnce.Do(func() { close(flow.authReady) })
	return nil
}

func (s *Service) removeMCPOAuthFlow(flow *mcpOAuthFlow) {
	s.mcpOAuthMu.Lock()
	defer s.mcpOAuthMu.Unlock()
	if s.mcpOAuthByServer[flow.serverID] == flow {
		delete(s.mcpOAuthByServer, flow.serverID)
	}
	if flow.state != "" && s.mcpOAuthFlows[flow.state] == flow {
		delete(s.mcpOAuthFlows, flow.state)
	}
}

func (s *Service) cancelMCPOAuthFlow(serverID string) {
	s.mcpOAuthMu.Lock()
	flow := s.mcpOAuthByServer[serverID]
	if flow != nil {
		delete(s.mcpOAuthByServer, serverID)
		if flow.state != "" && s.mcpOAuthFlows[flow.state] == flow {
			delete(s.mcpOAuthFlows, flow.state)
		}
	}
	s.mcpOAuthMu.Unlock()
	if flow != nil {
		flow.cancel()
	}
}

func (s *Service) mcpOAuthFlowCurrent(flow *mcpOAuthFlow) bool {
	s.mcpOAuthMu.Lock()
	defer s.mcpOAuthMu.Unlock()
	return s.mcpOAuthByServer[flow.serverID] == flow
}

func (s *Service) cancelAllMCPOAuthFlows() {
	s.mcpOAuthMu.Lock()
	s.mcpOAuthClosed = true
	flows := make([]*mcpOAuthFlow, 0, len(s.mcpOAuthByServer))
	for _, flow := range s.mcpOAuthByServer {
		flows = append(flows, flow)
	}
	s.mcpOAuthFlows = make(map[string]*mcpOAuthFlow)
	s.mcpOAuthByServer = make(map[string]*mcpOAuthFlow)
	s.mcpOAuthMu.Unlock()
	for _, flow := range flows {
		flow.cancel()
	}
}

func (s *Service) finishMCPOAuthFlow(flow *mcpOAuthFlow, err error) {
	flow.mu.Lock()
	flow.err = err
	flow.mu.Unlock()
}

func flowError(flow *mcpOAuthFlow) error {
	flow.mu.Lock()
	defer flow.mu.Unlock()
	return flow.err
}

func validateMCPOAuthRedirectURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid OAuth redirect URL")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	host := parsed.Hostname()
	if parsed.Scheme != "http" || (host != "localhost" && host != "127.0.0.1" && host != "[::1]" && host != "::1") {
		return fmt.Errorf("OAuth callback requires HTTPS or a loopback address")
	}
	return nil
}
