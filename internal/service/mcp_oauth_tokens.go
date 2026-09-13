package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/mcpclient"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/oauth2"
)

type mcpOAuthSession struct {
	ClientID     string           `json:"client_id"`
	ClientSecret string           `json:"client_secret,omitempty"`
	AuthURL      string           `json:"auth_url"`
	TokenURL     string           `json:"token_url"`
	AuthStyle    oauth2.AuthStyle `json:"auth_style"`
	RedirectURL  string           `json:"redirect_url"`
	Scopes       []string         `json:"scopes,omitempty"`
	AccessToken  string           `json:"access_token"`
	TokenType    string           `json:"token_type,omitempty"`
	RefreshToken string           `json:"refresh_token,omitempty"`
	Expiry       time.Time        `json:"expiry,omitempty"`
}

type mcpSavingTokenSource struct {
	mu       sync.Mutex
	source   oauth2.TokenSource
	config   *oauth2.Config
	previous *oauth2.Token
	save     func(*oauth2.Config, *oauth2.Token) error
}

func (s *mcpSavingTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := s.source.Token()
	if err != nil {
		return nil, err
	}
	if !sameMCPOAuthToken(s.previous, token) {
		if err := s.save(s.config, token); err != nil {
			return nil, err
		}
		s.previous = cloneOAuthToken(token)
	}
	return token, nil
}

func (s *Service) restoredMCPOAuthHandler(serverID string, session *mcpOAuthSession, client *http.Client, generation *mcpclient.Connection) (*auth.AuthorizationCodeHandler, error) {
	config, token := oauthConfigAndToken(session)
	credentials := &oauthex.ClientCredentials{ClientID: config.ClientID}
	if config.ClientSecret != "" {
		credentials.ClientSecretAuth = &oauthex.ClientSecretAuth{ClientSecret: config.ClientSecret}
	}
	initial := s.savingMCPOAuthTokenSource(serverID, client, config, token, generation)
	return auth.NewAuthorizationCodeHandler(&auth.AuthorizationCodeHandlerConfig{
		RedirectURL: config.RedirectURL, PreregisteredClient: credentials, RequestRefreshToken: true, Client: client,
		AuthorizationCodeFetcher: func(context.Context, *auth.AuthorizationArgs) (*auth.AuthorizationResult, error) {
			return nil, errors.New("MCP OAuth authorization must be renewed")
		},
		InitialTokenSource: initial,
		NewTokenSource: func(_ context.Context, updated *oauth2.Config, updatedToken *oauth2.Token) (oauth2.TokenSource, error) {
			if err := s.persistMCPOAuthSession(serverID, updated, updatedToken, generation); err != nil {
				return nil, err
			}
			return s.savingMCPOAuthTokenSource(serverID, client, updated, updatedToken, generation), nil
		},
	})
}

func (s *Service) savingMCPOAuthTokenSource(serverID string, client *http.Client, config *oauth2.Config, token *oauth2.Token, generation *mcpclient.Connection) oauth2.TokenSource {
	refreshCtx := context.WithValue(generation.LifetimeContext(), oauth2.HTTPClient, client)
	return &mcpSavingTokenSource{
		source: config.TokenSource(refreshCtx, token), config: config, previous: cloneOAuthToken(token),
		save: func(updatedConfig *oauth2.Config, updatedToken *oauth2.Token) error {
			return s.persistMCPOAuthSession(serverID, updatedConfig, updatedToken, generation)
		},
	}
}

func (s *Service) persistMCPOAuthSession(serverID string, config *oauth2.Config, token *oauth2.Token, generation *mcpclient.Connection) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.mcpSecretsMu.Lock()
	defer s.mcpSecretsMu.Unlock()
	if !generation.Current() {
		return context.Canceled
	}
	server, err := s.store.GetMCPServer(ctx, serverID)
	if err != nil {
		return err
	}
	secrets, err := s.decryptMCPSecrets(server.SecretsCipher)
	if err != nil {
		return err
	}
	secrets.OAuth = &mcpOAuthSession{
		ClientID: config.ClientID, ClientSecret: config.ClientSecret, AuthURL: config.Endpoint.AuthURL,
		TokenURL: config.Endpoint.TokenURL, AuthStyle: config.Endpoint.AuthStyle, RedirectURL: config.RedirectURL,
		Scopes: slices.Clone(config.Scopes), AccessToken: token.AccessToken, TokenType: token.TokenType,
		RefreshToken: token.RefreshToken, Expiry: token.Expiry,
	}
	return s.persistMCPSecrets(ctx, serverID, secrets)
}

func (s *Service) persistMCPSecrets(ctx context.Context, serverID string, secrets mcpSecrets) error {
	payload, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	ciphertext, err := s.encryptor.Encrypt(payload)
	if err != nil {
		return err
	}
	return s.store.UpdateMCPServerSecrets(ctx, serverID, ciphertext)
}

func oauthConfigAndToken(session *mcpOAuthSession) (*oauth2.Config, *oauth2.Token) {
	return &oauth2.Config{
		ClientID: session.ClientID, ClientSecret: session.ClientSecret, RedirectURL: session.RedirectURL,
		Endpoint: oauth2.Endpoint{AuthURL: session.AuthURL, TokenURL: session.TokenURL, AuthStyle: session.AuthStyle},
		Scopes:   slices.Clone(session.Scopes),
	}, &oauth2.Token{AccessToken: session.AccessToken, TokenType: session.TokenType, RefreshToken: session.RefreshToken, Expiry: session.Expiry}
}

func sameMCPOAuthToken(left, right *oauth2.Token) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.AccessToken == right.AccessToken && left.RefreshToken == right.RefreshToken && left.TokenType == right.TokenType && left.Expiry.Equal(right.Expiry)
}

func cloneOAuthToken(token *oauth2.Token) *oauth2.Token {
	if token == nil {
		return nil
	}
	clone := *token
	return &clone
}
