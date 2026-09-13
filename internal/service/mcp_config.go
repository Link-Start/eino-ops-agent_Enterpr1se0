package service

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
)

var mcpEnvNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type mcpSecrets struct {
	Env     map[string]string `json:"env,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	OAuth   *mcpOAuthSession  `json:"oauth,omitempty"`
}

func (s *Service) SaveMCPServer(ctx context.Context, input domain.MCPServerInput, actor string) (domain.MCPServer, error) {
	input.ID = strings.TrimSpace(input.ID)
	input.Name = strings.TrimSpace(input.Name)
	input.Command = strings.TrimSpace(input.Command)
	input.Cwd = strings.TrimSpace(input.Cwd)
	input.URL = strings.TrimSpace(input.URL)
	if err := validateMCPInput(input); err != nil {
		return domain.MCPServer{}, err
	}
	s.mcpSecretsMu.Lock()
	saved, err := s.storeMCPServerConfig(ctx, input)
	if err == nil {
		s.cancelMCPOAuthFlow(saved.ID)
		status := "disconnected"
		if !saved.Enabled {
			status = "disabled"
		}
		s.mcpClients.Disconnect(saved.ID, status)
	}
	s.mcpSecretsMu.Unlock()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique constraint") {
			return domain.MCPServer{}, fmt.Errorf("MCP server name already exists")
		}
		return domain.MCPServer{}, err
	}
	if saved.Enabled {
		_ = s.ReconnectMCPServer(ctx, saved.ID)
	}
	s.audit(ctx, "", "mcp_server_saved", actor, map[string]any{"server_id": saved.ID, "name": saved.Name, "transport": saved.Transport, "enabled": saved.Enabled})
	return s.GetMCPServer(ctx, saved.ID)
}

func (s *Service) storeMCPServerConfig(ctx context.Context, input domain.MCPServerInput) (domain.MCPServer, error) {
	server := domain.MCPServer{
		ID: input.ID, Name: input.Name, Transport: input.Transport, Command: input.Command,
		Args: append([]string(nil), input.Args...), Cwd: input.Cwd, URL: input.URL, Enabled: input.Enabled,
	}
	secrets := mcpSecrets{Env: map[string]string{}, Headers: map[string]string{}}
	if input.ID != "" {
		existing, err := s.store.GetMCPServer(ctx, input.ID)
		if err != nil {
			return domain.MCPServer{}, err
		}
		server.CreatedAt = existing.CreatedAt
		server.SecretsCipher = existing.SecretsCipher
		secrets, err = s.decryptMCPSecrets(existing.SecretsCipher)
		if err != nil {
			return domain.MCPServer{}, fmt.Errorf("decrypt existing MCP secrets: %w", err)
		}
		if existing.Transport != input.Transport || existing.URL != input.URL {
			secrets.OAuth = nil
		}
	}
	if input.Env != nil {
		secrets.Env = cloneStringMap(input.Env)
	}
	if input.Headers != nil {
		secrets.Headers = cloneStringMap(input.Headers)
	}
	if err := validateMCPSecrets(secrets); err != nil {
		return domain.MCPServer{}, err
	}
	server.EnvKeys = sortedMapKeys(secrets.Env)
	server.HeaderKeys = sortedMapKeys(secrets.Headers)
	payload, err := json.Marshal(secrets)
	if err != nil {
		return domain.MCPServer{}, err
	}
	server.SecretsCipher, err = s.encryptor.Encrypt(payload)
	if err != nil {
		return domain.MCPServer{}, err
	}
	saved, err := s.store.UpsertMCPServer(ctx, server)
	return saved, err
}

func (s *Service) decryptMCPSecrets(ciphertext string) (mcpSecrets, error) {
	result := mcpSecrets{Env: map[string]string{}, Headers: map[string]string{}}
	plain, err := s.encryptor.Decrypt(ciphertext)
	if err != nil {
		return result, err
	}
	if len(plain) == 0 {
		return result, nil
	}
	if err := json.Unmarshal(plain, &result); err != nil {
		return result, err
	}
	if result.Env == nil {
		result.Env = map[string]string{}
	}
	if result.Headers == nil {
		result.Headers = map[string]string{}
	}
	return result, nil
}

func validateMCPInput(input domain.MCPServerInput) error {
	if input.Name == "" || len(input.Name) > 80 {
		return fmt.Errorf("MCP server name must contain 1-80 characters")
	}
	if len(input.Args) > 64 {
		return fmt.Errorf("MCP command supports at most 64 arguments")
	}
	for _, argument := range input.Args {
		if strings.ContainsRune(argument, 0) || len(argument) > 4096 {
			return fmt.Errorf("MCP command contains an invalid argument")
		}
	}
	switch input.Transport {
	case domain.MCPTransportStdio:
		if input.Command == "" || strings.ContainsRune(input.Command, 0) {
			return fmt.Errorf("command is required for stdio MCP servers")
		}
		if input.Cwd != "" && !filepath.IsAbs(input.Cwd) {
			return fmt.Errorf("cwd must be an absolute path")
		}
	case domain.MCPTransportStreamableHTTP:
		parsed, err := url.Parse(input.URL)
		if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("url must be an absolute http or https URL")
		}
		if parsed.User != nil {
			return fmt.Errorf("URL credentials are not supported; use an HTTP header")
		}
	default:
		return fmt.Errorf("transport must be stdio or streamable_http")
	}
	return nil
}

func validateMCPSecrets(secrets mcpSecrets) error {
	if len(secrets.Env) > 64 || len(secrets.Headers) > 64 {
		return fmt.Errorf("MCP secrets support at most 64 environment variables and 64 headers")
	}
	for name, value := range secrets.Env {
		if !mcpEnvNameRE.MatchString(name) || strings.ContainsRune(value, 0) || len(value) > 32<<10 {
			return fmt.Errorf("invalid MCP environment variable %q", name)
		}
	}
	for name, value := range secrets.Headers {
		if strings.TrimSpace(name) == "" || http.CanonicalHeaderKey(name) == "" || strings.ContainsAny(name+value, "\r\n") || len(value) > 32<<10 {
			return fmt.Errorf("invalid MCP HTTP header %q", name)
		}
		switch strings.ToLower(name) {
		case "host", "content-length", "content-type", "accept", "mcp-session-id", "last-event-id":
			return fmt.Errorf("MCP HTTP header %q is managed by the protocol", name)
		}
	}
	return nil
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[strings.TrimSpace(key)] = value
	}
	return result
}

func sortedMapKeys(source map[string]string) []string {
	result := make([]string, 0, len(source))
	for key := range source {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}
