package mcpclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/proxyx"
	"github.com/cloudwego/eino/components/tool"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Config struct {
	Server  domain.MCPServer
	Env     map[string]string
	Headers map[string]string
	OAuth   auth.OAuthHandler
}

func (m *Manager) Open(ctx context.Context, config Config) (Session, []tool.BaseTool, error) {
	server := config.Server
	var transport mcp.Transport
	switch server.Transport {
	case domain.MCPTransportStdio:
		command := exec.Command(server.Command, server.Args...)
		command.Dir = server.Cwd
		command.Env = append(os.Environ(), environment(config.Env)...)
		transport = &mcp.CommandTransport{Command: command}
	case domain.MCPTransportStreamableHTTP:
		headers := make(map[string]string, len(config.Headers))
		for name, value := range config.Headers {
			if config.OAuth == nil || !strings.EqualFold(name, "Authorization") {
				headers[name] = value
			}
		}
		transport = &mcp.StreamableClientTransport{
			Endpoint:     server.URL,
			HTTPClient:   &http.Client{Timeout: CallTimeout, Transport: proxyx.HeaderRewriteTransport{Base: cleanupTransport{http.DefaultTransport}, Headers: headers}},
			OAuthHandler: config.OAuth, MaxRetries: 1, DisableStandaloneSSE: true,
		}
	default:
		return nil, nil, fmt.Errorf("unsupported MCP transport %q", server.Transport)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "opsnerva", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, nil, err
	}
	items, err := m.resolveTools(ctx, session, server)
	if err != nil {
		_ = session.Close()
		return nil, nil, err
	}
	return session, items, nil
}

func environment(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

// The SDK's Close sends DELETE before cancelling its network context. A peer
// waiting for an in-flight tool can otherwise hold both Close and CallTool for
// the normal call timeout. Only this best-effort session cleanup is bounded.
type cleanupTransport struct{ base http.RoundTripper }

func (transport cleanupTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodDelete {
		return transport.base.RoundTrip(request)
	}
	ctx, cancel := context.WithTimeout(request.Context(), 2*time.Second)
	response, err := transport.base.RoundTrip(request.Clone(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	response.Body = &cleanupBody{ReadCloser: response.Body, cancel: cancel}
	return response, nil
}

type cleanupBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (body *cleanupBody) Close() error { defer body.cancel(); return body.ReadCloser.Close() }
