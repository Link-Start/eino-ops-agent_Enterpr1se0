package mcpclient

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/security"
	officialmcp "github.com/cloudwego/eino-ext/components/tool/mcp/officialmcp"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type staticMCPClientSession struct {
	tools []*mcp.Tool
	pages map[string]*mcp.ListToolsResult
}

func (s *staticMCPClientSession) ListTools(_ context.Context, params *mcp.ListToolsParams) (*mcp.ListToolsResult, error) {
	if s.pages != nil {
		return s.pages[params.Cursor], nil
	}
	return &mcp.ListToolsResult{Tools: s.tools}, nil
}

func (s *staticMCPClientSession) CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	return nil, nil
}

func TestOfficialMCPToolDiscoveryKeepsSafetyLimitsAndUniqueNames(t *testing.T) {
	manager := New(security.NewRedactor(), nil)
	tools := make([]*mcp.Tool, 0, maxTools+2)
	tools = append(tools,
		&mcp.Tool{Name: "same.name", Description: "first", InputSchema: map[string]any{"type": "object"}},
		&mcp.Tool{Name: "same name", Description: "second", InputSchema: map[string]any{"type": "object"}},
	)
	for index := 2; index < maxTools+2; index++ {
		tools = append(tools, &mcp.Tool{Name: fmt.Sprintf("tool_%03d", index), InputSchema: map[string]any{"type": "object"}})
	}
	resolved, err := manager.resolveTools(context.Background(), &staticMCPClientSession{tools: tools}, domain.MCPServer{ID: "server-limits", Name: "Limits"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != maxTools {
		t.Fatalf("resolved MCP tools=%d, want %d", len(resolved), maxTools)
	}
	first, err := resolved[0].Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolved[1].Info(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Name == second.Name || len(first.Name) > 64 || len(second.Name) > 64 {
		t.Fatalf("colliding MCP names were not mapped safely: %q %q", first.Name, second.Name)
	}
	if first.Extra[officialmcp.ExtraMCPServerName] != "Limits" || first.Extra[officialmcp.ExtraMCPRawToolName] != "same.name" {
		t.Fatalf("official MCP metadata is incomplete: %#v", first.Extra)
	}
}

func TestOfficialMCPToolDiscoveryLoadsAllPages(t *testing.T) {
	manager := New(security.NewRedactor(), nil)
	session := &staticMCPClientSession{pages: map[string]*mcp.ListToolsResult{
		"": {
			Tools:      []*mcp.Tool{{Name: "first", InputSchema: map[string]any{"type": "object"}}},
			NextCursor: "next",
		},
		"next": {
			Tools: []*mcp.Tool{{Name: "second", InputSchema: map[string]any{"type": "object"}}},
		},
	}}
	resolved, err := manager.resolveTools(context.Background(), session, domain.MCPServer{ID: "server-pages", Name: "Pages"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 2 {
		t.Fatalf("resolved paginated MCP tools=%d, want 2", len(resolved))
	}
}

func TestOfficialMCPToolDiscoveryRejectsOversizedSchema(t *testing.T) {
	manager := New(security.NewRedactor(), nil)
	session := &staticMCPClientSession{tools: []*mcp.Tool{{
		Name: "oversized", InputSchema: map[string]any{"type": "object", "description": strings.Repeat("x", maxSchemaBytes)},
	}}}
	_, err := manager.resolveTools(context.Background(), session, domain.MCPServer{ID: "server-schema", Name: "Schema"})
	if err == nil || !strings.Contains(err.Error(), "input schema exceeds") {
		t.Fatalf("oversized MCP schema error=%v", err)
	}
}
