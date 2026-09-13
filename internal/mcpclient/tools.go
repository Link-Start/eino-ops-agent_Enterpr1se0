package mcpclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	officialmcp "github.com/cloudwego/eino-ext/components/tool/mcp/officialmcp"
	"github.com/cloudwego/eino/components/tool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	maxSchemaBytes = 256 << 10
	maxTools       = 128
)

var toolNameRE = regexp.MustCompile(`[^A-Za-z0-9_-]+`)

type toolSession struct {
	call             func(context.Context, string, *mcp.CallToolParams) (*mcp.CallToolResult, error)
	serverID         string
	serverName       string
	discoverySession officialmcp.ClientSession
	discoveredTools  int
}

func (a *toolSession) ListTools(ctx context.Context, params *mcp.ListToolsParams) (*mcp.ListToolsResult, error) {
	if a.discoverySession == nil {
		return nil, fmt.Errorf("MCP discovery session is not ready")
	}
	response, err := a.discoverySession.ListTools(ctx, params)
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, fmt.Errorf("MCP server returned an empty tool list")
	}
	filtered := *response
	filtered.Tools = make([]*mcp.Tool, 0, len(response.Tools))
	for _, candidate := range response.Tools {
		if a.discoveredTools >= maxTools {
			filtered.NextCursor = ""
			break
		}
		if candidate == nil || strings.TrimSpace(candidate.Name) == "" {
			continue
		}
		copyOfTool := *candidate
		if copyOfTool.InputSchema == nil {
			copyOfTool.InputSchema = map[string]any{"type": "object"}
		}
		encodedSchema, err := json.Marshal(copyOfTool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("encode MCP tool %q input schema: %w", candidate.Name, err)
		}
		if len(encodedSchema) > maxSchemaBytes {
			return nil, fmt.Errorf("MCP tool %q input schema exceeds %d bytes", candidate.Name, maxSchemaBytes)
		}
		description := strings.TrimSpace(copyOfTool.Description)
		if description == "" {
			description = copyOfTool.Name
		}
		copyOfTool.Description = fmt.Sprintf("%s: %s", a.serverName, strings.ToValidUTF8(description, "�"))
		filtered.Tools = append(filtered.Tools, &copyOfTool)
		a.discoveredTools++
	}
	if a.discoveredTools >= maxTools {
		filtered.NextCursor = ""
	}
	return &filtered, nil
}

func (a *toolSession) CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	return a.call(ctx, a.serverID, params)
}

func (m *Manager) resolveTools(ctx context.Context, session officialmcp.ClientSession, server domain.MCPServer) ([]tool.BaseTool, error) {
	adapter := &toolSession{
		call: m.Call, serverID: server.ID, serverName: server.Name, discoverySession: session,
	}
	// Model wrappers resolve calls through Manager; don't keep an old SDK
	// session alive solely because a previous Runner still holds its tools.
	defer func() { adapter.discoverySession = nil }()
	errorAsError := false
	seen := make(map[string]struct{})
	return officialmcp.GetTools(ctx, &officialmcp.Config{
		Cli:           adapter,
		ServerName:    server.Name,
		ListToolsMode: officialmcp.ListToolsAllPages,
		MaxToolPages:  100,
		ToolNameMapper: func(_ context.Context, input officialmcp.ToolNameMapperInput) (officialmcp.ToolNameMapperOutput, error) {
			exposed := exposedMCPToolName(server.ID, input.Tool.Name)
			if _, exists := seen[exposed]; exists {
				digest := sha256.Sum256([]byte(input.Tool.Name))
				exposed = truncateToolName(exposed, 55) + "_" + hex.EncodeToString(digest[:4])
			}
			seen[exposed] = struct{}{}
			return officialmcp.ToolNameMapperOutput{ExposedName: exposed}, nil
		},
		MetadataMode:      officialmcp.MetadataBasic,
		DescriptionPolicy: &officialmcp.DescriptionPolicy{MaxChars: 1000},
		ResultPolicy: &officialmcp.ResultPolicy{
			IncludeStructuredContent: true,
			IncludeMeta:              true,
			ErrorAsError:             &errorAsError,
		},
		ToolCallResultHandlerV2: markMCPToolResultUntrusted,
	})
}

func markMCPToolResultUntrusted(_ context.Context, _ officialmcp.ToolCallInfo, result *mcp.CallToolResult) (*mcp.CallToolResult, error) {
	if result == nil {
		return nil, nil
	}
	copyOfResult := *result
	copyOfResult.Meta = make(mcp.Meta, len(result.Meta)+1)
	for key, value := range result.Meta {
		copyOfResult.Meta[key] = value
	}
	security := map[string]any{
		"content_is_untrusted": true,
		"ok":                   !result.IsError,
		"status":               "completed",
		"code":                 "completed",
	}
	if result.IsError {
		security["status"] = "failed"
		security["code"] = "provider_failed"
		security["message"] = "the external MCP function tool returned an error"
		security["next_action"] = "inspect the returned error and external state; do not repeat the same call unchanged"
	}
	copyOfResult.Meta["opsnerva"] = security
	return &copyOfResult, nil
}

func exposedMCPToolName(serverID, original string) string {
	serverDigest := sha256.Sum256([]byte(serverID))
	toolPart := strings.Trim(toolNameRE.ReplaceAllString(original, "_"), "_-")
	if toolPart == "" {
		toolPart = "tool"
	}
	toolDigest := sha256.Sum256([]byte(original))
	if len(toolPart) > 38 {
		toolPart = toolPart[:29] + "_" + hex.EncodeToString(toolDigest[:4])
	}
	return "mcp__" + hex.EncodeToString(serverDigest[:5]) + "__" + toolPart
}

func truncateToolName(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func publicTools(items []tool.BaseTool) []domain.MCPTool {
	result := make([]domain.MCPTool, 0, len(items))
	for _, item := range items {
		info, err := item.Info(context.Background())
		if err != nil || info == nil {
			continue
		}
		rawName, _ := info.Extra[officialmcp.ExtraMCPRawToolName].(string)
		if rawName == "" {
			rawName = info.Name
		}
		result = append(result, domain.MCPTool{Name: rawName, ExposedName: info.Name, Description: info.Desc})
	}
	return result
}
