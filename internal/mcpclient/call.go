package mcpclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (m *Manager) Call(ctx context.Context, serverID string, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	if params == nil || strings.TrimSpace(params.Name) == "" {
		return nil, fmt.Errorf("MCP tool name is required")
	}
	callParams := *params
	if raw, ok := callParams.Arguments.(json.RawMessage); ok {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			raw = json.RawMessage(`{}`)
		}
		if !json.Valid(raw) {
			return nil, fmt.Errorf("invalid MCP tool arguments")
		}
		callParams.Arguments = raw
	}
	m.mu.Lock()
	state := m.states[serverID]
	if m.closed || state == nil || state.snapshot.Status != "ready" || !state.currentLocked() {
		m.mu.Unlock()
		return nil, fmt.Errorf("MCP server is not ready")
	}
	m.workers.Add(1)
	session := state.session
	m.mu.Unlock()
	defer m.workers.Done()
	var callCtx context.Context
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		callCtx, cancel = context.WithTimeout(ctx, CallTimeout)
	} else {
		callCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()
	stop := context.AfterFunc(state.ctx, cancel)
	defer stop()
	started := time.Now()
	result, err := session.CallTool(callCtx, &callParams)
	if err != nil && state.ctx.Err() != nil && ctx.Err() == nil {
		// Disabling a server is not cancellation of the user's whole Agent turn.
		// Its remote side effects remain unknown; never automatically replay it.
		err = fmt.Errorf("MCP connection changed during tool call: %v", err)
	}
	status := "completed"
	if err != nil {
		status = "failed"
	} else if result == nil {
		status, err = "failed", fmt.Errorf("MCP server returned an empty tool result")
	} else if result.IsError {
		status = "tool_error"
	}
	if m.observe != nil {
		m.observe(ctx, CallInfo{ServerID: serverID, ToolName: callParams.Name, Status: status, Duration: time.Since(started)})
	}
	return result, err
}
