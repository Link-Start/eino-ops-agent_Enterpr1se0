// Package mcpclient owns outbound MCP connections, discovery and tool calls.
// Configuration storage, OAuth authorization and audit policy stay with callers.
package mcpclient

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/security"
	"github.com/cloudwego/eino/components/tool"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	ConnectTimeout = 20 * time.Second
	CallTimeout    = 90 * time.Second
)

type Session interface {
	ListTools(context.Context, *mcp.ListToolsParams) (*mcp.ListToolsResult, error)
	CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)
	Close() error
	Wait() error
}

type Open func(context.Context) (Session, []tool.BaseTool, error)

// CallInfo contains no arguments, credentials or remote output. Observe runs
// outside registry locks and completes before the shutdown barrier releases.
type CallInfo struct {
	ServerID string
	ToolName string
	Status   string
	Duration time.Duration
}

type Observe func(context.Context, CallInfo)

type Snapshot struct {
	Status      string
	LastError   string
	ConnectedAt *time.Time
	Tools       []domain.MCPTool
}

type Manager struct {
	mu       sync.Mutex
	states   map[string]*Connection
	active   map[*Connection]struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	closed   bool
	workers  sync.WaitGroup
	done     chan struct{}
	redactor *security.Redactor
	observe  Observe
}

// Connection is one reserved generation. Call Run (or Test for BeginTest)
// exactly once, including preparation failures, to release its reservation.
type Connection struct {
	manager       *Manager
	id            string
	registered    bool
	ctx           context.Context
	cancel        context.CancelFunc
	startup       context.Context
	finishStartup func()
	snapshot      Snapshot
	session       Session
	tools         []tool.BaseTool
}

func New(redactor *security.Redactor, observe Observe) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{states: make(map[string]*Connection), active: make(map[*Connection]struct{}),
		ctx: ctx, cancel: cancel, done: make(chan struct{}), redactor: redactor, observe: observe}
}

func (m *Manager) Begin(ctx context.Context, id string) (*Connection, error) {
	return m.begin(ctx, id, true)
}

// BeginTest reserves a temporary connection without changing the ready registry.
func (m *Manager) BeginTest(ctx context.Context, id string) (*Connection, error) {
	return m.begin(ctx, id, false)
}

func (m *Manager) begin(ctx context.Context, id string, registered bool) (*Connection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, fmt.Errorf("MCP client is shutting down")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	lifetime, cancel := context.WithCancel(m.ctx)
	startup, cancelStartup := context.WithCancel(ctx)
	stop := context.AfterFunc(lifetime, cancelStartup)
	state := &Connection{manager: m, id: id, registered: registered, ctx: lifetime, cancel: cancel,
		startup: startup, finishStartup: func() { stop(); cancelStartup() }, snapshot: Snapshot{Status: "connecting"}}
	if registered {
		m.cancelServerLocked(id)
		m.states[id] = state
	}
	m.active[state] = struct{}{}
	m.workers.Add(1)
	return state, nil
}

// LifetimeContext survives a successful connection's initiating HTTP request.
// OAuth refresh sources use it until this generation is disabled/replaced.
func (state *Connection) LifetimeContext() context.Context { return state.ctx }

func (state *Connection) currentLocked() bool {
	m := state.manager
	_, active := m.active[state]
	return !m.closed && active && state.ctx.Err() == nil && (!state.registered || m.states[state.id] == state)
}

func (state *Connection) Current() bool {
	state.manager.mu.Lock()
	defer state.manager.mu.Unlock()
	return state.currentLocked()
}

func (m *Manager) Disconnect(id, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelServerLocked(id)
	if !m.closed {
		m.states[id] = &Connection{snapshot: Snapshot{Status: status}}
	}
}

func (m *Manager) Forget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancelServerLocked(id)
	delete(m.states, id)
}

func (m *Manager) cancelServerLocked(id string) {
	for state := range m.active {
		if state.id == id {
			state.cancel()
		}
	}
}

func (m *Manager) Snapshot(id string) Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	if state := m.states[id]; state != nil {
		result := state.snapshot
		result.Tools = slices.Clone(result.Tools)
		if result.ConnectedAt != nil {
			connectedAt := *result.ConnectedAt
			result.ConnectedAt = &connectedAt
		}
		return result
	}
	return Snapshot{}
}

func (m *Manager) Tools() []tool.BaseTool {
	m.mu.Lock()
	result := make([]tool.BaseTool, 0)
	for _, state := range m.states {
		if state.snapshot.Status == "ready" {
			result = append(result, state.tools...)
		}
	}
	m.mu.Unlock()
	sort.Slice(result, func(i, j int) bool {
		left, _ := result[i].Info(context.Background())
		right, _ := result[j].Info(context.Background())
		return left.Name < right.Name
	})
	return result
}

func (m *Manager) Close() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		m.cancel()
		clear(m.states)
		go func() { m.workers.Wait(); close(m.done) }()
	}
	return m.done
}
