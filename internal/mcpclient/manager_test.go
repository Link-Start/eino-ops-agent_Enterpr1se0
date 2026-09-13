package mcpclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/security"
	"github.com/cloudwego/eino/components/tool"
	"github.com/cloudwego/eino/schema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type testSession struct {
	closed   chan struct{}
	once     sync.Once
	waitGate <-chan struct{}
	call     func(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error)
}

func newSession() *testSession { return &testSession{closed: make(chan struct{})} }
func (s *testSession) ListTools(context.Context, *mcp.ListToolsParams) (*mcp.ListToolsResult, error) {
	return &mcp.ListToolsResult{}, nil
}
func (s *testSession) CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	if s.call != nil {
		return s.call(ctx, params)
	}
	return &mcp.CallToolResult{}, nil
}
func (s *testSession) Close() error { s.once.Do(func() { close(s.closed) }); return nil }
func (s *testSession) Wait() error {
	<-s.closed
	if s.waitGate != nil {
		<-s.waitGate
	}
	return errors.New("remote disconnected")
}

type testTool string

func (name testTool) Info(context.Context) (*schema.ToolInfo, error) {
	return &schema.ToolInfo{Name: string(name)}, nil
}

func testManager(t *testing.T, observe Observe) *Manager {
	t.Helper()
	m := New(security.NewRedactor(), observe)
	t.Cleanup(func() { await(t, m.Close()) })
	return m
}

func connect(t *testing.T, m *Manager, id string, session *testSession) *Connection {
	t.Helper()
	state, err := m.Begin(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Run(func(context.Context) (Session, []tool.BaseTool, error) {
		return session, []tool.BaseTool{testTool(id)}, nil
	}); err != nil {
		t.Fatal(err)
	}
	return state
}

func await(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for MCP worker")
	}
}

func TestDisableDoesNotWaitForToolCallOrBlockOtherServers(t *testing.T) {
	entered, gate := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	m := testManager(t, nil)
	t.Cleanup(release)
	blocked := newSession()
	blocked.call = func(ctx context.Context, _ *mcp.CallToolParams) (*mcp.CallToolResult, error) {
		close(entered)
		<-ctx.Done()
		<-gate
		return nil, ctx.Err()
	}
	connect(t, m, "blocked", blocked)
	connect(t, m, "other", newSession())
	callDone := make(chan error, 1)
	go func() {
		_, err := m.Call(context.Background(), "blocked", &mcp.CallToolParams{Name: "write"})
		callDone <- err
	}()
	await(t, entered)
	disabled := make(chan struct{})
	go func() { m.Disconnect("blocked", "disabled"); close(disabled) }()
	await(t, disabled)
	if m.Snapshot("blocked").Status != "disabled" {
		t.Fatal("disabled state not visible")
	}
	if _, err := m.Call(context.Background(), "other", &mcp.CallToolParams{Name: "read"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Call(context.Background(), "blocked", &mcp.CallToolParams{Name: "write"}); err == nil {
		t.Fatal("disabled wrapper remained callable")
	}
	done := m.Close()
	select {
	case <-done:
		t.Fatal("shutdown skipped the unfinished tool call")
	default:
	}
	release()
	await(t, done)
	if err := <-callDone; err == nil || errors.Is(err, context.Canceled) {
		t.Fatalf("connection cancellation became whole-Agent cancellation: %v", err)
	}
}

func TestLateConnectCannotReplaceNewGeneration(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "late_success", true: "late_failure"}[failure], func(t *testing.T) {
			m := testManager(t, nil)
			gate, entered := make(chan struct{}), make(chan struct{})
			release := sync.OnceFunc(func() { close(gate) })
			t.Cleanup(release)
			old, err := m.Begin(context.Background(), "server")
			if err != nil {
				t.Fatal(err)
			}
			late := newSession()
			finished := make(chan error, 1)
			go func() {
				finished <- old.Run(func(context.Context) (Session, []tool.BaseTool, error) {
					close(entered)
					<-gate
					if failure {
						return late, nil, errors.New("old failure")
					}
					return late, []tool.BaseTool{testTool("old")}, nil
				})
			}()
			await(t, entered)
			current := newSession()
			connect(t, m, "server", current)
			release()
			select {
			case err := <-finished:
				if err == nil {
					t.Fatal("superseded connection succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("old connection did not finish")
			}
			await(t, late.closed)
			snapshot := m.Snapshot("server")
			if snapshot.Status != "ready" || snapshot.Tools[0].Name != "server" || snapshot.LastError != "" {
				t.Fatalf("old result overwrote current: %#v", snapshot)
			}
			select {
			case <-current.closed:
				t.Fatal("old cleanup closed new session")
			default:
			}
		})
	}
}

func TestShutdownCancelsOpeningAndWaitsForLateSessionCleanup(t *testing.T) {
	m := testManager(t, nil)
	gate, entered := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	state, err := m.Begin(context.Background(), "server")
	if err != nil {
		t.Fatal(err)
	}
	late := newSession()
	finished := make(chan error, 1)
	go func() {
		finished <- state.Run(func(ctx context.Context) (Session, []tool.BaseTool, error) {
			close(entered)
			<-ctx.Done()
			<-gate
			return late, nil, nil
		})
	}()
	await(t, entered)
	done := m.Close()
	if m.Close() != done {
		t.Fatal("close barrier changed")
	}
	select {
	case <-done:
		t.Fatal("shutdown skipped pending connect")
	default:
	}
	if _, err := m.Begin(context.Background(), "new"); err == nil {
		t.Fatal("closed manager accepted a connection")
	}
	release()
	await(t, done)
	await(t, late.closed)
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("late connect = %v", err)
	}
	if len(m.Tools()) != 0 || m.Snapshot("server").Status != "" {
		t.Fatal("shutdown resurrected a connection")
	}
}

func TestShutdownWaitsForCallAuditAndSessionWait(t *testing.T) {
	gate, observed := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	var m *Manager
	m = testManager(t, func(_ context.Context, info CallInfo) {
		_ = m.Snapshot(info.ServerID)
		close(observed)
		<-gate
	})
	t.Cleanup(release)
	session := newSession()
	session.waitGate = gate
	connect(t, m, "server", session)
	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		_, _ = m.Call(context.Background(), "server", &mcp.CallToolParams{Name: "read"})
	}()
	await(t, observed)
	done := m.Close()
	await(t, session.closed)
	select {
	case <-done:
		t.Fatal("shutdown skipped audit or session Wait")
	default:
	}
	release()
	await(t, done)
	await(t, callDone)
}

func TestProbeAndSnapshotsDoNotMutateReadyConnection(t *testing.T) {
	m := testManager(t, nil)
	connect(t, m, "ready", newSession())
	before := m.Snapshot("ready")
	probe := newSession()
	connection, err := m.BeginTest(context.Background(), "ready")
	if err != nil {
		t.Fatal(err)
	}
	result, err := connection.Test(func(context.Context) (Session, []tool.BaseTool, error) {
		return probe, []tool.BaseTool{testTool("probe")}, nil
	})
	if err != nil || !result.OK || result.ToolCount != 1 || result.Tools[0].Name != "probe" {
		t.Fatalf("probe = %#v, %v", result, err)
	}
	await(t, probe.closed)
	snapshot := m.Snapshot("ready")
	if snapshot.Status != "ready" || !snapshot.ConnectedAt.Equal(*before.ConnectedAt) || snapshot.Tools[0].Name != "ready" {
		t.Fatalf("probe altered registry: %#v", snapshot)
	}
	snapshot.Tools[0].Name = "mutated"
	*snapshot.ConnectedAt = time.Time{}
	if current := m.Snapshot("ready"); current.Tools[0].Name != "ready" || current.ConnectedAt.IsZero() {
		t.Fatalf("snapshot aliases runtime: %#v", current)
	}
}

func TestPeerDisconnectDropsTools(t *testing.T) {
	m := testManager(t, nil)
	session := newSession()
	state := connect(t, m, "server", session)
	_ = session.Close()
	await(t, state.LifetimeContext().Done())
	if current := m.Snapshot("server"); current.Status != "disconnected" || current.LastError == "" || len(m.Tools()) != 0 {
		t.Fatalf("dead session remained ready: %#v", current)
	}
}
