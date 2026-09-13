package mcpclient

import (
	"context"
	"fmt"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/cloudwego/eino/components/tool"
)

func (state *Connection) Run(open Open) error {
	_, err := state.run(open)
	return err
}

func (state *Connection) Test(open Open) (domain.MCPTestResult, error) {
	started := time.Now()
	items, err := state.run(open)
	if err != nil {
		return domain.MCPTestResult{}, err
	}
	return domain.MCPTestResult{OK: true, LatencyMS: time.Since(started).Milliseconds(), ToolCount: len(items), Tools: publicTools(items)}, nil
}

func (state *Connection) run(open Open) ([]tool.BaseTool, error) {
	m := state.manager
	defer m.workers.Done()
	defer func() {
		state.finishStartup()
		state.startup, state.finishStartup = nil, nil
	}()
	var session Session
	var items []tool.BaseTool
	err := state.startup.Err()
	if err == nil {
		session, items, err = open(state.startup)
	}
	public := publicTools(items)
	m.mu.Lock()
	if err == nil {
		err = state.startup.Err()
	}
	if err == nil && !state.currentLocked() {
		err = context.Canceled
	}
	if err != nil || !state.registered {
		if state.currentLocked() && state.registered {
			state.snapshot = Snapshot{Status: "error", LastError: m.redactor.Redact(err.Error())}
		}
		state.cancel()
		delete(m.active, state)
		m.mu.Unlock()
		if session != nil {
			_ = session.Close()
		}
		return items, err
	}
	now := time.Now().UTC()
	state.session, state.tools = session, items
	state.snapshot = Snapshot{Status: "ready", ConnectedAt: &now, Tools: public}
	m.workers.Add(1)
	m.mu.Unlock()
	go state.watch()
	return items, nil
}

func (state *Connection) watch() {
	m := state.manager
	defer m.workers.Done()
	closed := make(chan struct{})
	stop := context.AfterFunc(state.ctx, func() { _ = state.session.Close(); close(closed) })
	err := state.session.Wait()
	if stop() {
		_ = state.session.Close()
	} else {
		<-closed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if state.currentLocked() && state.registered {
		if err == nil {
			err = fmt.Errorf("MCP connection closed")
		}
		state.snapshot = Snapshot{Status: "disconnected", LastError: m.redactor.Redact(err.Error())}
		state.tools = nil
	}
	state.cancel()
	delete(m.active, state)
}
