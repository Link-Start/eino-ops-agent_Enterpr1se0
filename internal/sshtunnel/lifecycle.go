package sshtunnel

import (
	"context"
	"fmt"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/ids"
	"github.com/Enterpr1se0/opsnerva/internal/observability"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

// Start receives normalized, validated endpoints from the control plane.
func (m *Manager) Start(ctx context.Context, host domain.Host, connection sshx.ConnectionSpec, config domain.SSHTunnelConfig) (domain.SSHTunnel, error) {
	return m.start(ctx, host, connection, config, "")
}

func (m *Manager) start(ctx context.Context, host domain.Host, connection sshx.ConnectionSpec, config domain.SSHTunnelConfig, id string) (domain.SSHTunnel, error) {
	if m.transport == nil {
		return domain.SSHTunnel{}, fmt.Errorf("configured SSH transport does not support port forwarding")
	}
	if err := m.begin(); err != nil {
		return domain.SSHTunnel{}, err
	}
	transferred := false
	defer func() {
		if !transferred {
			m.workers.Done()
		}
	}()
	tunnelCtx, cancel := context.WithCancel(m.ctx)
	runtime, localPort, remotePort, err := openRuntime(ctx, tunnelCtx, m.transport, connection, config)
	if err != nil {
		cancel()
		return domain.SSHTunnel{}, err
	}
	if id == "" {
		id = ids.New("tunnel")
	}
	state := &tunnel{
		value: domain.SSHTunnel{ID: id, HostID: host.ID, HostName: host.Name, Direction: config.Direction,
			LocalHost: config.LocalHost, LocalPort: localPort, RemoteHost: config.RemoteHost, RemotePort: remotePort,
			Status: "running", ProxyUsed: connection.Target.ProxyURL != "" || len(connection.Jumps) > 0, StartedAt: time.Now().UTC()},
		ctx: tunnelCtx, cancel: cancel, runtime: runtime, retry: make(chan struct{}, 1), done: make(chan struct{}),
		operation: make(chan struct{}, 1),
	}
	state.transitionMu.Lock()
	m.mu.Lock()
	if m.closed || tunnelCtx.Err() != nil || ctx.Err() != nil {
		m.mu.Unlock()
		state.transitionMu.Unlock()
		runtime.close()
		cancel()
		return domain.SSHTunnel{}, context.Canceled
	}
	if m.states[id] != nil {
		m.mu.Unlock()
		state.transitionMu.Unlock()
		runtime.close()
		cancel()
		return domain.SSHTunnel{}, fmt.Errorf("tunnel %q already exists", id)
	}
	m.states[id] = state
	m.mu.Unlock()
	started := state.snapshot()
	m.publish(started, false)
	state.transitionMu.Unlock()
	transferred = true
	go m.run(state)
	observability.FromContext(ctx).InfoContext(ctx, "SSH tunnel started", "component", "ssh_tunnel",
		"tunnel_id", id, "host_id", host.ID, "direction", config.Direction,
		"local_host", config.LocalHost, "local_port", localPort, "remote_host", config.RemoteHost, "remote_port", remotePort,
		"proxy_used", started.ProxyUsed)
	return started, nil
}

func (m *Manager) run(state *tunnel) {
	defer m.workers.Done()
	defer m.finish(state)
	state.mu.Lock()
	runtime := state.runtime
	state.mu.Unlock()
	for runtime != nil {
		terminalErr := m.serve(state, runtime)
		runtime.close()
		runtime.workers.Wait()
		if state.ctx.Err() != nil {
			return
		}
		failure := "SSH tunnel connection closed"
		if terminalErr != nil {
			failure = m.redactor.Redact(terminalErr.Error())
		}
		if !m.transition(state, func(state *tunnel) bool {
			if state.runtime != runtime || state.value.Status != "running" {
				return false
			}
			state.runtime = nil
			state.value.Status, state.value.Error, state.value.ReconnectAttempt = "retrying", failure, 0
			return true
		}) {
			return
		}
		observability.FromContext(context.Background()).Warn("SSH tunnel disconnected; reconnecting",
			"component", "ssh_tunnel", "tunnel_id", state.value.ID, "host_id", state.value.HostID, "error", failure)
		runtime = m.reconnect(state)
	}
}

func (m *Manager) finish(state *tunnel) {
	state.mu.Lock()
	runtime := state.runtime
	state.mu.Unlock()
	if runtime != nil {
		runtime.close()
		runtime.workers.Wait()
	}
	state.transitionMu.Lock()
	defer state.transitionMu.Unlock()
	state.mu.Lock()
	if state.ctx.Err() != nil {
		state.value.Status = "stopped"
	} else {
		state.value.Status = "failed"
		if state.value.Error == "" {
			state.value.Error = "SSH tunnel stopped unexpectedly"
		}
	}
	state.runtime = nil
	terminal := state.snapshotLocked()
	state.cancel()
	state.mu.Unlock()
	m.mu.Lock()
	if m.states[terminal.ID] == state {
		delete(m.states, terminal.ID)
	}
	m.mu.Unlock()
	m.publish(terminal, true)
	close(state.done)
}
