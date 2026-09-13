package sshtunnel

import (
	"context"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/observability"
)

const (
	reconnectInitialDelay   = time.Second
	reconnectMaximumDelay   = 30 * time.Second
	reconnectAttemptTimeout = 30 * time.Second
)

func (m *Manager) reconnect(state *tunnel) *generation {
	for attempt := 1; ; attempt++ {
		delay := reconnectDelay(attempt)
		if !m.transition(state, func(state *tunnel) bool {
			if state.value.Status != "retrying" {
				return false
			}
			state.value.ReconnectAttempt = attempt
			return true
		}) {
			return nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-state.ctx.Done():
			timer.Stop()
			return nil
		case <-state.retry:
		case <-timer.C:
		}
		timer.Stop()
		snapshot := state.snapshot()
		attemptCtx, cancel := context.WithTimeout(state.ctx, reconnectAttemptTimeout)
		host, connection, err := m.resolve(attemptCtx, snapshot.HostID)
		var runtime *generation
		var localPort, remotePort int
		if err == nil {
			runtime, localPort, remotePort, err = openRuntime(attemptCtx, state.ctx, m.transport, connection, configFromTunnel(snapshot))
		}
		cancel()
		if state.ctx.Err() != nil {
			if runtime != nil {
				runtime.close()
			}
			return nil
		}
		if err != nil {
			failure := m.redactor.Redact(err.Error())
			if !m.transition(state, func(state *tunnel) bool {
				if state.value.Status != "retrying" {
					return false
				}
				state.value.Error = failure
				return true
			}) {
				return nil
			}
			observability.FromContext(context.Background()).Warn("SSH tunnel reconnect failed",
				"component", "ssh_tunnel", "tunnel_id", snapshot.ID, "host_id", snapshot.HostID,
				"attempt", attempt, "attempt_delay", delay, "error", failure)
			continue
		}
		if !m.transition(state, func(state *tunnel) bool {
			if state.value.Status != "retrying" || state.runtime != nil {
				return false
			}
			state.runtime = runtime
			select {
			case <-state.retry:
			default:
			}
			state.value.HostName, state.value.LocalPort, state.value.RemotePort = host.Name, localPort, remotePort
			state.value.ProxyUsed = connection.Target.ProxyURL != "" || len(connection.Jumps) > 0
			state.value.Status, state.value.Error, state.value.ReconnectAttempt = "running", "", 0
			return true
		}) {
			runtime.close()
			return nil
		}
		observability.FromContext(context.Background()).Info("SSH tunnel reconnected",
			"component", "ssh_tunnel", "tunnel_id", snapshot.ID, "host_id", snapshot.HostID,
			"attempt", attempt, "direction", snapshot.Direction, "local_host", snapshot.LocalHost,
			"local_port", localPort, "remote_host", snapshot.RemoteHost, "remote_port", remotePort)
		return runtime
	}
}

func reconnectDelay(attempt int) time.Duration {
	delay := reconnectInitialDelay
	for index := 1; index < attempt && delay < reconnectMaximumDelay; index++ {
		delay *= 2
	}
	if delay > reconnectMaximumDelay {
		return reconnectMaximumDelay
	}
	return delay
}
