package sshtunnel

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

func TestReconnectDelayIsBounded(t *testing.T) {
	for attempt, expected := range map[int]time.Duration{
		0: time.Second, 1: time.Second, 2: 2 * time.Second, 5: 16 * time.Second, 6: 30 * time.Second, 100: 30 * time.Second,
	} {
		if actual := reconnectDelay(attempt); actual != expected {
			t.Fatalf("attempt %d delay = %s, want %s", attempt, actual, expected)
		}
	}
}

func TestReconnectDrainsPreviousGenerationAndResolvesFreshSettings(t *testing.T) {
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	oldClient, newClient := newTestClient(), newTestClient()
	oldClient.waitGate = gate
	fresh := domain.Host{ID: "host", Name: "updated host", ProxyURL: "socks5://127.0.0.1:1080"}
	var opens atomic.Int32
	resolved := make(chan sshx.ConnectionSpec, 1)
	manager, events := newTestManager(t, openFunc(func(_ context.Context, spec sshx.ConnectionSpec) (sshx.TunnelClient, error) {
		if opens.Add(1) == 1 {
			return oldClient, nil
		}
		resolved <- spec
		return newClient, nil
	}), func(_ context.Context, id string) (domain.Host, sshx.ConnectionSpec, error) {
		if id != fresh.ID {
			t.Errorf("resolved host = %q", id)
		}
		return fresh, sshx.ConnectionSpec{Target: fresh}, nil
	})
	t.Cleanup(release)
	started := startTestTunnel(t, manager)
	state, _ := manager.get(started.ID)
	state.sent.Store(31)
	state.received.Store(47)
	state.total.Store(2)
	state.mu.Lock()
	previous := state.runtime
	state.mu.Unlock()
	_ = previous.listener.Close()
	awaitSignal(t, oldClient.closed)
	if opens.Load() != 1 {
		t.Fatal("new generation opened before old client Wait exited")
	}
	value, _ := manager.Get(started.ID)
	if value.Status != "running" {
		t.Fatalf("reconnect began before previous generation drained: %#v", value)
	}
	release()
	awaitEvent(t, events, func(event stateEvent) bool {
		return event.tunnel.Status == "retrying" && event.tunnel.ReconnectAttempt == 1
	})
	if err := manager.Retry(context.Background(), started.ID); err != nil {
		t.Fatal(err)
	}
	reconnected := awaitEvent(t, events, func(event stateEvent) bool { return event.tunnel.Status == "running" }).tunnel
	if reconnected.ID != started.ID || reconnected.StartedAt != started.StartedAt || reconnected.LocalPort != started.LocalPort || reconnected.RemotePort != started.RemotePort {
		t.Fatalf("reconnect changed identity or endpoints: %#v", reconnected)
	}
	if reconnected.HostName != fresh.Name || !reconnected.ProxyUsed || reconnected.BytesSent != 31 || reconnected.BytesReceived != 47 || reconnected.TotalConnections != 2 {
		t.Fatalf("reconnect lost settings or counters: %#v", reconnected)
	}
	if spec := <-resolved; spec.Target.ProxyURL != fresh.ProxyURL {
		t.Fatalf("reconnect used stale connection: %#v", spec)
	}
	// Repeated cleanup of the old generation cannot close the new client.
	previous.close()
	select {
	case <-newClient.closed:
		t.Fatal("old generation closed the replacement")
	default:
	}
	if _, err := manager.Stop(context.Background(), started.ID); err != nil {
		t.Fatal(err)
	}
	if opens.Load() != 2 {
		t.Fatalf("unexpected additional connection: %d", opens.Load())
	}
}

func TestStopCancelsReconnectAndClosesLateClient(t *testing.T) {
	oldClient, lateClient := newTestClient(), newTestClient()
	entered := make(chan struct{})
	var opens atomic.Int32
	manager, events := newTestManager(t, openFunc(func(ctx context.Context, _ sshx.ConnectionSpec) (sshx.TunnelClient, error) {
		if opens.Add(1) == 1 {
			return oldClient, nil
		}
		close(entered)
		<-ctx.Done()
		return lateClient, nil
	}), func(_ context.Context, id string) (domain.Host, sshx.ConnectionSpec, error) {
		return domain.Host{ID: id}, sshx.ConnectionSpec{}, nil
	})
	started := startTestTunnel(t, manager)
	_ = oldClient.Close()
	awaitEvent(t, events, func(event stateEvent) bool {
		return event.tunnel.Status == "retrying" && event.tunnel.ReconnectAttempt == 1
	})
	if err := manager.Retry(context.Background(), started.ID); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, entered)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stopped, err := manager.Stop(ctx, started.ID)
	if err != nil || stopped.Status != "stopped" {
		t.Fatalf("stop during reconnect = %#v, %v", stopped, err)
	}
	awaitSignal(t, lateClient.closed)
	awaitSignal(t, manager.Close())
	for len(events) > 0 {
		event := <-events
		if event.tunnel.Status != "stopping" && event.tunnel.Status != "stopped" {
			t.Fatalf("late reconnect event: %#v", event)
		}
	}
}
