package sshtunnel

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/security"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

type openFunc func(context.Context, sshx.ConnectionSpec) (sshx.TunnelClient, error)

func (open openFunc) OpenTunnel(ctx context.Context, spec sshx.ConnectionSpec) (sshx.TunnelClient, error) {
	return open(ctx, spec)
}

type testClient struct {
	closed    chan struct{}
	closeOnce sync.Once
	waitGate  <-chan struct{}
	closeGate <-chan struct{}
	dial      func(string, string) (net.Conn, error)
	listen    func(string, string) (net.Listener, error)
}

func newTestClient() *testClient { return &testClient{closed: make(chan struct{})} }

func (client *testClient) Close() error {
	client.closeOnce.Do(func() {
		close(client.closed)
		if client.closeGate != nil {
			<-client.closeGate
		}
	})
	return nil
}

func (client *testClient) Wait() error {
	<-client.closed
	if client.waitGate != nil {
		<-client.waitGate
	}
	return net.ErrClosed
}

func (client *testClient) Dial(network, address string) (net.Conn, error) {
	if client.dial != nil {
		return client.dial(network, address)
	}
	return net.DialTimeout(network, address, time.Second)
}

func (client *testClient) Listen(network, address string) (net.Listener, error) {
	if client.listen != nil {
		return client.listen(network, address)
	}
	return net.Listen(network, address)
}

type stateEvent struct {
	tunnel  domain.SSHTunnel
	removed bool
}

func newTestManager(t *testing.T, transport sshx.TunnelTransport, resolve Resolve) (*Manager, chan stateEvent) {
	t.Helper()
	events := make(chan stateEvent, 100)
	var manager *Manager
	manager = New(transport, resolve, func(value domain.SSHTunnel, removed bool) {
		// A synchronous snapshot consumer must not deadlock event publication.
		_ = manager.List()
		events <- stateEvent{value, removed}
	}, security.NewRedactor())
	t.Cleanup(func() { awaitSignal(t, manager.Close()) })
	return manager, events
}

func localConfig() domain.SSHTunnelConfig {
	return domain.SSHTunnelConfig{Direction: domain.SSHTunnelDirectionLocal, LocalHost: "127.0.0.1", RemoteHost: "127.0.0.1", RemotePort: 8080}
}

func startTestTunnel(t *testing.T, manager *Manager) domain.SSHTunnel {
	t.Helper()
	host := domain.Host{ID: "host", Name: "original"}
	value, err := manager.Start(context.Background(), host, sshx.ConnectionSpec{Target: host}, localConfig())
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for worker")
	}
}

func awaitEvent(t *testing.T, events <-chan stateEvent, matches func(stateEvent) bool) stateEvent {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if matches(event) {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for tunnel event")
		}
	}
}

func TestManualRetriesCoalesceAndRespectStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := &tunnel{ctx: ctx, retry: make(chan struct{}, 1), value: domain.SSHTunnel{ID: "retry", Status: "retrying"}}
	manager := &Manager{states: map[string]*tunnel{"retry": state}}
	var callers sync.WaitGroup
	for range 20 {
		callers.Go(func() {
			if err := manager.Retry(context.Background(), "retry"); err != nil {
				t.Error(err)
			}
		})
	}
	callers.Wait()
	if len(state.retry) != 1 {
		t.Fatalf("pending retries = %d, want 1", len(state.retry))
	}
	cancel()
	if err := manager.Retry(context.Background(), "retry"); err == nil {
		t.Fatal("cancelled tunnel accepted a manual retry")
	}
	if err := manager.Retry(ctx, "retry"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled request = %v", err)
	}
	if err := manager.Retry(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown tunnel = %v", err)
	}
}
