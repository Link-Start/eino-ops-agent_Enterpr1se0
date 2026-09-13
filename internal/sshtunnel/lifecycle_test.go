package sshtunnel

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

func TestStopWaitsForClientAndForwardWorkers(t *testing.T) {
	for _, worker := range []string{"client_wait", "forward_dial"} {
		t.Run(worker, func(t *testing.T) {
			gate := make(chan struct{})
			release := sync.OnceFunc(func() { close(gate) })
			client := newTestClient()
			dialEntered := make(chan struct{})
			if worker == "client_wait" {
				client.waitGate = gate
			} else {
				client.dial = func(string, string) (net.Conn, error) {
					close(dialEntered)
					<-client.closed
					<-gate
					return nil, errors.New("late dial failure")
				}
			}
			manager, events := newTestManager(t, openFunc(func(context.Context, sshx.ConnectionSpec) (sshx.TunnelClient, error) {
				return client, nil
			}), nil)
			t.Cleanup(release)
			started := startTestTunnel(t, manager)
			if worker == "forward_dial" {
				inbound, err := net.DialTimeout("tcp", net.JoinHostPort(started.LocalHost, strconv.Itoa(started.LocalPort)), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer inbound.Close()
				awaitSignal(t, dialEntered)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			if _, err := manager.Stop(ctx, started.ID); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("stop returned before blocked worker: %v", err)
			}
			if !manager.HasHost(started.HostID) {
				t.Fatal("host became deletable before tunnel workers exited")
			}
			value, err := manager.Get(started.ID)
			if err != nil || value.Status != "stopping" {
				t.Fatalf("draining tunnel = %#v, %v", value, err)
			}
			done := manager.Close()
			select {
			case <-done:
				t.Fatal("shutdown did not wait for tunnel workers")
			default:
			}
			release()
			awaitSignal(t, done)
			if manager.List().Count != 0 || manager.HasHost(started.HostID) {
				t.Fatal("finished tunnel remains registered")
			}
			for index, status := range []string{"running", "stopping", "stopped"} {
				select {
				case event := <-events:
					if event.tunnel.Status != status || event.removed != (index == 2) || event.tunnel.Error != "" {
						t.Fatalf("event %d = %#v", index, event)
					}
					if event.removed && event.tunnel.ActiveConnections != 0 {
						t.Fatalf("removed with active connections: %#v", event)
					}
				default:
					t.Fatalf("missing %s event", status)
				}
			}
			if len(events) != 0 {
				t.Fatalf("unexpected late events: %d", len(events))
			}
			if _, err := manager.Stop(context.Background(), started.ID); !errors.Is(err, ErrNotFound) {
				t.Fatalf("stop after removal = %v", err)
			}
		})
	}
}

func TestCloseCancelsReverseListenAndJoinsStartupCleanup(t *testing.T) {
	client := newTestClient()
	gate, entered := make(chan struct{}), make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	client.closeGate = gate
	client.listen = func(string, string) (net.Listener, error) {
		close(entered)
		<-client.closed
		return nil, net.ErrClosed
	}
	manager, events := newTestManager(t, openFunc(func(context.Context, sshx.ConnectionSpec) (sshx.TunnelClient, error) {
		return client, nil
	}), nil)
	t.Cleanup(release)
	result := make(chan error, 1)
	go func() {
		_, err := manager.Start(context.Background(), domain.Host{ID: "host"}, sshx.ConnectionSpec{}, domain.SSHTunnelConfig{
			Direction: domain.SSHTunnelDirectionReverse, LocalHost: "127.0.0.1", LocalPort: 8080, RemoteHost: "127.0.0.1",
		})
		result <- err
	}()
	awaitSignal(t, entered)
	done := manager.Close()
	if manager.Close() != done {
		t.Fatal("repeated close returned a different barrier")
	}
	awaitSignal(t, client.closed)
	select {
	case <-done:
		t.Fatal("shutdown completed before startup cleanup")
	case err := <-result:
		t.Fatalf("start returned before cleanup: %v", err)
	default:
	}
	release()
	awaitSignal(t, done)
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled reverse listener was published")
		}
	case <-time.After(time.Second):
		t.Fatal("reverse listener did not respond to cancellation")
	}
	if manager.List().Count != 0 || len(events) != 0 {
		t.Fatal("cancelled startup published a tunnel")
	}
	if _, err := manager.Start(context.Background(), domain.Host{}, sshx.ConnectionSpec{}, localConfig()); err == nil {
		t.Fatal("closed manager accepted a new tunnel")
	}
}

func TestConcurrentReplaceOnlyCreatesOneReplacement(t *testing.T) {
	gate := make(chan struct{})
	release := sync.OnceFunc(func() { close(gate) })
	oldClient := newTestClient()
	oldClient.waitGate = gate
	var opens atomic.Int32
	manager, events := newTestManager(t, openFunc(func(context.Context, sshx.ConnectionSpec) (sshx.TunnelClient, error) {
		if opens.Add(1) == 1 {
			return oldClient, nil
		}
		return newTestClient(), nil
	}), nil)
	t.Cleanup(release)
	started := startTestTunnel(t, manager)
	host := domain.Host{ID: "replacement", Name: "new host"}
	result := make(chan error, 1)
	go func() {
		_, err := manager.Replace(context.Background(), started.ID, host, sshx.ConnectionSpec{Target: host}, localConfig())
		result <- err
	}()
	awaitEvent(t, events, func(event stateEvent) bool { return event.tunnel.Status == "stopping" })
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := manager.Replace(ctx, started.ID, host, sshx.ConnectionSpec{Target: host}, localConfig()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrent replace did not wait for original transaction: %v", err)
	}
	if opens.Load() != 1 {
		t.Fatal("replacement opened before old generation drained")
	}
	release()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("replacement did not finish")
	}
	list := manager.List()
	if list.Count != 1 || list.Tunnels[0].ID == started.ID || list.Tunnels[0].HostID != host.ID || opens.Load() != 2 {
		t.Fatalf("replacement registry = %#v, opens = %d", list, opens.Load())
	}
}

type peerWaitingListener struct {
	net.Listener
	clientClosed <-chan struct{}
}

func (listener peerWaitingListener) Close() error {
	// Like cancel-tcpip-forward with an unresponsive peer: SSH must close
	// before this request can return.
	<-listener.clientClosed
	return listener.Listener.Close()
}

func TestReverseStopClosesSSHBeforeListener(t *testing.T) {
	client := newTestClient()
	client.listen = func(network, address string) (net.Listener, error) {
		listener, err := net.Listen(network, address)
		if err != nil {
			return nil, err
		}
		return peerWaitingListener{listener, client.closed}, nil
	}
	manager, _ := newTestManager(t, openFunc(func(context.Context, sshx.ConnectionSpec) (sshx.TunnelClient, error) {
		return client, nil
	}), nil)
	t.Cleanup(func() { _ = client.Close() })
	started, err := manager.Start(context.Background(), domain.Host{ID: "host"}, sshx.ConnectionSpec{}, domain.SSHTunnelConfig{
		Direction: domain.SSHTunnelDirectionReverse, LocalHost: "127.0.0.1", LocalPort: 8080, RemoteHost: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := manager.Stop(ctx, started.ID); err != nil {
		t.Fatalf("reverse stop blocked on remote listener acknowledgement: %v", err)
	}
}
