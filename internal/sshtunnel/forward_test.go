package sshtunnel

import (
	"context"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

func TestForwardTrafficDoesNotPublishUnchangedState(t *testing.T) {
	client := newTestClient()
	target, remote := net.Pipe()
	defer target.Close()
	defer remote.Close()
	client.dial = func(string, string) (net.Conn, error) { return target, nil }
	manager, events := newTestManager(t, openFunc(func(context.Context, sshx.ConnectionSpec) (sshx.TunnelClient, error) {
		return client, nil
	}), nil)
	started := startTestTunnel(t, manager)
	awaitEvent(t, events, func(event stateEvent) bool { return event.tunnel.Status == "running" })
	echoDone := make(chan struct{})
	go func() { defer close(echoDone); _, _ = io.Copy(remote, remote) }()
	inbound, err := net.DialTimeout("tcp", net.JoinHostPort(started.LocalHost, strconv.Itoa(started.LocalPort)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()
	_ = inbound.SetDeadline(time.Now().Add(time.Second))
	const payload = "tunnel traffic"
	if _, err := io.WriteString(inbound, payload); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len(payload))
	if _, err := io.ReadFull(inbound, buffer); err != nil || string(buffer) != payload {
		t.Fatalf("echo = %q, %v", buffer, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stopped, err := manager.Stop(ctx, started.ID)
	if err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, echoDone)
	if stopped.BytesSent != int64(len(payload)) || stopped.BytesReceived != int64(len(payload)) || stopped.TotalConnections != 1 || stopped.ActiveConnections != 0 {
		t.Fatalf("final counters = %#v", stopped)
	}
	for len(events) > 0 {
		event := <-events
		if event.tunnel.Status != "stopping" && event.tunnel.Status != "stopped" {
			t.Fatalf("traffic published redundant lifecycle event: %#v", event)
		}
	}
}
