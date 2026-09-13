package sshtunnel

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

// generation owns one SSH client, listener, all forwarded sockets and their
// workers. Nothing from an old generation can close a replacement's sockets.
type generation struct {
	ctx         context.Context
	cancel      context.CancelFunc
	listener    net.Listener
	client      sshx.TunnelClient
	closeClient func()
	closeOnce   sync.Once
	mu          sync.Mutex
	closed      bool
	connections map[net.Conn]struct{}
	workers     sync.WaitGroup
}

func (runtime *generation) close() {
	runtime.closeOnce.Do(func() {
		runtime.mu.Lock()
		runtime.closed = true
		connections := make([]net.Conn, 0, len(runtime.connections))
		for connection := range runtime.connections {
			connections = append(connections, connection)
		}
		runtime.mu.Unlock()
		runtime.cancel()
		// Reverse listener Close waits for cancel-tcpip-forward's reply.
		// Close SSH first so an unresponsive peer cannot block teardown.
		runtime.closeClient()
		_ = runtime.listener.Close()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
}

func (runtime *generation) track(connection net.Conn) bool {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		_ = connection.Close()
		return false
	}
	runtime.connections[connection] = struct{}{}
	return true
}

func (runtime *generation) untrack(connection net.Conn) {
	runtime.mu.Lock()
	delete(runtime.connections, connection)
	runtime.mu.Unlock()
}

func openRuntime(startupParent, tunnelCtx context.Context, transport sshx.TunnelTransport, connection sshx.ConnectionSpec, config domain.SSHTunnelConfig) (*generation, int, int, error) {
	runtimeCtx, cancelRuntime := context.WithCancel(tunnelCtx)
	startupCtx, cancelStartup := context.WithCancel(startupParent)
	stopStartup := context.AfterFunc(runtimeCtx, cancelStartup)
	defer func() { stopStartup(); cancelStartup() }()
	client, err := transport.OpenTunnel(startupCtx, connection)
	if err != nil {
		cancelRuntime()
		return nil, 0, 0, err
	}
	closeClient := sync.OnceFunc(func() { _ = client.Close() })
	// Reverse Listen has no context argument. Keep cancellation connected to
	// the client until both authentication AND listener setup have completed.
	closedOnCancel := make(chan struct{})
	stopClient := context.AfterFunc(startupCtx, func() { closeClient(); close(closedOnCancel) })
	releaseStartupClient := sync.OnceFunc(func() {
		if !stopClient() {
			<-closedOnCancel
		}
	})
	defer releaseStartupClient()
	var listener net.Listener
	if err = startupCtx.Err(); err == nil {
		switch config.Direction {
		case domain.SSHTunnelDirectionLocal:
			listener, err = (&net.ListenConfig{}).Listen(startupCtx, "tcp", net.JoinHostPort(config.LocalHost, strconv.Itoa(config.LocalPort)))
			if err != nil {
				err = fmt.Errorf("listen on local endpoint %s:%d: %w", config.LocalHost, config.LocalPort, err)
			}
		case domain.SSHTunnelDirectionReverse:
			reverse, ok := client.(sshx.ReverseTunnelClient)
			if !ok {
				err = fmt.Errorf("configured SSH transport does not support reverse port forwarding")
				break
			}
			listener, err = reverse.Listen("tcp", net.JoinHostPort(config.RemoteHost, strconv.Itoa(config.RemotePort)))
			if err != nil {
				err = fmt.Errorf("listen on remote endpoint %s:%d: %w", config.RemoteHost, config.RemotePort, err)
			}
		default:
			err = fmt.Errorf("invalid SSH tunnel direction %q", config.Direction)
		}
	}
	// Join a fired cancellation callback before handing ownership to runtime.
	releaseStartupClient()
	if err == nil {
		err = startupCtx.Err()
	}
	if err != nil {
		cancelRuntime()
		closeClient()
		if listener != nil {
			_ = listener.Close()
		}
		return nil, 0, 0, err
	}
	runtime := &generation{ctx: runtimeCtx, cancel: cancelRuntime, listener: listener, client: client,
		closeClient: closeClient, connections: make(map[net.Conn]struct{})}
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		runtime.close()
		return nil, 0, 0, fmt.Errorf("resolve SSH tunnel listener address: %w", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		runtime.close()
		return nil, 0, 0, fmt.Errorf("resolve SSH tunnel listener port: %w", err)
	}
	localPort, remotePort := config.LocalPort, config.RemotePort
	if config.Direction == domain.SSHTunnelDirectionLocal {
		localPort = port
	} else {
		remotePort = port
	}
	return runtime, localPort, remotePort, nil
}
