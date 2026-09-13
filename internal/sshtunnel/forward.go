package sshtunnel

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
)

func (m *Manager) serve(state *tunnel, runtime *generation) error {
	acceptErrors, clientErrors := make(chan error, 1), make(chan error, 1)
	runtime.workers.Add(2)
	config := configFromTunnel(state.snapshot())
	go func() { defer runtime.workers.Done(); acceptErrors <- m.accept(state, runtime, config) }()
	go func() { defer runtime.workers.Done(); clientErrors <- runtime.client.Wait() }()
	select {
	case <-runtime.ctx.Done():
		return nil
	case err := <-acceptErrors:
		return err
	case err := <-clientErrors:
		return err
	}
}

func (m *Manager) accept(state *tunnel, runtime *generation, config domain.SSHTunnelConfig) error {
	target := net.JoinHostPort(config.RemoteHost, strconv.Itoa(config.RemotePort))
	side := "local"
	if config.Direction == domain.SSHTunnelDirectionReverse {
		target = net.JoinHostPort(config.LocalHost, strconv.Itoa(config.LocalPort))
		side = "remote"
	}
	for {
		inbound, err := runtime.listener.Accept()
		if err != nil {
			if runtime.ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept %s tunnel connection: %w", side, err)
		}
		if !runtime.track(inbound) {
			return nil
		}
		state.total.Add(1)
		state.active.Add(1)
		// The accept worker remains counted until it stops adding relays.
		runtime.workers.Add(1)
		go m.forward(state, runtime, inbound, target, config.Direction)
	}
}

func (m *Manager) forward(state *tunnel, runtime *generation, inbound net.Conn, targetAddress string, direction domain.SSHTunnelDirection) {
	defer runtime.workers.Done()
	defer state.active.Add(-1)
	defer runtime.untrack(inbound)
	defer inbound.Close()
	var target net.Conn
	var err error
	side := "remote"
	if direction == domain.SSHTunnelDirectionReverse {
		side = "local"
		target, err = (&net.Dialer{Timeout: 10 * time.Second}).DialContext(runtime.ctx, "tcp", targetAddress)
	} else {
		target, err = runtime.client.Dial("tcp", targetAddress)
	}
	failure := ""
	if err != nil {
		failure = m.redactor.Redact(fmt.Sprintf("connect %s endpoint %s: %v", side, targetAddress, err))
	}
	m.transition(state, func(state *tunnel) bool {
		if state.runtime != runtime || state.value.Status != "running" || state.value.Error == failure {
			return false
		}
		state.value.Error = failure
		return true
	})
	if err != nil {
		return
	}
	if !runtime.track(target) {
		return
	}
	defer runtime.untrack(target)
	defer target.Close()
	inboundTotal, targetTotal := &state.sent, &state.received
	if direction == domain.SSHTunnelDirectionReverse {
		inboundTotal, targetTotal = &state.received, &state.sent
	}
	var relay sync.WaitGroup
	relay.Add(2)
	go func() {
		defer relay.Done()
		_, _ = io.Copy(countingWriter{target, inboundTotal}, inbound)
		closeWrite(target)
	}()
	go func() {
		defer relay.Done()
		_, _ = io.Copy(countingWriter{inbound, targetTotal}, target)
		closeWrite(inbound)
	}()
	relay.Wait()
}

type countingWriter struct {
	writer io.Writer
	total  *atomic.Int64
}

func (writer countingWriter) Write(data []byte) (int, error) {
	written, err := writer.writer.Write(data)
	writer.total.Add(int64(written))
	return written, err
}

func closeWrite(connection net.Conn) {
	if halfCloser, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = halfCloser.CloseWrite()
		return
	}
	_ = connection.Close()
}
