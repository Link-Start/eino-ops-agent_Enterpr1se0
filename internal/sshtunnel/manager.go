// Package sshtunnel owns in-process SSH forwarding and its reconnect workers.
// Approval, credentials storage and audit policy belong to the caller.
package sshtunnel

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/security"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

var ErrNotFound = errors.New("tunnel not found")

// Resolve reloads and decrypts the current connection settings for each
// reconnect or rollback. Manager never keeps the initial credentials.
type Resolve func(context.Context, string) (domain.Host, sshx.ConnectionSpec, error)

// Publish synchronously enqueues ordered lifecycle events. It may read
// snapshots, but must not block on another lifecycle operation.
type Publish func(domain.SSHTunnel, bool)

type Manager struct {
	mu        sync.RWMutex
	states    map[string]*tunnel
	ctx       context.Context
	cancel    context.CancelFunc
	closed    bool
	workers   sync.WaitGroup
	done      chan struct{}
	transport sshx.TunnelTransport
	resolve   Resolve
	publish   Publish
	redactor  *security.Redactor
}

type tunnel struct {
	// Operations serialize user stop/replace transactions. Transitions
	// serialize metadata and event order, but never enclose network I/O.
	operation    chan struct{}
	transitionMu sync.Mutex
	mu           sync.Mutex
	value        domain.SSHTunnel
	runtime      *generation
	ctx          context.Context
	cancel       context.CancelFunc
	retry        chan struct{}
	done         chan struct{}
	active       atomic.Int64
	total        atomic.Int64
	sent         atomic.Int64
	received     atomic.Int64
}

func New(transport sshx.TunnelTransport, resolve Resolve, publish Publish, redactor *security.Redactor) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{states: make(map[string]*tunnel), ctx: ctx, cancel: cancel, done: make(chan struct{}),
		transport: transport, resolve: resolve, publish: publish, redactor: redactor}
}

func (m *Manager) begin() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return fmt.Errorf("service is shutting down")
	}
	m.workers.Add(1)
	return nil
}

// Close stops admission and cancels all generations, including connections
// still being opened. The channel closes only after their workers are joined.
func (m *Manager) Close() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		m.cancel()
		go func() { m.workers.Wait(); close(m.done) }()
	}
	return m.done
}

func (m *Manager) get(id string) (*tunnel, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	state := m.states[strings.TrimSpace(id)]
	if state == nil {
		return nil, ErrNotFound
	}
	return state, nil
}

func (m *Manager) current(state *tunnel) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.states[state.value.ID] == state
}

func (state *tunnel) snapshotLocked() domain.SSHTunnel {
	result := state.value
	result.ActiveConnections = state.active.Load()
	result.TotalConnections = state.total.Load()
	result.BytesSent, result.BytesReceived = state.sent.Load(), state.received.Load()
	return result
}

func (state *tunnel) snapshot() domain.SSHTunnel {
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.snapshotLocked()
}

func (m *Manager) Get(id string) (domain.SSHTunnel, error) {
	state, err := m.get(id)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	return state.snapshot(), nil
}

func (m *Manager) List() domain.SSHTunnelList {
	m.mu.RLock()
	states := make([]*tunnel, 0, len(m.states))
	for _, state := range m.states {
		states = append(states, state)
	}
	m.mu.RUnlock()
	items := make([]domain.SSHTunnel, 0, len(states))
	for _, state := range states {
		items = append(items, state.snapshot())
	}
	sort.Slice(items, func(i, j int) bool { return items[i].StartedAt.Before(items[j].StartedAt) })
	return domain.SSHTunnelList{Tunnels: items, Count: len(items)}
}

func (m *Manager) HasHost(hostID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, state := range m.states {
		if state.value.HostID == hostID {
			return true
		}
	}
	return false
}

// transition publishes only real changes to the current, uncanceled logical
// tunnel. The callback holds state.mu; the publisher holds neither data lock,
// so a subscriber can read authoritative snapshots without deadlocking.
func (m *Manager) transition(state *tunnel, change func(*tunnel) bool) bool {
	state.transitionMu.Lock()
	defer state.transitionMu.Unlock()
	state.mu.Lock()
	if state.ctx.Err() != nil || !change(state) {
		state.mu.Unlock()
		return false
	}
	snapshot := state.snapshotLocked()
	state.mu.Unlock()
	m.publish(snapshot, false)
	return true
}

func (m *Manager) Retry(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := m.get(id)
	if err != nil {
		return err
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.value.Status != "retrying" || state.ctx.Err() != nil {
		return fmt.Errorf("invalid tunnel status %q: only disconnected tunnels can be retried", state.value.Status)
	}
	select {
	case state.retry <- struct{}{}:
	default:
	}
	return nil
}

func (m *Manager) Stop(ctx context.Context, id string) (domain.SSHTunnel, error) {
	if strings.TrimSpace(id) == "" {
		return domain.SSHTunnel{}, fmt.Errorf("tunnel_id is required")
	}
	state, err := m.get(id)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	if err := state.lockOperation(ctx); err != nil {
		return domain.SSHTunnel{}, err
	}
	defer func() { <-state.operation }()
	if !m.current(state) {
		return domain.SSHTunnel{}, ErrNotFound
	}
	return m.stop(ctx, state)
}

func (m *Manager) stop(ctx context.Context, state *tunnel) (domain.SSHTunnel, error) {
	if err := ctx.Err(); err != nil {
		return domain.SSHTunnel{}, err
	}
	state.transitionMu.Lock()
	state.mu.Lock()
	changed := state.value.Status != "stopping" && state.value.Status != "stopped" && state.value.Status != "failed"
	if changed {
		state.value.Status = "stopping"
	}
	stopping := state.snapshotLocked()
	state.cancel()
	state.mu.Unlock()
	if changed {
		m.publish(stopping, false)
	}
	state.transitionMu.Unlock()
	select {
	case <-state.done:
		return state.snapshot(), nil
	case <-ctx.Done():
		return domain.SSHTunnel{}, ctx.Err()
	}
}

// Replace consumes already-validated target settings. Stop and replacement
// are serialized against other edits/stops of the same original instance.
// Failure restores the original ID with freshly resolved credentials.
func (m *Manager) Replace(ctx context.Context, id string, host domain.Host, connection sshx.ConnectionSpec, config domain.SSHTunnelConfig) (domain.SSHTunnel, error) {
	if err := m.begin(); err != nil {
		return domain.SSHTunnel{}, err
	}
	defer m.workers.Done()
	state, err := m.get(id)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	if err := state.lockOperation(ctx); err != nil {
		return domain.SSHTunnel{}, err
	}
	defer func() { <-state.operation }()
	if !m.current(state) {
		return domain.SSHTunnel{}, ErrNotFound
	}
	previous := state.snapshot()
	if previous.Status != "running" {
		return domain.SSHTunnel{}, fmt.Errorf("invalid tunnel status %q: only running tunnels can be edited", previous.Status)
	}
	if _, err := m.stop(ctx, state); err != nil {
		return domain.SSHTunnel{}, err
	}
	replacement, updateErr := m.Start(ctx, host, connection, config)
	if updateErr == nil {
		return replacement, nil
	}
	if m.ctx.Err() != nil {
		return domain.SSHTunnel{}, updateErr
	}
	rollbackCtx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
	defer cancel()
	restoredHost, restoredConnection, rollbackErr := m.resolve(rollbackCtx, previous.HostID)
	if rollbackErr == nil {
		_, rollbackErr = m.start(rollbackCtx, restoredHost, restoredConnection, configFromTunnel(previous), previous.ID)
	}
	if rollbackErr == nil {
		return domain.SSHTunnel{}, fmt.Errorf("update SSH tunnel: %w; previous tunnel restored", updateErr)
	}
	return domain.SSHTunnel{}, fmt.Errorf("update SSH tunnel: %w; restore previous tunnel: %v", updateErr, rollbackErr)
}

func configFromTunnel(value domain.SSHTunnel) domain.SSHTunnelConfig {
	return domain.SSHTunnelConfig{Direction: value.Direction, LocalHost: value.LocalHost, LocalPort: value.LocalPort,
		RemoteHost: value.RemoteHost, RemotePort: value.RemotePort}
}

func (state *tunnel) lockOperation(ctx context.Context) error {
	select {
	case state.operation <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
