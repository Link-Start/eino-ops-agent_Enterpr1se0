package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/observability"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

const (
	sshTunnelDefaultHost = "127.0.0.1"
)

var (
	sshTunnelHostnameRE = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9])?$`)
	// ErrHostHasActiveTunnel prevents deleting connection settings still used by a forwarding worker.
	ErrHostHasActiveTunnel = errors.New("host has an active SSH tunnel")
)

type preparedOperatorSSHTunnel struct {
	host       domain.Host
	connection sshx.ConnectionSpec
	request    domain.ExecRequest
}

func (s *Service) StartSSHTunnel(ctx context.Context, hostID string, config domain.SSHTunnelConfig, reason, actor string) (domain.ExecResult, error) {
	return s.Submit(ctx, domain.ExecRequest{
		HostID:           strings.TrimSpace(hostID),
		Mode:             domain.ExecSSHTunnelStart,
		Reason:           strings.TrimSpace(reason),
		TunnelDirection:  config.Direction,
		TunnelLocalHost:  config.LocalHost,
		TunnelLocalPort:  config.LocalPort,
		TunnelRemoteHost: config.RemoteHost,
		TunnelRemotePort: config.RemotePort,
	}, actor)
}

// StartOperatorSSHTunnel starts a tunnel explicitly requested by the Web
// operator, without entering Agent approval or history.
func (s *Service) StartOperatorSSHTunnel(ctx context.Context, hostID string, config domain.SSHTunnelConfig, _ string) (domain.SSHTunnel, error) {
	prepared, err := s.prepareOperatorSSHTunnel(ctx, hostID, config)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	release, err := s.acquire(ctx, prepared.host.ID)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	defer release()
	return s.createSSHTunnel(ctx, prepared.host, prepared.connection, prepared.request)
}

func (s *Service) prepareOperatorSSHTunnel(ctx context.Context, hostID string, config domain.SSHTunnelConfig) (preparedOperatorSSHTunnel, error) {
	req := domain.ExecRequest{
		HostID:           strings.TrimSpace(hostID),
		Mode:             domain.ExecSSHTunnelStart,
		Reason:           webOperatorReason,
		TunnelDirection:  config.Direction,
		TunnelLocalHost:  config.LocalHost,
		TunnelLocalPort:  config.LocalPort,
		TunnelRemoteHost: config.RemoteHost,
		TunnelRemotePort: config.RemotePort,
	}
	normalizeRequest(&req, s.limits)
	if err := validateRequestLimits(req, s.limits, s.redactor); err != nil {
		return preparedOperatorSSHTunnel{}, err
	}
	host, err := s.store.GetHost(ctx, req.HostID)
	if err != nil {
		return preparedOperatorSSHTunnel{}, err
	}
	connection, connectionDigest, err := s.resolveSSHConnection(ctx, host)
	if err != nil {
		return preparedOperatorSSHTunnel{}, err
	}
	bindSSHRequest(&req, connectionDigest)
	if err := validateExecutionRequest(host, req); err != nil {
		return preparedOperatorSSHTunnel{}, err
	}
	connection, err = s.prepareSSHExecutionConnection(ctx, connection, connectionDigest, false, false)
	if err != nil {
		return preparedOperatorSSHTunnel{}, err
	}
	return preparedOperatorSSHTunnel{host: host, connection: connection, request: req}, nil
}

// UpdateOperatorSSHTunnel replaces an operator tunnel. Invalid target host or
// forwarding input is rejected before the existing listener is touched;
// runtime replacement failures trigger a best-effort rollback.
func (s *Service) UpdateOperatorSSHTunnel(ctx context.Context, id, hostID string, config domain.SSHTunnelConfig, _ string) (domain.SSHTunnel, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return domain.SSHTunnel{}, fmt.Errorf("tunnel_id is required")
	}
	hostID = strings.TrimSpace(hostID)
	if hostID == "" {
		return domain.SSHTunnel{}, fmt.Errorf("host_id is required")
	}
	config, err := s.normalizedSSHTunnelConfig(config)
	if err != nil {
		return domain.SSHTunnel{}, err
	}

	previous, err := s.tunnels.Get(id)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	if previous.Status != "running" {
		return domain.SSHTunnel{}, fmt.Errorf("invalid tunnel status %q: only running tunnels can be edited", previous.Status)
	}
	if previous.HostID == hostID && previous.Direction == config.Direction && previous.LocalHost == config.LocalHost && previous.LocalPort == config.LocalPort &&
		previous.RemoteHost == config.RemoteHost && previous.RemotePort == config.RemotePort {
		return previous, nil
	}
	prepared, err := s.prepareOperatorSSHTunnel(ctx, hostID, config)
	if err != nil {
		return domain.SSHTunnel{}, err
	}

	// Keep both the replacement and any rollback within host concurrency limits.
	release, err := s.acquire(ctx, prepared.host.ID, previous.HostID)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	defer release()
	return s.tunnels.Replace(ctx, previous.ID, prepared.host, prepared.connection, config)
}

func (s *Service) normalizedSSHTunnelConfig(config domain.SSHTunnelConfig) (domain.SSHTunnelConfig, error) {
	req := domain.ExecRequest{
		Mode: domain.ExecSSHTunnelStart, TunnelDirection: config.Direction,
		TunnelLocalHost: config.LocalHost, TunnelLocalPort: config.LocalPort,
		TunnelRemoteHost: config.RemoteHost, TunnelRemotePort: config.RemotePort,
	}
	normalizeRequest(&req, s.limits)
	if err := validateSSHTunnelRequest(req); err != nil {
		return domain.SSHTunnelConfig{}, err
	}
	return domain.SSHTunnelConfig{
		Direction: req.TunnelDirection, LocalHost: req.TunnelLocalHost, LocalPort: req.TunnelLocalPort,
		RemoteHost: req.TunnelRemoteHost, RemotePort: req.TunnelRemotePort,
	}, nil
}

func (s *Service) ListSSHTunnels() domain.SSHTunnelList { return s.tunnels.List() }

func (s *Service) RetryOperatorSSHTunnel(ctx context.Context, id string) error {
	return s.tunnels.Retry(ctx, id)
}

func (s *Service) StopSSHTunnel(ctx context.Context, id, actor string) (domain.SSHTunnel, error) {
	stopped, err := s.stopSSHTunnel(ctx, id)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	s.audit(context.WithoutCancel(ctx), "", "ssh_tunnel_stopped", actor, map[string]any{
		"tunnel_id": stopped.ID, "host_id": stopped.HostID, "direction": stopped.Direction,
		"local_host": stopped.LocalHost, "local_port": stopped.LocalPort,
		"remote_host": stopped.RemoteHost, "remote_port": stopped.RemotePort,
	})
	return stopped, nil
}

// StopOperatorSSHTunnel stops a tunnel directly from the Web console without
// adding the personal action to Agent execution history.
func (s *Service) StopOperatorSSHTunnel(ctx context.Context, id, _ string) (domain.SSHTunnel, error) {
	return s.stopSSHTunnel(ctx, id)
}

func (s *Service) stopSSHTunnel(ctx context.Context, id string) (domain.SSHTunnel, error) {
	stopped, err := s.tunnels.Stop(ctx, id)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	observability.FromContext(ctx).InfoContext(ctx, "SSH tunnel stopped", "component", "ssh_tunnel",
		"tunnel_id", stopped.ID, "host_id", stopped.HostID, "direction", stopped.Direction,
		"local_host", stopped.LocalHost, "local_port", stopped.LocalPort, "remote_host", stopped.RemoteHost, "remote_port", stopped.RemotePort)
	return stopped, nil
}

func (s *Service) openSSHTunnel(ctx context.Context, host domain.Host, connection sshx.ConnectionSpec, req domain.ExecRequest, actor string) (domain.SSHTunnel, error) {
	startedTunnel, err := s.createSSHTunnel(ctx, host, connection, req)
	if err != nil {
		return domain.SSHTunnel{}, err
	}
	s.audit(context.WithoutCancel(ctx), "", "ssh_tunnel_started", actor, map[string]any{
		"tunnel_id": startedTunnel.ID, "host_id": host.ID, "direction": startedTunnel.Direction,
		"local_host": startedTunnel.LocalHost, "local_port": startedTunnel.LocalPort,
		"remote_host": startedTunnel.RemoteHost, "remote_port": startedTunnel.RemotePort, "proxy_used": startedTunnel.ProxyUsed,
	})
	return startedTunnel, nil
}

func (s *Service) createSSHTunnel(ctx context.Context, host domain.Host, connection sshx.ConnectionSpec, req domain.ExecRequest) (domain.SSHTunnel, error) {
	if err := validateSSHTunnelRequest(req); err != nil {
		return domain.SSHTunnel{}, err
	}
	return s.tunnels.Start(ctx, host, connection, domain.SSHTunnelConfig{
		Direction: req.TunnelDirection, LocalHost: req.TunnelLocalHost, LocalPort: req.TunnelLocalPort,
		RemoteHost: req.TunnelRemoteHost, RemotePort: req.TunnelRemotePort})
}

// Resolve current credentials for reconnection and edit rollback. Initial
// starts use the connection already validated by the approval/operator path.
func (s *Service) resolveTunnelConnection(ctx context.Context, hostID string) (domain.Host, sshx.ConnectionSpec, error) {
	host, err := s.store.GetHost(ctx, hostID)
	if err != nil {
		return domain.Host{}, sshx.ConnectionSpec{}, err
	}
	connection, _, err := s.resolveSSHConnection(ctx, host)
	if err != nil {
		return domain.Host{}, sshx.ConnectionSpec{}, err
	}
	connection, err = s.hydrateSSHConnection(connection, false)
	return host, connection, err
}

func validateSSHTunnelRequest(req domain.ExecRequest) error {
	if req.Mode != domain.ExecSSHTunnelStart {
		return fmt.Errorf("invalid SSH tunnel request mode")
	}
	switch req.TunnelDirection {
	case domain.SSHTunnelDirectionLocal:
		if err := validateSSHTunnelHost("local_host", req.TunnelLocalHost, true); err != nil {
			return err
		}
		if err := validateSSHTunnelHost("remote_host", req.TunnelRemoteHost, false); err != nil {
			return err
		}
		if req.TunnelLocalPort < 0 || req.TunnelLocalPort > 65535 {
			return fmt.Errorf("local_port must be between 0 and 65535")
		}
		if req.TunnelRemotePort < 1 || req.TunnelRemotePort > 65535 {
			return fmt.Errorf("remote_port must be between 1 and 65535")
		}
	case domain.SSHTunnelDirectionReverse:
		if err := validateSSHTunnelHost("local_host", req.TunnelLocalHost, false); err != nil {
			return err
		}
		if err := validateSSHTunnelHost("remote_host", req.TunnelRemoteHost, true); err != nil {
			return err
		}
		if req.TunnelLocalPort < 1 || req.TunnelLocalPort > 65535 {
			return fmt.Errorf("local_port must be between 1 and 65535")
		}
		if req.TunnelRemotePort < 0 || req.TunnelRemotePort > 65535 {
			return fmt.Errorf("remote_port must be between 0 and 65535")
		}
	default:
		return fmt.Errorf("direction must be local or reverse")
	}
	if req.Elevated {
		return fmt.Errorf("SSH tunnel requests cannot use elevated mode")
	}
	return nil
}

func validateSSHTunnelHost(field, value string, requireIP bool) error {
	host := strings.Trim(strings.TrimSpace(value), "[]")
	if host == "" {
		return fmt.Errorf("%s is required", field)
	}
	if len(host) > 253 || strings.ContainsAny(host, "\x00\r\n\t /\\") {
		return fmt.Errorf("invalid %s", field)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	if requireIP {
		return fmt.Errorf("%s must be an IP address", field)
	}
	if !sshTunnelHostnameRE.MatchString(host) {
		return fmt.Errorf("invalid %s", field)
	}
	return nil
}

func sshTunnelFieldsSet(req domain.ExecRequest) bool {
	return req.TunnelDirection != "" || req.TunnelLocalHost != "" || req.TunnelLocalPort != 0 ||
		req.TunnelRemoteHost != "" || req.TunnelRemotePort != 0
}

func marshalSSHTunnel(tunnel domain.SSHTunnel) ([]byte, error) {
	data, err := json.Marshal(tunnel)
	if err != nil {
		return nil, fmt.Errorf("encode SSH tunnel state: %w", err)
	}
	return data, nil
}
