package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
)

func TestOperatorTunnelManualRetrySkipsBackoff(t *testing.T) {
	for _, direction := range []domain.SSHTunnelDirection{domain.SSHTunnelDirectionLocal, domain.SSHTunnelDirectionReverse} {
		t.Run(string(direction), func(t *testing.T) {
			svc, transport, host := newTestService(t)
			events, _, unsubscribe := svc.SubscribeStateEvents()
			defer unsubscribe()
			config := domain.SSHTunnelConfig{Direction: direction, RemotePort: 8080}
			if direction == domain.SSHTunnelDirectionReverse {
				config.LocalPort, config.RemotePort = 8080, 0
			}
			started, err := svc.StartOperatorSSHTunnel(context.Background(), host.ID, config, "app")
			if err != nil {
				t.Fatal(err)
			}
			defer svc.StopOperatorSSHTunnel(context.Background(), started.ID, "app")
			if err := svc.RetryOperatorSSHTunnel(context.Background(), started.ID); err == nil {
				t.Fatal("manual retry accepted a running tunnel")
			}
			transport.mu.Lock()
			client := transport.tunnelClients[0]
			transport.tunnelOpenErrs = []error{errors.New("temporary connection failure")}
			transport.mu.Unlock()
			_ = client.Close()
			for attempt := 1; attempt <= 2; attempt++ {
				waitForTunnelStateEvent(t, events, started.ID, time.Second, func(tunnel domain.SSHTunnel) bool {
					return tunnel.Status == "retrying" && tunnel.ReconnectAttempt == attempt
				})
				if err := svc.RetryOperatorSSHTunnel(context.Background(), started.ID); err != nil {
					t.Fatal(err)
				}
			}
			// Automatic attempt 2 waits two seconds. Manual retry must wake it now.
			reconnected := waitForTunnelStateEvent(t, events, started.ID, time.Second, func(tunnel domain.SSHTunnel) bool {
				return tunnel.Status == "running" && tunnel.ReconnectAttempt == 0
			})
			if reconnected.ID != started.ID || reconnected.LocalPort != started.LocalPort || reconnected.RemotePort != started.RemotePort {
				t.Fatalf("manual retry changed tunnel identity or endpoints: %#v", reconnected)
			}
			transport.mu.Lock()
			clients := len(transport.tunnelClients)
			transport.mu.Unlock()
			if clients != 2 {
				t.Fatalf("opened %d SSH clients, want initial plus one replacement", clients)
			}
		})
	}
}
