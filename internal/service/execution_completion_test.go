package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

func TestExecutionCancellationBeforeCapacityIsPersisted(t *testing.T) {
	for _, capacity := range []string{"global", "host"} {
		t.Run(capacity, func(t *testing.T) {
			svc, transport, host := newTestService(t)
			if capacity == "global" {
				for len(svc.globalSem) < cap(svc.globalSem) {
					svc.globalSem <- struct{}{}
				}
			} else {
				svc.hostSems[host.ID] = make(chan struct{}, 1)
				svc.hostSems[host.ID] <- struct{}{}
			}
			ctx, cancel := context.WithCancel(WithSessionID(context.Background(), "cancel-before-capacity"))
			defer cancel()
			events, unsubscribe := svc.SubscribeExecutionEvents(SessionIDFromContext(ctx))
			defer unsubscribe()
			var runID string
			result, err := svc.submit(ctx, domain.ExecRequest{
				HostID: host.ID, Mode: domain.ExecProgram, Program: "uname", Reason: "inspect host",
			}, "test", executionObserver{RunStarted: func(run domain.Run) {
				runID = run.ID
				cancel()
			}})
			if !errors.Is(err, context.Canceled) || result.RunID != runID || result.Status != "interrupted" || result.CompletedAt.IsZero() {
				t.Fatalf("cancelled execution lost its terminal result: %+v err=%v", result, err)
			}
			assertExecutionCompletion(t, svc, events, result)
			if len(transport.calls) != 0 {
				t.Fatal("cancelled execution reached transport")
			}
			if capacity == "host" && len(svc.globalSem) != 0 {
				t.Fatal("cancelled host wait leaked global capacity")
			}
		})
	}
}

func TestExecutionConnectionPreparationFailureCompletesOnce(t *testing.T) {
	svc, transport, host := newTestService(t)
	ctx := WithSessionID(context.Background(), "failed-connection-preparation")
	events, unsubscribe := svc.SubscribeExecutionEvents(SessionIDFromContext(ctx))
	defer unsubscribe()
	result, err := svc.submit(ctx, domain.ExecRequest{
		HostID: host.ID, Mode: domain.ExecProgram, Program: "uname", Reason: "inspect host",
	}, "test", executionObserver{RunStarted: func(domain.Run) {
		host.Address = "192.0.2.10"
		if _, err := svc.store.UpsertHost(ctx, host); err != nil {
			t.Fatal(err)
		}
	}})
	if err == nil || result.Status != "failed" || result.Stderr == "" || result.ExitCode != -1 {
		t.Fatalf("preparation failure was not reported consistently: %+v err=%v", result, err)
	}
	assertExecutionCompletion(t, svc, events, result)
	if len(transport.calls) != 0 || len(svc.globalSem) != 0 || len(svc.hostSems[host.ID]) != 0 {
		t.Fatal("failed preparation executed or leaked capacity")
	}
}

func TestExecutionCancellationWhileWaitingForHostCompletes(t *testing.T) {
	svc, transport, host := newTestService(t)
	svc.limits.HostConcurrency = 1
	release, err := svc.acquire(context.Background(), host.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithCancel(WithSessionID(context.Background(), "cancel-host-wait"))
	defer cancel()
	events, unsubscribe := svc.SubscribeExecutionEvents(SessionIDFromContext(ctx))
	defer unsubscribe()
	type outcome struct {
		result domain.ExecResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		result, err := svc.Submit(ctx, domain.ExecRequest{
			HostID: host.ID, Mode: domain.ExecProgram, Program: "uname", Reason: "inspect host",
		}, "test")
		done <- outcome{result, err}
	}()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	// The extra global permit means execute has passed preparation and entered
	// acquire, but cannot obtain the host permit held by this test.
	for len(svc.globalSem) != 2 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("execution did not reach the host capacity wait")
		case finished := <-done:
			t.Fatalf("execution bypassed host capacity: %+v", finished)
		}
	}
	cancel()
	select {
	case finished := <-done:
		if !errors.Is(finished.err, context.Canceled) || finished.result.Status != "interrupted" {
			t.Fatalf("waiting execution lost its cancellation: %+v", finished)
		}
		assertExecutionCompletion(t, svc, events, finished.result)
	case <-deadline.C:
		t.Fatal("cancelled capacity wait did not return")
	}
	if len(svc.globalSem) != 1 || len(svc.hostSems[host.ID]) != 1 || len(transport.calls) != 0 {
		t.Fatal("cancelled waiter leaked capacity or reached transport")
	}
}

func TestExecutionPersistenceFailurePreservesCauseAndDoesNotPublishCompletion(t *testing.T) {
	svc, transport, host := newTestService(t)
	cause := errors.New("transport disconnected")
	transport.execErr = cause
	svc.transport = &completionHookTransport{fakeTransport: transport, afterExec: func() {
		if err := svc.store.Close(); err != nil {
			t.Fatal(err)
		}
	}}
	ctx := WithSessionID(context.Background(), "failed-completion-write")
	events, unsubscribe := svc.SubscribeExecutionEvents(SessionIDFromContext(ctx))
	defer unsubscribe()
	result, err := svc.Submit(ctx, domain.ExecRequest{
		HostID: host.ID, Mode: domain.ExecProgram, Program: "uname", Reason: "inspect host",
	}, "test")
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "persist execution result") || result.RunID == "" {
		t.Fatalf("completion write hid the execution identity or error: %+v err=%v", result, err)
	}
	for len(events) > 0 {
		if event := <-events; terminalExecutionStatus(event.Status) {
			t.Fatalf("published a completion that was not saved: %+v", event)
		}
	}
}

func TestExecutionPreparationPersistenceFailureDoesNotPublishCompletion(t *testing.T) {
	svc, _, host := newTestService(t)
	ctx := WithSessionID(context.Background(), "failed-preparation-write")
	events, unsubscribe := svc.SubscribeExecutionEvents(SessionIDFromContext(ctx))
	defer unsubscribe()
	result, err := svc.submit(ctx, domain.ExecRequest{
		HostID: host.ID, Mode: domain.ExecProgram, Program: "uname", Reason: "inspect host",
	}, "test", executionObserver{RunStarted: func(domain.Run) {
		if err := svc.store.Close(); err != nil {
			t.Fatal(err)
		}
	}})
	if err == nil || !strings.Contains(err.Error(), "persist execution result") || result.RunID == "" {
		t.Fatalf("preparation completion write failed silently: %+v err=%v", result, err)
	}
	if len(events) != 0 {
		t.Fatalf("preparation published an unsaved terminal event: %+v", <-events)
	}
}

func TestExecutionCompletionPreservesOutputAfterCancellation(t *testing.T) {
	for _, outcome := range []struct {
		name   string
		cause  error
		status string
	}{
		{name: "transport deadline", cause: context.DeadlineExceeded, status: "interrupted"},
		{name: "caller cancelled with transport error", cause: errors.New("connection closed"), status: "interrupted"},
		{name: "known success before cancellation", status: "completed"},
	} {
		t.Run(outcome.name, func(t *testing.T) {
			svc, transport, host := newTestService(t)
			ctx, cancel := context.WithCancel(WithSessionID(context.Background(), "cancel-with-output"))
			defer cancel()
			transport.stdout = []byte("useful output\n")
			transport.execErr = outcome.cause
			svc.transport = &completionHookTransport{fakeTransport: transport, afterExec: cancel}
			events, unsubscribe := svc.SubscribeExecutionEvents(SessionIDFromContext(ctx))
			defer unsubscribe()
			result, err := svc.Submit(ctx, domain.ExecRequest{
				HostID: host.ID, Mode: domain.ExecProgram, Program: "uname", Reason: "inspect host",
			}, "test")
			if !errors.Is(err, outcome.cause) || result.Status != outcome.status || result.Stdout != "useful output\n" {
				t.Fatalf("completion lost the known outcome: %+v err=%v", result, err)
			}
			assertExecutionCompletion(t, svc, events, result)
			run, err := svc.store.GetRun(context.Background(), result.RunID)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := svc.encryptor.Decrypt(run.StdoutCipher)
			if err != nil || string(plain) != "useful output\n" {
				t.Fatalf("cancelled caller prevented raw output persistence: %q err=%v", plain, err)
			}
		})
	}
}

func TestExecutionCompletionRedactsError(t *testing.T) {
	svc, transport, host := newTestService(t)
	transport.execErr = errors.New("password=execution-secret")
	ctx := WithSessionID(context.Background(), "redacted-execution-error")
	events, unsubscribe := svc.SubscribeExecutionEvents(SessionIDFromContext(ctx))
	defer unsubscribe()
	result, err := svc.Submit(ctx, domain.ExecRequest{
		HostID: host.ID, Mode: domain.ExecProgram, Program: "uname", Reason: "inspect host",
	}, "test")
	if !errors.Is(err, transport.execErr) || result.Stderr != "password=[REDACTED]" {
		t.Fatalf("execution error was not redacted in its result: %+v err=%v", result, err)
	}
	assertExecutionCompletion(t, svc, events, result)
	run, err := svc.store.GetRun(context.Background(), result.RunID)
	if err != nil || run.Error != result.Stderr {
		t.Fatalf("stored error was not redacted: %+v err=%v", run, err)
	}
}

type completionHookTransport struct {
	*fakeTransport
	afterExec func()
}

func (f *completionHookTransport) Exec(ctx context.Context, connection sshx.ConnectionSpec, req domain.ExecRequest) (sshx.RawResult, error) {
	raw, err := f.fakeTransport.Exec(ctx, connection, req)
	f.afterExec()
	return raw, err
}

func assertExecutionCompletion(t *testing.T, svc *Service, events <-chan ExecutionEvent, result domain.ExecResult) {
	t.Helper()
	run, err := svc.store.GetRun(context.Background(), result.RunID)
	if err != nil || run.Status != result.Status || run.CompletedAt.IsZero() || run.ExitCode != result.ExitCode {
		t.Fatalf("stored execution differs from result: %+v result=%+v err=%v", run, result, err)
	}
	terminalEvents := 0
	for len(events) > 0 {
		event := <-events
		if terminalExecutionStatus(event.Status) {
			terminalEvents++
			if event.RunID != run.ID || event.Status != run.Status {
				t.Fatalf("completion event differs from stored execution: %+v", event)
			}
		}
	}
	if terminalEvents != 1 {
		t.Fatalf("terminal events = %d, want 1", terminalEvents)
	}
	audit, err := svc.ListAudit(context.Background(), run.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	completions := 0
	for _, event := range audit {
		if event.Type == "command_completed" {
			completions++
		}
	}
	if completions != 1 {
		t.Fatalf("completion audit events = %d, want 1: %+v", completions, audit)
	}
}
