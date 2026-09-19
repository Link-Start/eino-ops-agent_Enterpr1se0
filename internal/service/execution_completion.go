package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/observability"
)

const executionCompletionTimeout = 5 * time.Second

// finishExecution owns the only completion write for an attempted execution.
// Caller cancellation must not prevent saving its outcome. A failed write is
// returned together with the original cause and never emits a terminal event.
func (s *Service) finishExecution(ctx context.Context, run domain.Run, req domain.ExecRequest, output executionOutput, actor string, execErr error) (domain.ExecResult, error) {
	raw := output.raw
	run.ExitCode = raw.ExitCode
	run.StdoutRedacted = s.redactor.Redact(string(raw.Stdout))
	run.StderrRedacted = s.redactor.Redact(string(raw.Stderr))
	var err error
	run.StdoutCipher, err = s.encryptor.Encrypt(raw.Stdout)
	if err != nil {
		execErr = errors.Join(execErr, fmt.Errorf("encrypt execution stdout: %w", err))
	}
	run.StderrCipher, err = s.encryptor.Encrypt(raw.Stderr)
	if err != nil {
		execErr = errors.Join(execErr, fmt.Errorf("encrypt execution stderr: %w", err))
	}
	run.CompletedAt = time.Now().UTC()
	run.Error = ""
	switch {
	case execErr != nil:
		run.Status = "failed"
		if errors.Is(execErr, context.Canceled) || errors.Is(execErr, context.DeadlineExceeded) || ctx.Err() != nil {
			run.Status = "interrupted"
		}
		run.Error = s.redactor.Redact(execErr.Error())
	case raw.ExitCode != 0:
		run.Error = "remote command exited with code " + strconv.Itoa(raw.ExitCode)
		run.Status = "failed"
		if len(bytes.TrimSpace(raw.Stdout)) > 0 {
			run.Status = "partial"
		}
	default:
		run.Status = "completed"
	}
	result := executionResult(run, req, output)
	logger := observability.FromContext(ctx).With(
		"component", "execution", "run_id", run.ID, "session_id", run.SessionID, "host_id", run.HostID,
		"mode", req.Mode, "program", req.Program, "elevated", req.Elevated,
	)
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), executionCompletionTimeout)
	defer cancel()
	if err := s.store.UpdateRun(persistCtx, run); err != nil {
		logger.ErrorContext(persistCtx, "persist execution result failed", "error", err)
		return result, errors.Join(execErr, fmt.Errorf("persist execution result: %w", err))
	}
	s.audit(persistCtx, run.ID, "command_completed", actor, map[string]any{
		"status": run.Status, "exit_code": run.ExitCode, "duration_ms": raw.Duration.Milliseconds(), "error": run.Error,
	})
	s.publishExecutionEvent(ExecutionEvent{SessionID: run.SessionID, RunID: run.ID, Status: run.Status})
	completion := logger.InfoContext
	if run.Status == "failed" {
		completion = logger.ErrorContext
	}
	completion(persistCtx, "operation execution completed", "status", run.Status, "exit_code", run.ExitCode,
		"duration_ms", raw.Duration.Milliseconds(), "stdout_bytes", len(raw.Stdout), "stderr_bytes", len(raw.Stderr), "error", run.Error)
	return result, execErr
}
