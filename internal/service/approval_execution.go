package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/observability"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

type approvedExecution struct {
	approval domain.Approval
	request  domain.ExecRequest
	run      domain.Run
	host     domain.Host
	actor    string
}

func (s *Service) loadApprovalExecution(ctx context.Context, approval domain.Approval) (approvedExecution, error) {
	requestData, err := s.encryptor.Decrypt(approval.RequestCipher)
	if err != nil {
		return approvedExecution{}, err
	}
	if len(requestData) == 0 {
		requestData = []byte(approval.RequestJSON)
	}
	var req domain.ExecRequest
	if err := json.Unmarshal(requestData, &req); err != nil {
		return approvedExecution{}, err
	}
	_, digest, err := canonicalRequest(req)
	if err != nil || digest != approval.RequestDigest {
		return approvedExecution{}, fmt.Errorf("approved request digest no longer matches")
	}
	run, err := s.store.GetRun(ctx, approval.RunID)
	if err != nil {
		return approvedExecution{}, err
	}
	host, err := s.store.GetHost(ctx, approval.HostID)
	if err != nil {
		return approvedExecution{}, err
	}
	return approvedExecution{approval: approval, request: req, run: run, host: host}, nil
}

func (s *Service) startApprovedExecution(parent context.Context, approved approvedExecution) error {
	executionCtx, cancel := context.WithCancel(context.WithoutCancel(parent))
	s.executionMu.Lock()
	if s.executionClosed {
		s.executionMu.Unlock()
		cancel()
		return fmt.Errorf("service is shutting down")
	}
	if _, cancelled := s.cancelledExecutions[approved.run.ID]; cancelled {
		delete(s.cancelledExecutions, approved.run.ID)
		s.executionMu.Unlock()
		cancel()
		return context.Canceled
	}
	s.executionCancels[approved.run.ID] = cancel
	s.executionWG.Add(1)
	s.executionMu.Unlock()

	stopServiceCancellation := context.AfterFunc(s.executionCtx, cancel)
	go func() {
		defer s.executionWG.Done()
		defer stopServiceCancellation()
		defer cancel()
		defer func() {
			s.executionMu.Lock()
			delete(s.executionCancels, approved.run.ID)
			delete(s.cancelledExecutions, approved.run.ID)
			s.executionMu.Unlock()
		}()
		defer func() {
			if recovered := recover(); recovered != nil {
				err := fmt.Errorf("approved execution stopped unexpectedly")
				observability.FromContext(executionCtx).ErrorContext(executionCtx, "approved execution panicked", "run_id", approved.run.ID, "panic", s.redactor.Redact(fmt.Sprint(recovered)))
				_, _ = s.finishApprovedExecutionError(executionCtx, approved, err)
			}
		}()
		_, _ = s.execute(executionCtx, approved.host, approved.request, approved.run, approved.actor, nil)
	}()
	return nil
}

func (s *Service) cancelApprovedExecution(runID string) bool {
	if runID == "" {
		return false
	}
	s.executionMu.Lock()
	cancel := s.executionCancels[runID]
	if cancel == nil {
		s.cancelledExecutions[runID] = struct{}{}
	}
	s.executionMu.Unlock()
	if cancel != nil {
		cancel()
	}
	return true
}

// finishApprovedExecutionError handles failures before execute is entered and
// panics in the detached approval worker. Normal execution errors are already
// finalized by execute and must not trigger a second completion attempt.
func (s *Service) finishApprovedExecutionError(parent context.Context, approved approvedExecution, cause error) (domain.ExecResult, error) {
	defer s.clearExecutionOwner(approved.run.ID)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), executionCompletionTimeout)
	defer cancel()
	run, err := s.store.GetRun(ctx, approved.run.ID)
	if err != nil {
		observability.FromContext(ctx).ErrorContext(ctx, "load approved execution failure state failed", "run_id", approved.run.ID, "error", err)
		return domain.ExecResult{RunID: approved.run.ID, ApprovalID: approved.approval.ID},
			errors.Join(cause, fmt.Errorf("load approved execution: %w", err))
	}
	if terminalExecutionStatus(run.Status) {
		return execResultFromRun(run, approved.approval.ID, ""), cause
	}
	output := executionOutput{raw: sshx.RawResult{ExitCode: -1}}
	result, err := s.finishExecution(parent, run, approved.request, output, approved.actor, cause)
	result.ApprovalID = approved.approval.ID
	return result, err
}
