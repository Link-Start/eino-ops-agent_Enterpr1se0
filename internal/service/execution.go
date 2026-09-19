package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/ids"
	"github.com/Enterpr1se0/opsnerva/internal/observability"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

type executionObserver struct {
	RunStarted func(domain.Run)
	Output     func(string, []byte)
}

func (s *Service) Submit(ctx context.Context, req domain.ExecRequest, actor string) (domain.ExecResult, error) {
	return s.submit(ctx, req, actor, executionObserver{})
}

func (s *Service) submit(ctx context.Context, req domain.ExecRequest, actor string, observer executionObserver) (domain.ExecResult, error) {
	normalizeRequest(&req, s.limits)
	if err := validateRequestLimits(req, s.limits, s.redactor); err != nil {
		return domain.ExecResult{}, err
	}
	if strings.TrimSpace(req.Reason) == "" {
		return domain.ExecResult{}, fmt.Errorf("reason is required")
	}
	if req.Mode == domain.ExecWorkspaceUpload {
		if _, err := s.prepareWorkspaceUpload(req); err != nil {
			return domain.ExecResult{}, err
		}
	}
	host, err := s.store.GetHost(ctx, req.HostID)
	if err != nil {
		return domain.ExecResult{}, err
	}
	var rootConnections []sshx.ConnectionSpec
	if isWorkspaceMode(req.Mode) {
		if req.SSHConnectionDigest != "" || req.SourceConnectionDigest != "" {
			return domain.ExecResult{}, fmt.Errorf("SSH connection binding is invalid for local Workspace operations")
		}
	} else if req.Mode == domain.ExecSSHFileTransfer {
		connections, bindErr := s.bindSSHFileTransfer(ctx, host, &req, actor)
		err = bindErr
		if err != nil {
			return domain.ExecResult{}, err
		}
		rootConnections = append(rootConnections, connections.Destination, connections.Source)
	} else {
		if req.SourceConnectionDigest != "" {
			return domain.ExecResult{}, fmt.Errorf("source SSH connection binding is only valid for host-to-host transfers")
		}
		connection, digest, connectionErr := s.resolveSSHConnection(ctx, host)
		if connectionErr != nil {
			return domain.ExecResult{}, connectionErr
		}
		if err := requireAgentSSHAccess(actor, connection); err != nil {
			return domain.ExecResult{}, err
		}
		bindSSHRequest(&req, digest)
		rootConnections = append(rootConnections, connection)
	}
	if err := authorizeAgentRootConnections(actor, req.Elevated, rootConnections...); err != nil {
		return domain.ExecResult{}, err
	}
	if err := validateExecutionRequest(host, req); err != nil {
		return domain.ExecResult{}, err
	}
	requestJSON, digest, err := canonicalRequest(req)
	if err != nil {
		return domain.ExecResult{}, err
	}
	sessionID := SessionIDFromContext(ctx)
	if (req.Mode == domain.ExecSSHShellStart || req.Mode == domain.ExecWorkspaceShellStart) && sessionID == "" {
		return domain.ExecResult{}, fmt.Errorf("interactive shells require an Agent conversation")
	}
	settings, settingsErr := s.store.GetSystemSettings(ctx)
	if settingsErr != nil {
		return domain.ExecResult{}, settingsErr
	}
	llmRequest := actor == "eino-agent" || actor == "mcp-client"
	approvalRequired := llmRequest && settings.ApprovalMode != domain.ApprovalModeFullAccess
	requestCipher, err := s.encryptor.Encrypt([]byte(requestJSON))
	if err != nil {
		return domain.ExecResult{}, err
	}
	requestRedacted := s.redactor.Redact(requestJSON)
	now := time.Now().UTC()
	var commandExplanation *domain.CommandReview
	var explanationInput *domain.CommandReviewInput
	var reviewer ApprovalReviewer
	autoRejected := false
	if approvalRequired {
		if llmRequest && settings.ApprovalMode == domain.ApprovalModeAuto {
			input := s.automaticApprovalInput(ctx, req, host, digest, sessionID)
			review := s.reviewForAutomaticApproval(ctx, s.automaticApprovalReviewer(), input, settings.SubagentTimeoutSeconds)
			commandExplanation = &review
			switch {
			case review.Status == "completed" && review.Decision == domain.ApprovalAgentAllow:
				approvalRequired = false
			case review.Status == "completed" && review.Decision == domain.ApprovalAgentReject:
				autoRejected = true
			case review.Status == "completed" && review.Decision == domain.ApprovalAgentManual:
				approvalRequired = true
			}
		} else {
			reviewer = s.approvalReviewer()
			if settings.ApprovalExplanationsEnabled && reviewer != nil {
				input := s.commandReviewInput(ctx, req, host, digest, sessionID)
				explanationInput = &input
				commandExplanation = &domain.CommandReview{Status: "pending"}
			}
		}
	}
	reviewJSON := ""
	if commandExplanation != nil {
		if encoded, marshalErr := json.Marshal(commandExplanation); marshalErr == nil {
			reviewJSON = string(encoded)
		}
	}
	run := domain.Run{
		ID: ids.New("run"), SessionID: sessionID, HostID: host.ID, RequestJSON: requestRedacted, RequestCipher: requestCipher,
		SearchText: s.redactor.Redact(req.SearchText()), RequestDigest: digest,
		Status: "created", AIReviewJSON: reviewJSON, AIReview: commandExplanation, StartedAt: now,
	}
	if owner, ok := executionOwnerFromContext(ctx); ok {
		run.ToolName = owner.ToolName
		run.ToolArgumentsJSON = s.redactor.Redact(owner.Arguments)
	}
	logger := observability.FromContext(ctx).With(
		"session_id", sessionID, "host_id", host.ID,
		"mode", req.Mode, "program", req.Program, "elevated", req.Elevated,
		"actor", actor, "run_id", run.ID,
	)
	logger.DebugContext(ctx, "approval route selected", "approval_mode", settings.ApprovalMode, "approval_required", approvalRequired, "request_digest", digest)
	if autoRejected {
		run.Status = "rejected"
		run.Error = commandExplanation.Reason
		run.CompletedAt = time.Now().UTC()
		if err := s.store.CreateRun(ctx, run); err != nil {
			return domain.ExecResult{}, err
		}
		if observer.RunStarted != nil {
			observer.RunStarted(run)
		}
		s.audit(ctx, run.ID, "auto_approval_agent_rejected", "auto-approval-agent", map[string]any{
			"reason": commandExplanation.Reason, "model": commandExplanation.Model,
		})
		logger.With("component", "approval").InfoContext(ctx, "Auto approval Agent rejected execution", "model", commandExplanation.Model)
		return execResultFromRun(run, "", ""), nil
	}
	if approvalRequired {
		run.Status = "approval_required"
		if err := s.store.CreateRun(ctx, run); err != nil {
			return domain.ExecResult{}, err
		}
		if owner, ok := executionOwnerFromContext(ctx); ok {
			s.bindExecutionOwner(ctx, run.ID, sessionID, owner)
		}
		approval := domain.Approval{
			ID: ids.New("approval"), RunID: run.ID, HostID: host.ID, RequestJSON: requestRedacted, RequestCipher: requestCipher,
			RequestDigest: digest, Status: domain.ApprovalStatusPending,
			CreatedAt: now,
		}
		if continuation, ok := agentApprovalContinuationFromContext(ctx); ok {
			approval.Status = domain.ApprovalStatusPreparing
			approval.ContinuationKind = domain.ApprovalContinuationAgent
			approval.CheckpointID = continuation.CheckpointID
		}
		if err := s.store.CreateApproval(ctx, approval); err != nil {
			s.clearExecutionOwner(run.ID)
			return domain.ExecResult{}, err
		}
		s.audit(ctx, run.ID, "approval_requested", actor, map[string]any{"approval_id": approval.ID, "mode": settings.ApprovalMode})
		if commandExplanation != nil && commandExplanation.Status == "completed" && commandExplanation.Decision == domain.ApprovalAgentManual {
			s.audit(ctx, run.ID, "auto_approval_agent_requested_manual_review", "auto-approval-agent", map[string]any{
				"approval_id": approval.ID, "reason": commandExplanation.Reason, "model": commandExplanation.Model,
			})
		}
		logger.With("component", "approval").InfoContext(ctx, "execution awaiting approval", "approval_id", approval.ID, "approval_mode", settings.ApprovalMode)
		if commandExplanation != nil && commandExplanation.Status == "pending" && explanationInput != nil && reviewer != nil {
			s.startPendingApprovalExplanation(ctx, approval, *explanationInput, reviewer, settings.SubagentTimeoutSeconds)
		}
		if observer.RunStarted != nil {
			observer.RunStarted(run)
		}
		return domain.ExecResult{RunID: run.ID, Status: run.Status, ApprovalID: approval.ID}, nil
	}
	run.Status = "running"
	if err := s.store.CreateRun(ctx, run); err != nil {
		return domain.ExecResult{}, err
	}
	if owner, ok := executionOwnerFromContext(ctx); ok {
		s.bindExecutionOwner(ctx, run.ID, sessionID, owner)
	}
	if commandExplanation != nil && commandExplanation.Status == "completed" && commandExplanation.Decision == domain.ApprovalAgentAllow {
		s.audit(ctx, run.ID, "auto_approval_agent_granted", "auto-approval-agent", map[string]any{
			"reason": commandExplanation.Reason, "model": commandExplanation.Model,
		})
	}
	if observer.RunStarted != nil {
		observer.RunStarted(run)
	}
	return s.execute(ctx, host, req, run, actor, observer.Output)
}
