package service

import (
	"context"
	"fmt"
	"time"

	"github.com/Enterpr1se0/opsnerva/internal/domain"
	"github.com/Enterpr1se0/opsnerva/internal/observability"
	"github.com/Enterpr1se0/opsnerva/internal/sshx"
)

// executionOutput separates transport output from the durable Run and tool view.
type executionOutput struct {
	raw    sshx.RawResult
	tunnel *domain.SSHTunnel
	shell  *domain.SSHShell
}

func (s *Service) execute(ctx context.Context, host domain.Host, req domain.ExecRequest, run domain.Run, actor string, stream func(string, []byte)) (domain.ExecResult, error) {
	ctx = s.withExecutionOwnerForRun(ctx, run.ID)
	defer s.clearExecutionOwner(run.ID)
	observability.FromContext(ctx).InfoContext(ctx, "operation execution started",
		"component", "execution", "run_id", run.ID, "session_id", run.SessionID, "host_id", host.ID,
		"mode", req.Mode, "program", req.Program, "elevated", req.Elevated)
	output, err := s.runExecution(ctx, host, req, run, actor, stream)
	return s.finishExecution(ctx, run, req, output, actor, err)
}

// runExecution only prepares and executes the operation. All exits, including
// cancelled capacity waits and preparation failures, return to one finalizer.
func (s *Service) runExecution(ctx context.Context, host domain.Host, req domain.ExecRequest, run domain.Run, actor string, stream func(string, []byte)) (executionOutput, error) {
	output := executionOutput{raw: sshx.RawResult{ExitCode: -1}}
	if err := ctx.Err(); err != nil {
		return output, err
	}
	if req.Mode == domain.ExecWorkspaceUpload {
		prepared, prepareErr := s.prepareWorkspaceUpload(req)
		if prepareErr != nil {
			return output, prepareErr
		}
		req = prepared
	}
	transportReq := req
	if req.Mode == domain.ExecRemoteRead {
		transportReq.Mode = domain.ExecScript
		transportReq.Script = buildRemoteFileReadScript(req)
	}
	if req.Mode == domain.ExecRemoteSearch {
		transportReq.Mode = domain.ExecScript
		transportReq.Script = buildRemoteFileSearchScript(req)
	}
	if req.Mode == domain.ExecRemoteEdit {
		prepared, prepareErr := s.prepareRemoteFileChange(req)
		if prepareErr != nil {
			return output, prepareErr
		}
		transportReq = prepared
	}
	hostIDs := []string{host.ID}
	if req.Mode == domain.ExecSSHFileTransfer {
		hostIDs = append(hostIDs, req.SourceHostID)
	}
	release, err := s.acquire(ctx, hostIDs...)
	if err != nil {
		return output, err
	}
	defer release()
	var connection sshx.ConnectionSpec
	if !isWorkspaceMode(req.Mode) && req.Mode != domain.ExecSSHFileTransfer {
		var currentDigest string
		latestHost, connectionErr := s.store.GetHost(ctx, host.ID)
		if connectionErr == nil {
			connection, currentDigest, connectionErr = s.resolveSSHConnection(ctx, latestHost)
			if connectionErr == nil {
				connectionErr = verifySSHRequestBinding(req, currentDigest)
			}
		}
		if connectionErr == nil {
			connection, connectionErr = s.prepareSSHExecutionConnection(
				ctx, connection, currentDigest, req.Elevated, requiresDetectedShell(req.Mode, transportReq.Mode),
			)
		}
		err = connectionErr
	}
	if err != nil {
		return output, err
	}
	s.audit(ctx, run.ID, "command_started", actor, map[string]any{"digest": run.RequestDigest})
	s.publishExecutionEvent(ExecutionEvent{
		SessionID: run.SessionID,
		RunID:     run.ID,
		Status:    "running",
	})
	var execErr error
	var outputSink *executionOutputSink
	if stream != nil || s.hasExecutionSubscribers(run.SessionID) || s.hasApprovalTask(run.ID) {
		outputSink = s.newExecutionOutputSink(run, stream)
		defer outputSink.Flush()
	}
	if req.Mode == domain.ExecSSHTunnelStart {
		started := time.Now()
		created, tunnelErr := s.openSSHTunnel(ctx, host, connection, req, actor)
		execErr = tunnelErr
		output.raw.Duration = time.Since(started)
		if tunnelErr == nil {
			output.tunnel = &created
			output.raw.ExitCode = 0
			output.raw.Stdout, execErr = marshalSSHTunnel(created)
		}
	} else if req.Mode == domain.ExecSSHShellStart {
		started := time.Now()
		created, shellErr := s.openSSHShell(ctx, host, connection, req, run, actor)
		execErr = shellErr
		output.raw.Duration = time.Since(started)
		if shellErr == nil {
			output.shell = &created
			output.raw.ExitCode = 0
			output.raw.Stdout, execErr = marshalSSHShell(created)
		}
	} else if req.Mode == domain.ExecWorkspaceShellStart {
		started := time.Now()
		created, shellErr := s.openWorkspaceShell(ctx, host, req, run, actor)
		execErr = shellErr
		output.raw.Duration = time.Since(started)
		if shellErr == nil {
			output.shell = &created
			output.raw.ExitCode = 0
			output.raw.Stdout, execErr = marshalSSHShell(created)
		}
	} else if req.Mode == domain.ExecSSHFileTransfer {
		output.raw, execErr = s.executeSSHFileTransfer(ctx, run, req)
	} else if req.Mode == domain.ExecWorkspaceUpload {
		transport, ok := s.transport.(sshx.WorkspaceFileUploadTransport)
		if !ok {
			execErr = fmt.Errorf("configured SSH transport does not support Workspace file upload")
		} else {
			output.raw, execErr = transport.UploadWorkspaceFile(ctx, connection, req, s.executionTransferReporter(run))
		}
	} else if req.Mode == domain.ExecWorkspaceDownload {
		output.raw, execErr = s.executeWorkspaceDownload(ctx, connection, req, run, actor)
	} else if isWorkspaceMode(req.Mode) {
		var workspaceStream func(string, []byte)
		if outputSink != nil {
			workspaceStream = outputSink.Write
		}
		output.raw, execErr = s.executeWorkspace(ctx, req, actor, workspaceStream)
	} else if streaming, ok := s.transport.(sshx.StreamingTransport); ok && outputSink != nil {
		output.raw, execErr = streaming.ExecStream(ctx, connection, transportReq, outputSink.Write)
	} else {
		output.raw, execErr = s.transport.Exec(ctx, connection, transportReq)
	}
	return output, execErr
}
