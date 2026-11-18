import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from backend.app.config import settings, BASE_DIR
from backend.app.core.models import (
    DynamicSandboxRun,
    SandboxEnvironmentInfo,
    SandboxCapabilityMatrix,
    DynamicObservation,
    DynamicReport
)
from backend.app.database.repository import repo
from backend.app.analyzers.dynamic.sandbox_registry import sandbox_registry
from backend.app.analyzers.dynamic.sandbox_capabilities import sandbox_capabilities
from backend.app.analyzers.dynamic.sandbox_policy import sandbox_policy
from backend.app.analyzers.dynamic.windows_sandbox import windows_sandbox_provider
from backend.app.analyzers.dynamic.hyperv_provider import hyperv_provider
from backend.app.analyzers.dynamic.virtualbox_provider import virtualbox_provider
from backend.app.analyzers.dynamic.vmware_provider import vmware_provider
from backend.app.analyzers.dynamic.kvm_provider import kvm_provider
from backend.app.analyzers.dynamic.proxmox_provider import proxmox_provider
from backend.app.analyzers.dynamic.cape_provider import cape_provider
from backend.app.analyzers.dynamic.android_emulator_provider import android_emulator_provider
from backend.app.analyzers.dynamic.genymotion_provider import genymotion_provider
from backend.app.analyzers.dynamic.mobfs_dynamic_adapter import mobsf_dynamic_adapter
from backend.app.analyzers.dynamic.telemetry_collector import telemetry_collector
from backend.app.analyzers.dynamic.behavior_analyzer import behavior_analyzer
from backend.app.analyzers.dynamic.dynamic_report_generator import dynamic_report_generator
from backend.app.analyzers.dynamic.sandbox_cleanup import sandbox_cleanup
from backend.app.analyzers.dynamic.worker_auth import worker_auth_manager
from backend.app.analyzers.dynamic.resource_manager import vm_resource_manager, ResourceExhaustionError

logger = logging.getLogger(__name__)

class DynamicSandboxManager:
    """
    High-level facade orchestrating isolated dynamic analysis sessions,
    provider lifecycle, evidence staging, telemetry collation, and chain-of-custody logging.
    """

    def __init__(self):
        # Register all core providers
        sandbox_registry.register(windows_sandbox_provider)
        sandbox_registry.register(hyperv_provider)
        sandbox_registry.register(virtualbox_provider)
        sandbox_registry.register(vmware_provider)
        sandbox_registry.register(kvm_provider)
        sandbox_registry.register(proxmox_provider)
        sandbox_registry.register(cape_provider)
        sandbox_registry.register(android_emulator_provider)
        sandbox_registry.register(genymotion_provider)
        sandbox_registry.register(mobsf_dynamic_adapter)

    def get_capabilities(self, force_refresh: bool = False) -> SandboxCapabilityMatrix:
        return sandbox_capabilities.get_capabilities(force_refresh=force_refresh)

    def list_environments(self, force_refresh: bool = False) -> List[SandboxEnvironmentInfo]:
        return sandbox_capabilities.list_environments(force_refresh=force_refresh)

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Calculates aggregated metrics for the Dynamic Analysis Lab dashboard."""
        all_runs = repo.list_all_sandbox_runs(limit=1000)
        envs = self.list_environments()

        total = len(all_runs)
        running = sum(1 for r in all_runs if r.status in ("RUNNING", "INITIALIZING", "PROVISIONING"))
        completed = sum(1 for r in all_runs if r.status == "COMPLETED")
        failed = sum(1 for r in all_runs if r.status in ("FAILED", "CANCELLED"))
        apk_runs = sum(1 for r in all_runs if r.target_type == "apk")
        exe_runs = sum(1 for r in all_runs if r.target_type == "exe")
        detections = sum(1 for r in all_runs if r.risk_score >= 3.0)
        available_envs = sum(1 for e in envs if e.is_available)

        return {
            "total_dynamic_analyses": total,
            "running_analyses": running,
            "completed_analyses": completed,
            "failed_analyses": failed,
            "apk_analyses": apk_runs,
            "exe_analyses": exe_runs,
            "malware_detections": detections,
            "available_environments": available_envs,
            "total_environments": len(envs),
            "environments": [e.model_dump() if hasattr(e, "model_dump") else e.dict() for e in envs]
        }

    def create_analysis_session(
        self,
        investigation_id: str,
        evidence_id: str,
        environment_id: str,
        network_policy: str = "DISABLED",
        timeout_seconds: int = 120,
        user_id: Optional[str] = None
    ) -> DynamicSandboxRun:
        """
        Creates, stages, and registers a dynamic analysis session.
        Enforces zero host execution and verifies evidence integrity.
        """
        inv = repo.get_investigation(investigation_id)
        if not inv:
            raise ValueError(f"Investigation {investigation_id} does not exist.")

        # Find target evidence file on disk
        target_path = self._resolve_evidence_path(investigation_id, inv.filename)
        expected_sha256 = inv.sha256

        # Safety Preflight Check
        sandbox_policy.validate_execution_target(environment_id, target_path, expected_sha256)

        run_id = f"RUN-{datetime.utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        # Create isolated staging working copy
        staged_target, staged_sha256 = sandbox_policy.create_isolated_staging_copy(
            analysis_id=run_id,
            original_evidence_path=target_path,
            expected_sha256=expected_sha256
        )

        norm_net_policy = sandbox_policy.enforce_network_policy(network_policy)
        valid_timeout = sandbox_policy.validate_timeout(timeout_seconds)
        target_type = "apk" if inv.filename.lower().endswith(".apk") else (
            "exe" if inv.filename.lower().endswith((".exe", ".dll", ".sys")) else "generic"
        )

        # Resolve provider
        provider = sandbox_registry.get_provider(environment_id) or sandbox_registry.resolve_best_provider(target_type)
        provider_name = provider.name if provider else environment_id

        run = DynamicSandboxRun(
            id=run_id,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            target_binary=inv.filename,
            sandbox_environment=provider_name,
            status="PENDING",
            is_simulated_network=(norm_net_policy == "ISOLATED_SIMULATION"),
            simulated_services=["DNS", "HTTP", "HTTPS"] if norm_net_policy == "ISOLATED_SIMULATION" else [],
            duration_seconds=0.0,
            started_at_utc=datetime.utcnow().isoformat(),
            process_count=0,
            file_event_count=0,
            registry_event_count=0,
            network_flow_count=0,
            dropped_artifacts_count=0,
            sandbox_logs=[
                f"[{datetime.utcnow().isoformat()}] Session {run_id} staged.",
                f"[{datetime.utcnow().isoformat()}] Target binary: {inv.filename} (SHA-256: {staged_sha256})",
                f"[{datetime.utcnow().isoformat()}] Staged path: {staged_target}",
                f"[{datetime.utcnow().isoformat()}] Designated environment: {provider_name}",
                f"[{datetime.utcnow().isoformat()}] Network containment policy: {norm_net_policy}"
            ],
            limitations="Isolated execution strictly enforced. No malware executed on host.",
            user_id=user_id,
            target_sha256=staged_sha256,
            target_type=target_type,
            provider=provider.provider_id if provider else environment_id,
            environment_id=environment_id,
            network_policy=norm_net_policy,
            timeout_seconds=valid_timeout
        )

        repo.create_sandbox_run(run)

        # Record Chain-of-Custody Event: EVIDENCE_STAGED
        self._record_custody(
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            action="EVIDENCE_STAGED_FOR_SANDBOX",
            details={"run_id": run_id, "environment": provider_name, "staged_sha256": staged_sha256}
        )

        return run

    def start_analysis_session(self, run_id: str) -> DynamicSandboxRun:
        """
        Launches the isolated execution inside the designated guest environment.
        Requires explicit examiner confirmation.
        """
        run = repo.get_sandbox_run(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found.")

        # Check resource budgets and reserve concurrency slot
        vm_resource_manager.allocate_worker_resources(run.id)

        provider = sandbox_registry.get_provider(run.provider or run.environment_id)
        if not provider:
            vm_resource_manager.release_worker_resources(run.id)
            run.status = "FAILED"
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Error: Provider '{run.provider}' not available.")
            repo.update_sandbox_run(run)
            raise RuntimeError(f"Sandbox provider '{run.provider}' is not available.")

        # Check preflight readiness
        pre = provider.preflight()
        if not pre.get("ready"):
            vm_resource_manager.release_worker_resources(run.id)
            run.status = "FAILED"
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Preflight failed: {pre.get('details', {}).get('message', 'Not configured')}")
            repo.update_sandbox_run(run)
            raise RuntimeError(f"Sandbox '{provider.name}' is not ready: {pre.get('status')}")

        staged_file = settings.DATA_DIR / "staging" / run.id / run.target_binary
        run.status = "PROVISIONING"
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Provisioning guest container/worker...")
        repo.update_sandbox_run(run)

        try:
            # Provision
            provider.provision(run, staged_file)

            # Execute
            run.status = "RUNNING"
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Isolated execution commenced.")
            repo.update_sandbox_run(run)

            provider.execute(run, timeout_seconds=run.timeout_seconds)

            # Record Chain of Custody
            self._record_custody(
                investigation_id=run.investigation_id,
                evidence_id=run.evidence_id,
                action="DYNAMIC_SANDBOX_LAUNCHED",
                details={"run_id": run_id, "provider": provider.name, "network_policy": run.network_policy}
            )
            return run
        except Exception as e:
            vm_resource_manager.release_worker_resources(run.id)
            worker_auth_manager.revoke_worker_session(run.id)
            run.status = "FAILED"
            run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Execution failed: {str(e)}")
            repo.update_sandbox_run(run)
            raise

    def finalize_analysis_session(self, run_id: str, duration: float = 60.0) -> DynamicReport:
        """Collects telemetry, runs behavioral analysis, generates report, and cleans up."""
        run = repo.get_sandbox_run(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found.")

        provider = sandbox_registry.get_provider(run.provider or run.environment_id)
        run.status = "COLLECTING"
        run.duration_seconds = duration
        run.completed_at_utc = datetime.utcnow().isoformat()
        repo.update_sandbox_run(run)

        # Collect raw telemetry bundle
        if provider:
            raw_telemetry = provider.collect_telemetry(run)
            telemetry_collector.ingest_bundle(run, raw_telemetry)
            # Restore & Cleanup guest
            provider.restore_and_cleanup(run)

        # Run behavioral heuristics
        behavior_analyzer.analyze_run_behavior(run)

        # Generate report
        report = dynamic_report_generator.generate_report(run)

        # Cleanup host staging
        sandbox_cleanup.cleanup_run_staging(run.id)
        vm_resource_manager.release_worker_resources(run.id)
        worker_auth_manager.revoke_worker_session(run.id)

        run.status = "COMPLETED"
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Dynamic run completed successfully.")
        repo.update_sandbox_run(run)

        # Record Chain-of-Custody Event
        self._record_custody(
            investigation_id=run.investigation_id,
            evidence_id=run.evidence_id,
            action="DYNAMIC_ANALYSIS_COMPLETED_AND_SEALED",
            details={"run_id": run_id, "report_id": report.id, "risk_score": run.risk_score}
        )

        return report

    def cancel_analysis_session(self, run_id: str) -> DynamicSandboxRun:
        """Forces immediate termination of a running sandbox session."""
        run = repo.get_sandbox_run(run_id)
        if not run:
            raise ValueError(f"Run {run_id} not found.")

        provider = sandbox_registry.get_provider(run.provider or run.environment_id)
        if provider:
            provider.terminate(run)
            provider.restore_and_cleanup(run)

        sandbox_cleanup.cleanup_run_staging(run.id)
        vm_resource_manager.release_worker_resources(run.id)
        worker_auth_manager.revoke_worker_session(run.id)
        run.status = "CANCELLED"
        run.sandbox_logs.append(f"[{datetime.utcnow().isoformat()}] Emergency termination invoked by examiner.")
        repo.update_sandbox_run(run)

        self._record_custody(
            investigation_id=run.investigation_id,
            evidence_id=run.evidence_id,
            action="DYNAMIC_ANALYSIS_EMERGENCY_CANCELLED",
            details={"run_id": run_id}
        )
        return run

    def _resolve_evidence_path(self, investigation_id: str, filename: str) -> Path:
        """Resolves the original evidence file path on the host."""
        candidates = [
            settings.DATA_DIR / investigation_id / "evidence" / filename,
            settings.DATA_DIR / investigation_id / filename,
            settings.DATA_DIR / "evidence" / filename,
            BASE_DIR / "analysis_workspace" / investigation_id / filename
        ]
        for c in candidates:
            if c.exists():
                return c
        # If not found, fallback to check evidence in data dir
        return candidates[0]

    def _record_custody(self, investigation_id: str, evidence_id: Optional[str], action: str, details: Dict[str, Any]):
        """Records a forensic custody event cleanly in the chain of custody."""
        try:
            from backend.app.core.models import ChainOfCustodyEvent
            import hashlib
            now = datetime.utcnow().isoformat()
            ev_id = f"CUSTODY-{uuid.uuid4().hex[:8]}"
            valid_evidence_id = None
            if evidence_id and repo.get_evidence_item(evidence_id):
                valid_evidence_id = evidence_id

            last = repo.get_last_chain_of_custody_event(investigation_id)
            prev_hash = last.event_hash if last else "0" * 64
            event_hash = hashlib.sha256(f"{ev_id}{investigation_id}{action}{now}{prev_hash}".encode()).hexdigest()
            event = ChainOfCustodyEvent(
                id=ev_id,
                investigation_id=investigation_id,
                evidence_id=valid_evidence_id,
                event_type=action,
                timestamp_utc=now,
                examiner="TraceX Dynamic Lab Supervisor",
                details=details,
                prev_event_hash=prev_hash,
                event_hash=event_hash
            )
            repo.add_chain_of_custody_event(event)
        except Exception as e:
            logger.warning(f"Could not record custody event: {e}")

sandbox_manager = DynamicSandboxManager()
