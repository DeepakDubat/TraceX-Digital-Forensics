import socket
import ssl
import time
import uuid
import ipaddress
import httpx
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse

from backend.app.config import settings
from backend.app.core.models import AuthorizedNetworkScope, ActiveValidationResult
from backend.app.database.repository import repo

# SSRF Blocked Networks (Private, Loopback, Link-Local, Cloud Metadata, Documentation, Multicast, Broadcast)
BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"), # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("169.254.0.0/16"), # Link-local / Cloud metadata (AWS/Azure/GCP 169.254.169.254)
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.0.2.0/24"), # Documentation
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"), # Benchmark
    ipaddress.ip_network("198.51.100.0/24"), # Documentation
    ipaddress.ip_network("203.0.113.0/24"), # Documentation
    ipaddress.ip_network("224.0.0.0/4"), # Multicast
    ipaddress.ip_network("240.0.0.0/4"), # Reserved
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 blocked ranges
    ipaddress.ip_network("::/128"),
    ipaddress.ip_network("::1/128"), # Loopback
    ipaddress.ip_network("::ffff:0:0/96"), # IPv4-mapped
    ipaddress.ip_network("100::/64"),
    ipaddress.ip_network("2001:db8::/32"), # Documentation
    ipaddress.ip_network("fc00::/7"), # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"), # Link-local
    ipaddress.ip_network("ff00::/8"), # Multicast
]

# Emergency Global Kill Switch
_EXTERNAL_REQUEST_KILL_SWITCH = False

def set_external_request_kill_switch(active: bool):
    """Engages or disengages the external request kill switch."""
    global _EXTERNAL_REQUEST_KILL_SWITCH
    _EXTERNAL_REQUEST_KILL_SWITCH = active

def is_kill_switch_active() -> bool:
    return _EXTERNAL_REQUEST_KILL_SWITCH

class ActiveNetworkValidator:
    """
    Controlled, low-impact Authorized Network Validation Engine.
    Strictly verifies authorization scope, expiration, operator confirmation,
    request budget, and SSRF/DNS-rebinding protections.
    """

    def is_safe_ip(self, ip_str: str) -> Tuple[bool, str]:
        """Validates that an IP address is a globally routable public address and not private/loopback/cloud metadata."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
            for net in BLOCKED_NETWORKS:
                if ip_obj in net:
                    return False, f"Address '{ip_str}' belongs to blocked private/reserved range {net} (SSRF protection)."
            return True, "Safe public IP"
        except ValueError:
            return False, f"Invalid IP address format: '{ip_str}'."

    def validate_scope(
        self,
        scope: AuthorizedNetworkScope,
        target: str,
        test_type: str,
        port: Optional[int] = None
    ) -> Tuple[bool, str]:
        """
        Validates target authorization against an active scope record:
        1. Kill switch check
        2. Local-only mode check
        3. Expiration check
        4. Revocation check
        5. Operator confirmation check
        6. Budget check
        7. Test type allowlist check
        8. Target allowlist check
        9. Port allowlist check
        """
        if _EXTERNAL_REQUEST_KILL_SWITCH:
            return False, "BLOCKED: Emergency external-request kill switch is active."

        if settings.LOCAL_ONLY_MODE:
            return False, "BLOCKED: Local-Only mode is enabled. All external network validation is strictly blocked."

        if scope.is_revoked:
            return False, "BLOCKED: Investigation authorization scope has been revoked by operator."

        if not scope.operator_confirmed:
            return False, "BLOCKED: Scope requires explicit operator confirmation before execution."

        # Check expiration
        try:
            exp_dt = datetime.fromisoformat(scope.expires_at_utc.replace("Z", "+00:00"))
            now_dt = datetime.utcnow()
            if hasattr(exp_dt, "tzinfo") and exp_dt.tzinfo is not None:
                from datetime import timezone
                now_dt = datetime.now(timezone.utc)
            if now_dt > exp_dt:
                return False, f"BLOCKED: Authorization scope expired at {scope.expires_at_utc}."
        except Exception as e:
            return False, f"BLOCKED: Scope expiration date format error: {e}"

        # Check budget
        if scope.requests_used >= scope.request_budget:
            return False, f"BLOCKED: Scope request budget exhausted ({scope.requests_used}/{scope.request_budget})."

        # Check test type
        if test_type.upper() not in [t.upper() for t in scope.allowed_test_types]:
            return False, f"BLOCKED: Test type '{test_type}' is not authorized in scope. Allowed: {scope.allowed_test_types}"

        # Normalize target
        clean_target = target.strip().lower()
        if "://" in clean_target:
            try:
                parsed = urlparse(clean_target)
                clean_target = (parsed.hostname or "").lower()
            except Exception:
                pass

        # Check target allowlist
        scope_targets = [t.strip().lower() for t in scope.authorized_targets]
        target_matched = False
        for st in scope_targets:
            if clean_target == st or clean_target.endswith(f".{st}"):
                target_matched = True
                break

        if not target_matched:
            return False, f"BLOCKED: Target '{target}' is not in the operator-approved scope allowlist: {scope_targets}"

        # Check port if provided
        if port is not None and scope.allowed_ports:
            if port not in scope.allowed_ports:
                return False, f"BLOCKED: Port {port} is not in approved ports list: {scope.allowed_ports}"

        return True, "Authorized"

    def execute_dns_lookup(
        self,
        scope_id: str,
        investigation_id: str,
        target_domain: str
    ) -> ActiveValidationResult:
        """Low-impact authorized DNS lookup."""
        scope = repo.get_authorized_scope(scope_id)
        if not scope:
            return self._rejected_result(scope_id, investigation_id, target_domain, "DNS", "Scope not found.")

        ok, msg = self.validate_scope(scope, target_domain, "DNS")
        if not ok:
            return self._rejected_result(scope_id, investigation_id, target_domain, "DNS", msg)

        repo.increment_scope_requests(scope_id)
        clean_domain = target_domain.strip().lower()

        t0 = time.time()
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(clean_domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                ip = item[4][0]
                if ip not in resolved_ips:
                    resolved_ips.append(ip)
            timing_ms = (time.time() - t0) * 1000.0

            # SSRF / Private IP validation on resolved IPs
            for ip in resolved_ips:
                safe, reason = self.is_safe_ip(ip)
                if not safe:
                    return ActiveValidationResult(
                        id=f"VAL-DNS-{uuid.uuid4().hex[:8]}",
                        scope_id=scope_id,
                        investigation_id=investigation_id,
                        target=clean_domain,
                        test_type="DNS",
                        status="PRIVATE_IP_BLOCKED",
                        resolved_ips=resolved_ips,
                        timing_ms=timing_ms,
                        diagnostic_message=f"DNS-Rebinding / SSRF safeguard triggered: {reason}",
                        operator_confirmation_ref=scope.operator_name
                    )

            status = "SUCCESS" if resolved_ips else "NO_DATA"
            res = ActiveValidationResult(
                id=f"VAL-DNS-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=clean_domain,
                test_type="DNS",
                status=status,
                resolved_ips=resolved_ips,
                timing_ms=timing_ms,
                diagnostic_message=f"Resolved {len(resolved_ips)} addresses in {timing_ms:.2f}ms.",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res

        except socket.gaierror as e:
            timing_ms = (time.time() - t0) * 1000.0
            res = ActiveValidationResult(
                id=f"VAL-DNS-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=clean_domain,
                test_type="DNS",
                status="FAILED",
                timing_ms=timing_ms,
                diagnostic_message=f"DNS resolution failed: {e}",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res

    def execute_tcp_connect(
        self,
        scope_id: str,
        investigation_id: str,
        target: str,
        port: int
    ) -> ActiveValidationResult:
        """Low-impact authorized TCP handshake test (no payload sent)."""
        scope = repo.get_authorized_scope(scope_id)
        if not scope:
            return self._rejected_result(scope_id, investigation_id, target, "TCP_CONNECT", "Scope not found.", port)

        ok, msg = self.validate_scope(scope, target, "TCP_CONNECT", port=port)
        if not ok:
            return self._rejected_result(scope_id, investigation_id, target, "TCP_CONNECT", msg, port)

        clean_target = target.strip()
        # Resolve address first to guarantee SSRF protection
        try:
            addr = socket.gethostbyname(clean_target)
        except Exception as e:
            return self._failed_result(scope_id, investigation_id, target, "TCP_CONNECT", f"Could not resolve host: {e}", port)

        safe, reason = self.is_safe_ip(addr)
        if not safe:
            return ActiveValidationResult(
                id=f"VAL-TCP-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target,
                test_type="TCP_CONNECT",
                status="PRIVATE_IP_BLOCKED",
                resolved_ips=[addr],
                port=port,
                diagnostic_message=reason,
                operator_confirmation_ref=scope.operator_name
            )

        repo.increment_scope_requests(scope_id)
        t0 = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(4.0)

        try:
            sock.connect((addr, port))
            timing_ms = (time.time() - t0) * 1000.0
            sock.close()
            res = ActiveValidationResult(
                id=f"VAL-TCP-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target,
                test_type="TCP_CONNECT",
                status="SUCCESS",
                resolved_ips=[addr],
                port=port,
                timing_ms=timing_ms,
                diagnostic_message=f"TCP 3-way handshake established successfully in {timing_ms:.2f}ms.",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res
        except socket.timeout:
            timing_ms = (time.time() - t0) * 1000.0
            res = ActiveValidationResult(
                id=f"VAL-TCP-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target,
                test_type="TCP_CONNECT",
                status="TIMEOUT",
                resolved_ips=[addr],
                port=port,
                timing_ms=timing_ms,
                diagnostic_message="Connection attempt timed out after 4.0s.",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res
        except Exception as e:
            timing_ms = (time.time() - t0) * 1000.0
            res = ActiveValidationResult(
                id=f"VAL-TCP-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target,
                test_type="TCP_CONNECT",
                status="FAILED",
                resolved_ips=[addr],
                port=port,
                timing_ms=timing_ms,
                diagnostic_message=f"TCP connection refused or unreachable: {e}",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res
        finally:
            sock.close()

    def execute_tls_inspection(
        self,
        scope_id: str,
        investigation_id: str,
        target: str,
        port: int = 443
    ) -> ActiveValidationResult:
        """Low-impact TLS handshake & certificate metadata inspection (does not follow redirects or send HTTP payloads)."""
        scope = repo.get_authorized_scope(scope_id)
        if not scope:
            return self._rejected_result(scope_id, investigation_id, target, "TLS_INSPECT", "Scope not found.", port)

        ok, msg = self.validate_scope(scope, target, "TLS_INSPECT", port=port)
        if not ok:
            return self._rejected_result(scope_id, investigation_id, target, "TLS_INSPECT", msg, port)

        clean_target = target.strip()
        try:
            addr = socket.gethostbyname(clean_target)
        except Exception as e:
            return self._failed_result(scope_id, investigation_id, target, "TLS_INSPECT", f"Could not resolve host: {e}", port)

        safe, reason = self.is_safe_ip(addr)
        if not safe:
            return ActiveValidationResult(
                id=f"VAL-TLS-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target,
                test_type="TLS_INSPECT",
                status="PRIVATE_IP_BLOCKED",
                resolved_ips=[addr],
                port=port,
                diagnostic_message=reason,
                operator_confirmation_ref=scope.operator_name
            )

        repo.increment_scope_requests(scope_id)
        t0 = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE # Inspect raw cert without throwing on self-signed

        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(4.0)
            ssl_sock = ctx.wrap_socket(raw_sock, server_hostname=clean_target)
            ssl_sock.connect((addr, port))
            timing_ms = (time.time() - t0) * 1000.0

            cert = ssl_sock.getpeercert(binary_form=False) or {}
            der_cert = ssl_sock.getpeercert(binary_form=True)

            import hashlib
            sha256_fp = hashlib.sha256(der_cert).hexdigest() if der_cert else None
            sha1_fp = hashlib.sha1(der_cert).hexdigest() if der_cert else None

            # Parse subject & issuer
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            san = [entry[1] for entry in cert.get("subjectAltName", [])]

            tls_info = {
                "version": ssl_sock.version(),
                "cipher": ssl_sock.cipher(),
                "subject": subject,
                "issuer": issuer,
                "san": san[:15],
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "sha256_fingerprint": sha256_fp,
                "sha1_fingerprint": sha1_fp,
                "is_self_signed": subject == issuer and bool(subject)
            }
            ssl_sock.close()

            res = ActiveValidationResult(
                id=f"VAL-TLS-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target,
                test_type="TLS_INSPECT",
                status="SUCCESS",
                resolved_ips=[addr],
                port=port,
                timing_ms=timing_ms,
                tls_cert_info=tls_info,
                diagnostic_message=f"TLS handshake established with {ssl_sock.version()}. Subject: {subject.get('commonName', 'Unknown')}",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res

        except Exception as e:
            timing_ms = (time.time() - t0) * 1000.0
            res = ActiveValidationResult(
                id=f"VAL-TLS-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target,
                test_type="TLS_INSPECT",
                status="FAILED",
                resolved_ips=[addr],
                port=port,
                timing_ms=timing_ms,
                diagnostic_message=f"TLS handshake failed: {e}",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res

    def execute_https_head(
        self,
        scope_id: str,
        investigation_id: str,
        target_url: str
    ) -> ActiveValidationResult:
        """
        Executes a safe, non-crawling HTTP/HTTPS HEAD request.
        Does NOT follow redirects automatically to prevent SSRF bypass.
        Does NOT download response body.
        """
        scope = repo.get_authorized_scope(scope_id)
        if not scope:
            return self._rejected_result(scope_id, investigation_id, target_url, "HTTPS_HEAD", "Scope not found.")

        ok, msg = self.validate_scope(scope, target_url, "HTTPS_HEAD")
        if not ok:
            return self._rejected_result(scope_id, investigation_id, target_url, "HTTPS_HEAD", msg)

        parsed = urlparse(target_url)
        hostname = (parsed.hostname or target_url).strip()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        try:
            addr = socket.gethostbyname(hostname)
        except Exception as e:
            return self._failed_result(scope_id, investigation_id, target_url, "HTTPS_HEAD", f"Could not resolve host: {e}", port)

        safe, reason = self.is_safe_ip(addr)
        if not safe:
            return ActiveValidationResult(
                id=f"VAL-HEAD-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target_url,
                test_type="HTTPS_HEAD",
                status="PRIVATE_IP_BLOCKED",
                resolved_ips=[addr],
                port=port,
                diagnostic_message=reason,
                operator_confirmation_ref=scope.operator_name
            )

        repo.increment_scope_requests(scope_id)
        t0 = time.time()

        try:
            # Strict no-redirect client
            with httpx.Client(timeout=4.0, follow_redirects=False, verify=False) as client:
                resp = client.head(target_url)
                timing_ms = (time.time() - t0) * 1000.0

                # Select safe diagnostic response headers
                selected_headers = {}
                for h in ("server", "date", "content-type", "content-length", "location", "strict-transport-security"):
                    if h in resp.headers:
                        selected_headers[h] = resp.headers[h]

                res = ActiveValidationResult(
                    id=f"VAL-HEAD-{uuid.uuid4().hex[:8]}",
                    scope_id=scope_id,
                    investigation_id=investigation_id,
                    target=target_url,
                    test_type="HTTPS_HEAD",
                    status="SUCCESS",
                    resolved_ips=[addr],
                    port=port,
                    timing_ms=timing_ms,
                    http_status=resp.status_code,
                    http_headers=selected_headers,
                    diagnostic_message=f"HTTP HEAD returned {resp.status_code} in {timing_ms:.2f}ms. Redirects deliberately un-followed.",
                    operator_confirmation_ref=scope.operator_name
                )
                repo.add_active_validation_result(res)
                return res

        except Exception as e:
            timing_ms = (time.time() - t0) * 1000.0
            res = ActiveValidationResult(
                id=f"VAL-HEAD-{uuid.uuid4().hex[:8]}",
                scope_id=scope_id,
                investigation_id=investigation_id,
                target=target_url,
                test_type="HTTPS_HEAD",
                status="FAILED",
                resolved_ips=[addr],
                port=port,
                timing_ms=timing_ms,
                diagnostic_message=f"HTTP HEAD request error: {e}",
                operator_confirmation_ref=scope.operator_name
            )
            repo.add_active_validation_result(res)
            return res

    def _rejected_result(
        self,
        scope_id: str,
        inv_id: str,
        target: str,
        test_type: str,
        msg: str,
        port: Optional[int] = None
    ) -> ActiveValidationResult:
        status = "CANCELLED" if is_kill_switch_active() else "SCOPE_REJECTED"
        res = ActiveValidationResult(
            id=f"VAL-REJ-{uuid.uuid4().hex[:8]}",
            scope_id=scope_id,
            investigation_id=inv_id,
            target=target,
            test_type=test_type,
            status=status,
            port=port,
            diagnostic_message=msg
        )
        try:
            repo.add_active_validation_result(res)
        except Exception:
            pass
        return res

    def _failed_result(
        self,
        scope_id: str,
        inv_id: str,
        target: str,
        test_type: str,
        msg: str,
        port: Optional[int] = None
    ) -> ActiveValidationResult:
        res = ActiveValidationResult(
            id=f"VAL-FAIL-{uuid.uuid4().hex[:8]}",
            scope_id=scope_id,
            investigation_id=inv_id,
            target=target,
            test_type=test_type,
            status="FAILED",
            port=port,
            diagnostic_message=msg
        )
        try:
            repo.add_active_validation_result(res)
        except Exception:
            pass
        return res

active_validator = ActiveNetworkValidator()
