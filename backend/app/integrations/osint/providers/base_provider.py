import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional
from backend.app.core.models import OSINTObservation

# Standard Explicit Result Statuses
STATUS_SUCCESS = "SUCCESS"
STATUS_NO_DATA = "NO_DATA"
STATUS_NOT_FOUND = "NOT_FOUND"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_UNAUTHORIZED = "UNAUTHORIZED"
STATUS_FORBIDDEN = "FORBIDDEN"
STATUS_TIMEOUT = "TIMEOUT"
STATUS_NETWORK_ERROR = "NETWORK_ERROR"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_SKIPPED_LOCAL_ONLY = "SKIPPED_LOCAL_ONLY"
STATUS_SKIPPED_PRIVACY_POLICY = "SKIPPED_PRIVACY_POLICY"
STATUS_INVALID_INDICATOR = "INVALID_INDICATOR"
STATUS_PARTIAL = "PARTIAL"

class ProviderStatus:
    SUCCESS = STATUS_SUCCESS
    NO_DATA = STATUS_NO_DATA
    NOT_FOUND = STATUS_NOT_FOUND
    RATE_LIMITED = STATUS_RATE_LIMITED
    UNAUTHORIZED = STATUS_UNAUTHORIZED
    FORBIDDEN = STATUS_FORBIDDEN
    TIMEOUT = STATUS_TIMEOUT
    NETWORK_ERROR = STATUS_NETWORK_ERROR
    UNAVAILABLE = STATUS_UNAVAILABLE
    SKIPPED_LOCAL_ONLY = STATUS_SKIPPED_LOCAL_ONLY
    SKIPPED_PRIVACY_POLICY = STATUS_SKIPPED_PRIVACY_POLICY
    INVALID_INDICATOR = STATUS_INVALID_INDICATOR
    PARTIAL = STATUS_PARTIAL


class BaseOSINTProvider(ABC):
    """
    Abstract Base Class for all OSINT and Threat Intelligence provider adapters.
    Enforces explicit status codes, audit timestamps, privacy warnings,
    and rate limit / credential metadata.
    """

    provider_id: str
    provider_name: str
    supported_types: List[str] # e.g. ["ip", "domain", "hash", "url"]
    requires_credentials: bool
    endpoint_display: str
    rate_limits: str
    known_limitations: str
    privacy_implications: str

    @abstractmethod
    def is_configured(self) -> bool:
        """Checks if required API keys / credentials or endpoints are configured."""
        pass

    @abstractmethod
    def query(
        self,
        indicator_type: str,
        value: str,
        investigation_id: str,
        indicator_id: str,
        local_only: bool = False,
        timeout: float = 8.0
    ) -> OSINTObservation:
        """Executes passive OSINT lookup for the given indicator."""
        pass

    @abstractmethod
    def test_connection(self) -> Dict[str, Any]:
        """Performs a safe read-only credential/connectivity check without transmitting evidence."""
        pass

    def get_byok_credential(self) -> Dict[str, Any]:
        """Fetches decrypted credentials from centralized CredentialManager."""
        try:
            from backend.app.core.credential_manager import credential_manager
            return credential_manager.get_credential(self.provider_id) or {}
        except Exception:
            return {}

    def create_observation(
        self,
        investigation_id: str,
        indicator_id: str,
        indicator_type: str,
        indicator_value: str,
        status: str,
        normalized_data: Optional[Dict[str, Any]] = None,
        permalink: Optional[str] = None,
        provider_timestamp_utc: Optional[str] = None,
        data_freshness: str = "Live",
        error_message: Optional[str] = None,
        limitations: Optional[str] = None
    ) -> OSINTObservation:
        """Helper to create standardized, source-attributed OSINTObservation records."""
        return OSINTObservation(
            id=f"OBS-{self.provider_id[:4].upper()}-{uuid.uuid4().hex[:8]}",
            investigation_id=investigation_id,
            indicator_id=indicator_id,
            provider=self.provider_name,
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            query_timestamp_utc=datetime.utcnow().isoformat(),
            provider_timestamp_utc=provider_timestamp_utc,
            status=status,
            normalized_data=normalized_data or {},
            permalink=permalink,
            data_freshness=data_freshness,
            error_message=error_message,
            limitations=limitations or self.known_limitations
        )
