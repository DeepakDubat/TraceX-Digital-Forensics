import logging
import uuid
from typing import Dict, Any, List, Optional
from backend.app.config import settings
from backend.app.core.models import OSINTIndicator, OSINTObservation
from backend.app.database.repository import repo
from backend.app.integrations.osint.providers.provider_registry import provider_registry

logger = logging.getLogger(__name__)

class OSINTService:
    """
    Unified OSINT Service & Provider Coordinator.
    Enriches indicators with caching, error isolation, modular provider failover,
    explicit status tracking, and strict passive operation (no active traffic to target systems).
    """

    def __init__(self, local_only_mode: Optional[bool] = None):
        self.local_only_mode = settings.LOCAL_ONLY_MODE if local_only_mode is None else local_only_mode

    def enrich_indicator(self, indicator: OSINTIndicator, force_refresh: bool = False) -> List[OSINTObservation]:
        """
        Runs authorized passive OSINT enrichment for a single indicator.
        Checks local cache first unless force_refresh is True.
        """
        observations: List[OSINTObservation] = []
        ind_type = indicator.indicator_type.lower()
        val = (indicator.normalized_value or indicator.value or "").strip()

        # STRICT SAFETY RULE: Sensitive secrets like bot tokens are NEVER enriched externally
        if indicator.is_sensitive_secret or ind_type == "telegram_bot_token":
            obs = OSINTObservation(
                id=f"OBS-SEC-{uuid.uuid4().hex[:8]}",
                investigation_id=indicator.investigation_id,
                indicator_id=indicator.id,
                provider="LocalSecretIsolationEngine",
                indicator_type=ind_type,
                indicator_value=indicator.masked_value or "[PROTECTED_SECRET]",
                status="SKIPPED_BY_PRIVACY_POLICY",
                normalized_data={
                    "safety_status": "CONTAINED_LOCALLY",
                    "reason": "Cryptographic tokens and secrets are protected by strict non-transmission policy."
                },
                limitations="Secret tokens are never sent to external APIs or adversary infrastructure."
            )
            try:
                repo.add_osint_observation(obs)
            except Exception as e:
                logger.warning(f"Could not persist secret observation to DB: {e}")
            return [obs]

        # Get all registered providers that support this indicator type
        providers = provider_registry.get_providers_for_indicator(ind_type)
        if not providers and ind_type in ("ipv4", "ipv6"):
            providers = provider_registry.get_providers_for_indicator("ip")
        elif not providers and ind_type in ("sha256", "md5", "sha1"):
            providers = provider_registry.get_providers_for_indicator("hash")
        elif not providers and ind_type in ("hostname",):
            providers = provider_registry.get_providers_for_indicator("domain")

        for p in providers:
            # Check cache
            if not force_refresh:
                cached = repo.get_cached_osint_observation(p.provider_name, ind_type, val)
                if cached:
                    cached_obs = OSINTObservation(
                        id=f"OBS-CACHE-{uuid.uuid4().hex[:8]}",
                        investigation_id=indicator.investigation_id,
                        indicator_id=indicator.id,
                        provider=p.provider_name,
                        indicator_type=ind_type,
                        indicator_value=val,
                        status=cached.get("status", "SUCCESS"),
                        normalized_data=cached.get("data", {}),
                        data_freshness="Cached",
                        limitations="Result loaded from local high-speed forensics cache."
                    )
                    observations.append(cached_obs)
                    continue

            # Query provider
            try:
                obs = p.query(
                    indicator_type=ind_type,
                    value=val,
                    investigation_id=indicator.investigation_id,
                    indicator_id=indicator.id,
                    local_only=self.local_only_mode
                )
                if obs:
                    if obs.status == "SUCCESS" and obs.normalized_data:
                        repo.set_cached_osint_observation(p.provider_name, ind_type, val, obs.status, obs.normalized_data)
                    observations.append(obs)
            except Exception as e:
                logger.error(f"Error querying provider {p.provider_name} for {val}: {e}", exc_info=True)
                err_obs = p.create_observation(
                    indicator.investigation_id,
                    indicator.id,
                    ind_type,
                    val,
                    "NETWORK_ERROR",
                    error_message=str(e)
                )
                observations.append(err_obs)

        # Persist all observations
        for obs in observations:
            try:
                repo.add_osint_observation(obs)
            except Exception as e:
                logger.error(f"Failed to persist observation {obs.id}: {e}")

        return observations

osint_service = OSINTService()
