from typing import Dict, Any, List, Optional
from backend.app.integrations.osint.providers.base_provider import BaseOSINTProvider
from backend.app.integrations.osint.providers.virustotal_adapter import VirusTotalProvider
from backend.app.integrations.osint.providers.alienvault_adapter import AlienVaultOTXProvider
from backend.app.integrations.osint.providers.abuseipdb_adapter import AbuseIPDBProvider
from backend.app.integrations.osint.providers.urlhaus_adapter import URLhausProvider
from backend.app.integrations.osint.providers.malwarebazaar_adapter import MalwareBazaarProvider
from backend.app.integrations.osint.providers.urlscan_adapter import URLScanProvider
from backend.app.integrations.osint.providers.dns_adapter import DNSProvider
from backend.app.integrations.osint.providers.rdap_adapter import RDAPProvider
from backend.app.integrations.osint.providers.network_intelligence_adapter import NetworkIntelligenceProvider
from backend.app.integrations.osint.providers.cert_transparency_adapter import CertTransparencyProvider
from backend.app.integrations.osint.providers.ipinfo_adapter import IPinfoProvider
from backend.app.integrations.osint.providers.shodan_adapter import ShodanProvider
from backend.app.integrations.osint.providers.censys_adapter import CensysProvider
from backend.app.integrations.osint.providers.greynoise_adapter import GreyNoiseProvider
from backend.app.integrations.osint.providers.misp_adapter import MISPProvider
from backend.app.integrations.osint.providers.passivedns_adapter import PassiveDNSProvider

class ProviderRegistry:
    """Central registry and dispatch coordinator for all modular OSINT provider adapters."""

    def __init__(self):
        self._providers: Dict[str, BaseOSINTProvider] = {
            "virustotal": VirusTotalProvider(),
            "alienvault_otx": AlienVaultOTXProvider(),
            "abuseipdb": AbuseIPDBProvider(),
            "urlhaus": URLhausProvider(),
            "malwarebazaar": MalwareBazaarProvider(),
            "urlscan": URLScanProvider(),
            "dns": DNSProvider(),
            "rdap": RDAPProvider(),
            "network_info": NetworkIntelligenceProvider(),
            "cert_transparency": CertTransparencyProvider(),
            "ipinfo": IPinfoProvider(),
            "shodan": ShodanProvider(),
            "censys": CensysProvider(),
            "greynoise": GreyNoiseProvider(),
            "misp": MISPProvider(),
            "passive_dns": PassiveDNSProvider(),
        }

    def get_provider(self, provider_id: str) -> Optional[BaseOSINTProvider]:
        pid = provider_id.lower().strip()
        if pid == "network_intelligence":
            pid = "network_info"
        elif pid == "passivedns":
            pid = "passive_dns"
        return self._providers.get(pid)

    def list_providers(self) -> List[BaseOSINTProvider]:
        return list(self._providers.values())

    def get_providers_for_indicator(self, indicator_type: str) -> List[BaseOSINTProvider]:
        norm_type = indicator_type.lower()
        matched = []
        for p in self._providers.values():
            if norm_type in [t.lower() for t in p.supported_types]:
                matched.append(p)
        return matched

    def list_providers_metadata(self) -> List[Dict[str, Any]]:
        results = []
        for p in self._providers.values():
            results.append({
                "provider_id": p.provider_id,
                "provider_name": p.provider_name,
                "supported_types": p.supported_types,
                "requires_credentials": p.requires_credentials,
                "is_configured": p.is_configured(),
                "endpoint": p.endpoint_display,
                "rate_limits": p.rate_limits,
                "known_limitations": p.known_limitations,
                "privacy_implications": p.privacy_implications
            })
        return results

    def test_provider(self, provider_id: str) -> Dict[str, Any]:
        provider = self.get_provider(provider_id)
        if not provider:
            return {"status": "Unknown provider", "connected": False, "provider": provider_id}
        return provider.test_connection()

provider_registry = ProviderRegistry()
