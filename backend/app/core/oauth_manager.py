"""
OAuth 2.0 Authorization Code + PKCE Manager
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Guarantees:
- RFC 7636 compliant Proof Key for Code Exchange (S256) implementation.
- Official Google Cloud / Gemini OAuth 2.0 connector with offline access for refresh tokens.
- Strict state parameter verification protecting against CSRF & replay attacks.
- Explicit rejection of non-OAuth providers (prevents fake OAuth or password harvesting).
- Ephemeral state memory cache with bounded 10-minute lifetime.
"""

import os
import time
import json
import secrets
import hashlib
import base64
import logging
from typing import Dict, Any, Tuple, Optional
import httpx

from backend.app.core.auth_registry import AUTHENTICATION_REGISTRY
from backend.app.core.api_error_classifier import classify_api_error, sanitize_error_text

logger = logging.getLogger("uvicorn.error")

# Default Client Configuration
DEFAULT_GOOGLE_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
DEFAULT_GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
STATE_EXPIRY_SECONDS = 600  # 10 minutes


class OAuthManager:
    """Manages PKCE flows, authorization URLs, token exchange, and refreshes."""

    def __init__(self):
        # In-memory transient state cache: state -> {user_id, provider, verifier, redirect_uri, expires_at}
        self._states: Dict[str, Dict[str, Any]] = {}

    def _cleanup_expired_states(self):
        now = time.time()
        expired = [s for s, data in self._states.items() if data["expires_at"] < now]
        for s in expired:
            self._states.pop(s, None)

    def generate_pkce(self) -> Tuple[str, str]:
        """
        Generates (code_verifier, code_challenge) using SHA-256 (S256).
        RFC 7636 Section 4.1 & 4.2.
        """
        # Verifier: 43-128 unreserved characters
        verifier = secrets.token_urlsafe(64)[:96]
        # Challenge: BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) without padding
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return verifier, challenge

    def create_authorization_request(
        self,
        user_id: str,
        provider_name: str,
        redirect_uri: Optional[str] = None,
        custom_client_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Constructs an OAuth 2.0 PKCE authorization URL for supported providers.
        Rejects providers without official user-delegated OAuth support.
        """
        self._cleanup_expired_states()
        provider_id = provider_name.lower().strip()
        reg = AUTHENTICATION_REGISTRY.get(provider_id)
        if not reg:
            raise ValueError(f"Unknown provider: '{provider_id}'")

        oauth_cfg = reg.get("oauth2_config", {})
        if not oauth_cfg.get("enabled"):
            note = oauth_cfg.get("note", f"{reg.get('name', provider_id)} does not offer user-delegated OAuth2.")
            raise ValueError(f"OAuth is not supported for {reg.get('name', provider_id)}. {note} Use API key configuration.")

        client_id = custom_client_id or os.getenv(f"{provider_id.upper()}_OAUTH_CLIENT_ID") or DEFAULT_GOOGLE_CLIENT_ID
        if not client_id:
            # Provide instructional guidance for Google Cloud Project configuration
            raise ValueError(
                f"Missing OAuth Client ID for {reg.get('name', provider_id)}. "
                f"Please set GOOGLE_OAUTH_CLIENT_ID or provide client_id in configuration."
            )

        verifier, challenge = self.generate_pkce()
        state = secrets.token_urlsafe(32)

        # Default callback URL
        effective_redirect = redirect_uri or oauth_cfg.get("redirect_uri", "/api/oauth/callback/gemini")
        if effective_redirect.startswith("/"):
            # Normalize to localhost or host URL
            effective_redirect = f"http://localhost:8000{effective_redirect}"

        # Record state for callback validation
        self._states[state] = {
            "user_id": user_id,
            "provider": provider_id,
            "code_verifier": verifier,
            "redirect_uri": effective_redirect,
            "client_id": client_id,
            "expires_at": time.time() + STATE_EXPIRY_SECONDS
        }

        # Build Authorization URL
        scopes = " ".join(oauth_cfg.get("scopes", []))
        auth_endpoint = oauth_cfg["authorization_endpoint"]

        params = {
            "client_id": client_id,
            "redirect_uri": effective_redirect,
            "response_type": "code",
            "scope": scopes,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "prompt": "consent"
        }

        import urllib.parse
        query_string = urllib.parse.urlencode(params)
        auth_url = f"{auth_endpoint}?{query_string}"

        return {
            "authorization_url": auth_url,
            "state": state,
            "expires_in": STATE_EXPIRY_SECONDS,
            "provider": provider_id,
            "scopes": oauth_cfg.get("scopes", [])
        }

    async def exchange_code(
        self,
        state: str,
        code: str,
        custom_client_secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Exchanges authorization code and PKCE verifier for OAuth access and refresh tokens.
        """
        self._cleanup_expired_states()
        state_data = self._states.pop(state, None)
        if not state_data:
            raise ValueError("Invalid or expired OAuth state. Please re-initiate authorization.")

        now = time.time()
        if state_data["expires_at"] < now:
            raise ValueError("OAuth authorization session expired. Please try again.")

        user_id = state_data["user_id"]
        provider_id = state_data["provider"]
        verifier = state_data["code_verifier"]
        redirect_uri = state_data["redirect_uri"]
        client_id = state_data["client_id"]

        reg = AUTHENTICATION_REGISTRY.get(provider_id, {})
        oauth_cfg = reg.get("oauth2_config", {})
        token_endpoint = oauth_cfg.get("token_endpoint")
        if not token_endpoint:
            raise ValueError(f"No token endpoint defined for {provider_id}")

        client_secret = (
            custom_client_secret
            or os.getenv(f"{provider_id.upper()}_OAUTH_CLIENT_SECRET")
            or DEFAULT_GOOGLE_CLIENT_SECRET
        )

        payload = {
            "client_id": client_id,
            "code": code,
            "code_verifier": verifier,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri
        }
        if client_secret:
            payload["client_secret"] = client_secret

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(token_endpoint, data=payload)
                if resp.status_code != 200:
                    classified = classify_api_error(provider_id, resp.status_code, resp.text)
                    logger.error(f"OAuth token exchange failed for {provider_id}: {classified['message']}")
                    raise ValueError(f"OAuth exchange failed: {classified['message']} ({classified['actionable_hint']})")

                token_data = resp.json()
        except httpx.RequestError as exc:
            classified = classify_api_error(provider_id, None, None, exc)
            raise ValueError(f"OAuth token endpoint network error: {classified['message']}")

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")
        expires_in = token_data.get("expires_in", 3600)
        scope = token_data.get("scope", "")

        # Try to resolve account identity
        account_identifier = None
        id_token = token_data.get("id_token")
        if id_token:
            try:
                # Decode unverified JWT payload for email display
                parts = id_token.split(".")
                if len(parts) >= 2:
                    padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    payload_json = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
                    account_identifier = payload_json.get("email")
            except Exception:
                pass

        return {
            "user_id": user_id,
            "provider": provider_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "expires_in": expires_in,
            "scope": scope,
            "account_identifier": account_identifier
        }

    async def refresh_access_token(
        self,
        provider_name: str,
        refresh_token: str,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Uses refresh token to obtain a fresh access token.
        """
        provider_id = provider_name.lower().strip()
        reg = AUTHENTICATION_REGISTRY.get(provider_id, {})
        oauth_cfg = reg.get("oauth2_config", {})
        token_endpoint = oauth_cfg.get("token_endpoint")
        if not token_endpoint:
            raise ValueError(f"No token endpoint for {provider_id}")

        c_id = client_id or os.getenv(f"{provider_id.upper()}_OAUTH_CLIENT_ID") or DEFAULT_GOOGLE_CLIENT_ID
        c_sec = client_secret or os.getenv(f"{provider_id.upper()}_OAUTH_CLIENT_SECRET") or DEFAULT_GOOGLE_CLIENT_SECRET

        payload = {
            "client_id": c_id,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token"
        }
        if c_sec:
            payload["client_secret"] = c_sec

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(token_endpoint, data=payload)
                if resp.status_code != 200:
                    classified = classify_api_error(provider_id, resp.status_code, resp.text)
                    raise ValueError(f"Token refresh failed: {classified['message']}")
                data = resp.json()
                return {
                    "access_token": data.get("access_token"),
                    "expires_in": data.get("expires_in", 3600),
                    "scope": data.get("scope", "")
                }
        except httpx.RequestError as exc:
            classified = classify_api_error(provider_id, None, None, exc)
            raise ValueError(f"Token refresh network error: {classified['message']}")

    async def revoke_token(
        self,
        provider_name: str,
        token: str
    ) -> bool:
        """
        Revokes an OAuth access or refresh token with the upstream provider.
        """
        provider_id = provider_name.lower().strip()
        reg = AUTHENTICATION_REGISTRY.get(provider_id, {})
        oauth_cfg = reg.get("oauth2_config", {})
        revocation_endpoint = oauth_cfg.get("revocation_endpoint")
        if not revocation_endpoint or not token:
            return False

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(revocation_endpoint, params={"token": token})
                return resp.status_code in (200, 204)
        except Exception as e:
            logger.warning(f"OAuth token revocation failed for {provider_id}: {e}")
            return False


oauth_manager = OAuthManager()
