"""
OAuth 2.0 PKCE Authorization & Callback Routes
Universal Digital Forensics & Evidence Intelligence Platform v2.0.0

Implements RFC 7636 Authorization Code with PKCE flows for official providers (Google Gemini / Google Cloud).
Includes CSRF state verification, encrypted token storage, and automatic redirection.
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel
from fastapi import APIRouter, HTTPException, Depends, Request, Response, status
from fastapi.responses import RedirectResponse, HTMLResponse

from backend.app.core.user_auth import get_current_user, get_current_user_optional
from backend.app.core.oauth_manager import oauth_manager
from backend.app.core.credential_manager import credential_manager
from backend.app.core.auth_registry import AUTHENTICATION_REGISTRY

router = APIRouter(prefix="/api/oauth", tags=["Provider OAuth 2.0 PKCE"])


class ExchangeRequest(BaseModel):
    code: str
    state: str
    client_secret: Optional[str] = None


@router.get("/{provider_id}/authorize")
def start_oauth_flow(
    provider_id: str,
    redirect_uri: Optional[str] = None,
    client_id: Optional[str] = None,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Generates a high-entropy PKCE code challenge and cryptographically signed state token,
    returning the official provider authorization URL.
    """
    pid = provider_id.lower().strip()
    try:
        req = oauth_manager.create_authorization_request(
            user_id=user["id"],
            provider_name=pid,
            redirect_uri=redirect_uri,
            custom_client_id=client_id
        )
        return req
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to initiate OAuth flow: {str(e)}")


@router.get("/callback/{provider_id}")
@router.get("/{provider_id}/callback")
async def oauth_callback(
    provider_id: str,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    error_description: Optional[str] = None
):
    """
    Handles standard HTTP GET OAuth 2.0 redirect callbacks from provider authorization servers.
    Exchanges the authorization code for tokens using PKCE verifier and stores encrypted tokens.
    """
    pid = provider_id.lower().strip()
    if error:
        err_msg = error_description or error
        return HTMLResponse(
            content=f"""
            <html>
                <body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; text-align: center;">
                    <h2 style="color: #ef4444;">Authorization Denied</h2>
                    <p>The provider reported an authorization error: <code>{err_msg}</code></p>
                    <a href="/settings" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 6px;">Return to Workbench</a>
                </body>
            </html>
            """,
            status_code=400
        )

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing required 'code' or 'state' parameters in OAuth callback.")

    try:
        result = await oauth_manager.exchange_code(state=state, code=code)
        
        # Save encrypted tokens under the user who initiated the request
        credential_manager.save_oauth_tokens(
            provider_name=pid,
            access_token=result["access_token"],
            refresh_token=result.get("refresh_token"),
            expires_in=result.get("expires_in", 3600),
            scope=result.get("scope"),
            account_identifier=result.get("account_identifier"),
            user_id=result["user_id"]
        )

        return HTMLResponse(
            content=f"""
            <html>
                <body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; text-align: center;">
                    <h2 style="color: #10b981;">Successfully Connected!</h2>
                    <p>Your connection to <strong>{pid.title()}</strong> has been securely established via OAuth 2.0.</p>
                    <p style="color: #94a3b8;">Account: {result.get('account_identifier', 'Authorized Account')}</p>
                    <script>
                        setTimeout(function() {{
                            window.location.href = "/settings";
                        }}, 2000);
                    </script>
                    <a href="/settings" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 6px;">Return to Integrations</a>
                </body>
            </html>
            """
        )
    except Exception as e:
        return HTMLResponse(
            content=f"""
            <html>
                <body style="font-family: sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; text-align: center;">
                    <h2 style="color: #ef4444;">Token Exchange Failed</h2>
                    <p>{str(e)}</p>
                    <a href="/settings" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background: #3b82f6; color: white; text-decoration: none; border-radius: 6px;">Return to Workbench</a>
                </body>
            </html>
            """,
            status_code=400
        )


@router.post("/{provider_id}/exchange")
async def exchange_token_programmatic(
    provider_id: str,
    payload: ExchangeRequest,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Direct JSON token exchange endpoint for SPA client flows.
    """
    pid = provider_id.lower().strip()
    try:
        result = await oauth_manager.exchange_code(
            state=payload.state,
            code=payload.code,
            custom_client_secret=payload.client_secret
        )

        # Store encrypted credentials
        save_res = credential_manager.save_oauth_tokens(
            provider_name=pid,
            access_token=result["access_token"],
            refresh_token=result.get("refresh_token"),
            expires_in=result.get("expires_in", 3600),
            scope=result.get("scope"),
            account_identifier=result.get("account_identifier"),
            user_id=user["id"]
        )

        return {
            "status": "success",
            "provider": pid,
            "connected": True,
            "account_identifier": result.get("account_identifier"),
            "expires_at": save_res.get("expires_at")
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/{provider_id}/disconnect")
async def disconnect_oauth_provider(
    provider_id: str,
    user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Revokes the provider's active OAuth tokens upstream and deletes stored credentials.
    """
    pid = provider_id.lower().strip()
    creds = credential_manager.get_credential(pid, user_id=user["id"])
    if creds and creds.get("access_token"):
        await oauth_manager.revoke_token(pid, creds["access_token"])

    deleted = credential_manager.delete_credential(pid, user_id=user["id"])
    return {
        "status": "success",
        "provider": pid,
        "connected": False,
        "message": f"Successfully disconnected from {pid}."
    }

