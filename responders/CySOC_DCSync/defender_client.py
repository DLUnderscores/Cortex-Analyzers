#!/usr/bin/env python3
# encoding: utf-8
"""Minimal Microsoft Graph + Defender for Endpoint client for containment actions.

One Azure app registration (tenant_id/client_id/client_secret) is used to mint a
separate OAuth2 client-credentials token per API scope, the same pattern already
used by analyzers/MicrosoftDefender/MicrosoftDefender.py.
"""
import requests

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
MDE_BASE_URL = "https://api.securitycenter.microsoft.com/api"
MDE_SCOPE = "https://api.securitycenter.microsoft.com/.default"
TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"


class DefenderActionError(Exception):
    """Raised when a Graph/MDE containment action cannot be completed."""


class DefenderClient:
    def __init__(self, tenant_id: str, client_id: str, client_secret: str, http=requests):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.http = http
        self._tokens = {}

    def _token(self, scope: str) -> str:
        if scope not in self._tokens:
            resp = self.http.post(
                TOKEN_URL.format(tenant_id=self.tenant_id),
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": scope,
                },
                timeout=30,
            )
            if not (200 <= resp.status_code < 300):
                raise DefenderActionError(
                    f"OAuth2 token request failed for {scope}: HTTP {resp.status_code} — {resp.text}"
                )
            token = resp.json().get("access_token")
            if not token:
                raise DefenderActionError(f"OAuth2 response contained no access_token for {scope}")
            self._tokens[scope] = token
        return self._tokens[scope]

    def disable_user(self, user_id: str) -> None:
        resp = self.http.patch(
            f"{GRAPH_BASE_URL}/users/{user_id}",
            headers={"Authorization": f"Bearer {self._token(GRAPH_SCOPE)}", "Content-Type": "application/json"},
            json={"accountEnabled": False},
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise DefenderActionError(f"Failed to disable user {user_id}: HTTP {resp.status_code} — {resp.text}")

    def force_password_reset_entra(self, user_id: str) -> None:
        """Force a password change at next sign-in for a cloud-only Entra user (Graph passwordProfile).

        Ineffective for hybrid identities whose password is mastered on-prem — use
        force_password_reset_ad for those (see the identityAccounts invokeAction endpoint).
        """
        resp = self.http.patch(
            f"{GRAPH_BASE_URL}/users/{user_id}",
            headers={"Authorization": f"Bearer {self._token(GRAPH_SCOPE)}", "Content-Type": "application/json"},
            json={"passwordProfile": {"forceChangePasswordNextSignIn": True}},
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise DefenderActionError(
                f"Failed to force password reset for user {user_id}: HTTP {resp.status_code} — {resp.text}"
            )

    def force_password_reset_ad(self, identity_account_id: str, account_id: str) -> None:
        """Force a password reset on an on-prem AD account via the Defender identityAccounts action.

        identity_account_id is the Defender identity-account GUID (path id); account_id is the on-prem
        AD object id (the analyzer's OnPrem_Object_ID). forcePasswordReset only supports the
        activeDirectory provider, so this is the path that works for hybrid/on-prem identities.
        Requires the SecurityIdentitiesActions.ReadWrite.All application permission.
        """
        resp = self.http.post(
            f"{GRAPH_BASE_URL}/security/identities/identityAccounts/{identity_account_id}/invokeAction",
            headers={"Authorization": f"Bearer {self._token(GRAPH_SCOPE)}", "Content-Type": "application/json"},
            json={"accountId": account_id, "action": "forcePasswordReset", "identityProvider": "activeDirectory"},
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise DefenderActionError(
                f"Failed to force AD password reset for account {account_id}: HTTP {resp.status_code} — {resp.text}"
            )

    def revoke_sessions(self, user_id: str) -> None:
        resp = self.http.post(
            f"{GRAPH_BASE_URL}/users/{user_id}/revokeSignInSessions",
            headers={"Authorization": f"Bearer {self._token(GRAPH_SCOPE)}", "Content-Type": "application/json"},
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise DefenderActionError(
                f"Failed to revoke sign-in sessions for user {user_id}: HTTP {resp.status_code} — {resp.text}"
            )

    def isolate_device(self, device_id: str, comment: str, full: bool = False) -> None:
        resp = self.http.post(
            f"{MDE_BASE_URL}/machines/{device_id}/isolate",
            headers={"Authorization": f"Bearer {self._token(MDE_SCOPE)}", "Content-Type": "application/json"},
            json={"Comment": comment, "IsolationType": "Full" if full else "Selective"},
            timeout=30,
        )
        if not (200 <= resp.status_code < 300):
            raise DefenderActionError(f"Failed to isolate device {device_id}: HTTP {resp.status_code} — {resp.text}")
