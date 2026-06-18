import pytest
from conftest import FakeResponse

from defender_client import DefenderActionError, DefenderClient

TENANT_ID = "11111111-1111-1111-1111-111111111111"
USER_ID = "a11133f3-9f15-4294-b779-600f5cbce391"
DEVICE_ID = "d5735271e432abf076c0a009fe1eae3aaffd51e4"
IDENTITY_ACCOUNT_ID = "c86844d7-5270-4bac-b5c4-d9174d11a9e2"
ONPREM_ID = "5c8dcfd2-d4f1-45c7-b28f-68076378e4f8"


def token_route(fake_http, token="tok"):
    fake_http.route(
        "POST", f"/{TENANT_ID}/oauth2/v2.0/token", FakeResponse(200, {"access_token": token})
    )


def test_disable_user_success(fake_http):
    token_route(fake_http)
    fake_http.route("PATCH", f"/users/{USER_ID}", FakeResponse(200, {}))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    client.disable_user(USER_ID)

    call = fake_http.calls[-1]
    assert call["json"] == {"accountEnabled": False}
    assert call["headers"]["Authorization"] == "Bearer tok"


def test_disable_user_raises_on_error(fake_http):
    token_route(fake_http)
    fake_http.route("PATCH", f"/users/{USER_ID}", FakeResponse(403, text="forbidden"))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    with pytest.raises(DefenderActionError):
        client.disable_user(USER_ID)


def test_isolate_device_defaults_to_selective(fake_http):
    token_route(fake_http)
    fake_http.route("POST", f"/machines/{DEVICE_ID}/isolate", FakeResponse(200, {}))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    client.isolate_device(DEVICE_ID, "comment")

    isolate_call = [c for c in fake_http.calls if c["url"].endswith("/isolate")][0]
    assert isolate_call["json"] == {"Comment": "comment", "IsolationType": "Selective"}


def test_isolate_device_full_when_requested(fake_http):
    token_route(fake_http)
    fake_http.route("POST", f"/machines/{DEVICE_ID}/isolate", FakeResponse(200, {}))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    client.isolate_device(DEVICE_ID, "comment", full=True)

    isolate_call = [c for c in fake_http.calls if c["url"].endswith("/isolate")][0]
    assert isolate_call["json"] == {"Comment": "comment", "IsolationType": "Full"}


def test_isolate_device_raises_on_error(fake_http):
    token_route(fake_http)
    fake_http.route("POST", f"/machines/{DEVICE_ID}/isolate", FakeResponse(500, text="boom"))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    with pytest.raises(DefenderActionError):
        client.isolate_device(DEVICE_ID, "comment")


def test_token_is_cached_per_scope(fake_http):
    token_calls = {"count": 0}

    def token_response(**kwargs):
        token_calls["count"] += 1
        return FakeResponse(200, {"access_token": "tok"})

    fake_http.route("POST", f"/{TENANT_ID}/oauth2/v2.0/token", token_response)
    fake_http.route("PATCH", f"/users/{USER_ID}", FakeResponse(200, {}))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    client.disable_user(USER_ID)
    client.disable_user(USER_ID)

    assert token_calls["count"] == 1


def test_force_password_reset_entra_success(fake_http):
    token_route(fake_http)
    fake_http.route("PATCH", f"/users/{USER_ID}", FakeResponse(200, {}))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    client.force_password_reset_entra(USER_ID)

    call = fake_http.calls[-1]
    assert call["json"] == {"passwordProfile": {"forceChangePasswordNextSignIn": True}}


def test_force_password_reset_entra_raises_on_error(fake_http):
    token_route(fake_http)
    fake_http.route("PATCH", f"/users/{USER_ID}", FakeResponse(403, text="forbidden"))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    with pytest.raises(DefenderActionError):
        client.force_password_reset_entra(USER_ID)


def test_force_password_reset_ad_success(fake_http):
    token_route(fake_http)
    fake_http.route(
        "POST", f"/security/identities/identityAccounts/{IDENTITY_ACCOUNT_ID}/invokeAction", FakeResponse(200, {})
    )
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    client.force_password_reset_ad(IDENTITY_ACCOUNT_ID, ONPREM_ID)

    call = fake_http.calls[-1]
    assert f"/security/identities/identityAccounts/{IDENTITY_ACCOUNT_ID}/invokeAction" in call["url"]
    assert call["json"] == {
        "accountId": ONPREM_ID,
        "action": "forcePasswordReset",
        "identityProvider": "activeDirectory",
    }
    assert call["headers"]["Authorization"] == "Bearer tok"


def test_force_password_reset_ad_raises_on_error(fake_http):
    token_route(fake_http)
    fake_http.route(
        "POST", f"/security/identities/identityAccounts/{IDENTITY_ACCOUNT_ID}/invokeAction", FakeResponse(403, text="forbidden")
    )
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    with pytest.raises(DefenderActionError):
        client.force_password_reset_ad(IDENTITY_ACCOUNT_ID, ONPREM_ID)


def test_revoke_sessions_success(fake_http):
    token_route(fake_http)
    fake_http.route("POST", f"/users/{USER_ID}/revokeSignInSessions", FakeResponse(200, {"value": True}))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    client.revoke_sessions(USER_ID)

    call = fake_http.calls[-1]
    assert f"/users/{USER_ID}/revokeSignInSessions" in call["url"]


def test_revoke_sessions_raises_on_error(fake_http):
    token_route(fake_http)
    fake_http.route("POST", f"/users/{USER_ID}/revokeSignInSessions", FakeResponse(403, text="forbidden"))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    with pytest.raises(DefenderActionError):
        client.revoke_sessions(USER_ID)


def test_token_request_failure_raises(fake_http):
    fake_http.route("POST", f"/{TENANT_ID}/oauth2/v2.0/token", FakeResponse(401, text="bad creds"))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    with pytest.raises(DefenderActionError):
        client.disable_user(USER_ID)


def test_token_response_without_access_token_raises(fake_http):
    fake_http.route("POST", f"/{TENANT_ID}/oauth2/v2.0/token", FakeResponse(200, {}))
    client = DefenderClient(TENANT_ID, "client", "secret", http=fake_http)

    with pytest.raises(DefenderActionError):
        client.disable_user(USER_ID)
