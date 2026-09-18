"""`passkey_auth.router.build_router`のHTTPレベルの結合テスト。

実際のFIDO2認証器（仮想認証器含む）は使わず、`verify_registration`／
`verify_authentication`（`webauthn`ライブラリへの薄いラッパー）をモックして、
ルーター自身の配線（チャレンジトークンの発行・検証、ストアへの保存、Cookie発行、
クレームの埋め込み等）を検証する。
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from passkey_auth.ceremony import RelyingParty
from passkey_auth.router import SharedSecretRegistrationGate, build_router
from passkey_auth.session import SessionSigner
from passkey_auth.store import InMemoryCredentialStore, StoredCredential

_RP = RelyingParty(id="localhost", name="テストデモ", origin="http://localhost")


def _make_app(**router_kwargs: object) -> tuple[FastAPI, InMemoryCredentialStore]:
    router_kwargs.setdefault("rp", _RP)
    router_kwargs.setdefault("store", InMemoryCredentialStore())
    router_kwargs.setdefault("signer", SessionSigner(secret_key="test-secret"))
    store = router_kwargs["store"]
    assert isinstance(store, InMemoryCredentialStore)
    router = build_router(**router_kwargs)  # type: ignore[arg-type]
    app = FastAPI()
    app.include_router(router)
    return app, store


def test_register_begin_returns_options_and_challenge_token() -> None:
    app, _ = _make_app()
    client = TestClient(app)

    response = client.post(
        "/passkey/register/begin",
        json={"user_id": "staff-001", "display_name": "山田太郎"},
    )

    assert response.status_code == 200
    body = response.json()
    assert "options" in body
    assert "challenge_token" in body
    assert body["options"]["rp"]["id"] == "localhost"


def test_register_begin_rejects_when_gate_denies() -> None:
    app, _ = _make_app(registration_gate=SharedSecretRegistrationGate("correct-secret"))
    client = TestClient(app)

    response = client.post(
        "/passkey/register/begin",
        json={
            "user_id": "staff-001",
            "display_name": "山田太郎",
            "registration_secret": "wrong-secret",
        },
    )

    assert response.status_code == 403


def test_register_begin_allows_when_gate_secret_matches() -> None:
    app, _ = _make_app(registration_gate=SharedSecretRegistrationGate("correct-secret"))
    client = TestClient(app)

    response = client.post(
        "/passkey/register/begin",
        json={
            "user_id": "staff-001",
            "display_name": "山田太郎",
            "registration_secret": "correct-secret",
        },
    )

    assert response.status_code == 200


def test_register_complete_rejects_invalid_challenge_token() -> None:
    app, _ = _make_app()
    client = TestClient(app)

    response = client.post(
        "/passkey/register/complete",
        json={
            "challenge_token": "not-a-real-token",
            "user_id": "staff-001",
            "display_name": "山田太郎",
            "credential": {},
        },
    )

    assert response.status_code == 400


def test_register_complete_saves_credential_on_successful_verification() -> None:
    app, store = _make_app()
    client = TestClient(app)

    begin = client.post(
        "/passkey/register/begin",
        json={"user_id": "staff-001", "display_name": "山田太郎"},
    ).json()

    fake_verification = SimpleNamespace(
        credential_id=b"credential-id-bytes",
        credential_public_key=b"public-key-bytes",
        sign_count=0,
    )
    with patch("passkey_auth.router.verify_registration", return_value=fake_verification):
        response = client.post(
            "/passkey/register/complete",
            json={
                "challenge_token": begin["challenge_token"],
                "user_id": "staff-001",
                "display_name": "山田太郎",
                "credential": {"id": "whatever", "response": {}},
            },
        )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "user_id": "staff-001"}
    saved = store.get(b"credential-id-bytes")
    assert saved is not None
    assert saved.display_name == "山田太郎"


def test_register_complete_returns_400_on_verification_failure() -> None:
    app, store = _make_app()
    client = TestClient(app)

    begin = client.post(
        "/passkey/register/begin",
        json={"user_id": "staff-001", "display_name": "山田太郎"},
    ).json()

    with patch(
        "passkey_auth.router.verify_registration", side_effect=ValueError("bad attestation")
    ):
        response = client.post(
            "/passkey/register/complete",
            json={
                "challenge_token": begin["challenge_token"],
                "user_id": "staff-001",
                "display_name": "山田太郎",
                "credential": {"id": "whatever", "response": {}},
            },
        )

    assert response.status_code == 400
    assert store.list_all() == []


def test_login_begin_returns_404_when_no_credentials_registered() -> None:
    app, _ = _make_app()
    client = TestClient(app)

    response = client.post("/passkey/login/begin")

    assert response.status_code == 404


def test_login_begin_returns_options_when_credentials_exist() -> None:
    app, store = _make_app()
    store.save(
        StoredCredential(
            credential_id=b"credential-id-bytes",
            public_key=b"public-key-bytes",
            sign_count=0,
            user_id="staff-001",
            display_name="山田太郎",
        )
    )
    client = TestClient(app)

    response = client.post("/passkey/login/begin")

    assert response.status_code == 200
    body = response.json()
    assert "options" in body
    assert "challenge_token" in body


@pytest.fixture
def _registered_store() -> InMemoryCredentialStore:
    store = InMemoryCredentialStore()
    store.save(
        StoredCredential(
            credential_id=b"credential-id-bytes",
            public_key=b"public-key-bytes",
            sign_count=3,
            user_id="staff-001",
            display_name="山田太郎",
        )
    )
    return store


def test_login_complete_returns_access_token_and_sets_cookie(
    _registered_store: InMemoryCredentialStore,
) -> None:
    from webauthn.helpers import bytes_to_base64url

    app, store = _make_app(store=_registered_store, cookie_name="app_session")
    client = TestClient(app)

    begin = client.post("/passkey/login/begin").json()

    fake_verification = SimpleNamespace(new_sign_count=4)
    with patch("passkey_auth.router.verify_authentication", return_value=fake_verification):
        response = client.post(
            "/passkey/login/complete",
            json={
                "challenge_token": begin["challenge_token"],
                "credential": {
                    "id": bytes_to_base64url(b"credential-id-bytes"),
                    "response": {"userHandle": None},
                },
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == "staff-001"
    assert body["access_token"]
    assert "app_session" in response.cookies
    assert store.get(b"credential-id-bytes").sign_count == 4  # type: ignore[union-attr]


def test_login_complete_without_cookie_name_does_not_set_cookie(
    _registered_store: InMemoryCredentialStore,
) -> None:
    from webauthn.helpers import bytes_to_base64url

    app, _ = _make_app(store=_registered_store)  # cookie_name未指定
    client = TestClient(app)
    begin = client.post("/passkey/login/begin").json()

    fake_verification = SimpleNamespace(new_sign_count=4)
    with patch("passkey_auth.router.verify_authentication", return_value=fake_verification):
        response = client.post(
            "/passkey/login/complete",
            json={
                "challenge_token": begin["challenge_token"],
                "credential": {
                    "id": bytes_to_base64url(b"credential-id-bytes"),
                    "response": {"userHandle": None},
                },
            },
        )

    assert response.status_code == 200
    assert response.cookies.get("app_session") is None


def test_login_complete_embeds_claims_from_hook(
    _registered_store: InMemoryCredentialStore,
) -> None:
    from webauthn.helpers import bytes_to_base64url

    app, _ = _make_app(
        store=_registered_store,
        claims_for_user=lambda user_id: {"role": "区役所", "user_id_echo": user_id},
    )
    client = TestClient(app)
    begin = client.post("/passkey/login/begin").json()

    fake_verification = SimpleNamespace(new_sign_count=4)
    with patch("passkey_auth.router.verify_authentication", return_value=fake_verification):
        response = client.post(
            "/passkey/login/complete",
            json={
                "challenge_token": begin["challenge_token"],
                "credential": {
                    "id": bytes_to_base64url(b"credential-id-bytes"),
                    "response": {"userHandle": None},
                },
            },
        )

    body = response.json()
    assert body["claims"] == {"role": "区役所", "user_id_echo": "staff-001"}


def test_login_complete_rejects_unknown_credential_id(
    _registered_store: InMemoryCredentialStore,
) -> None:
    from webauthn.helpers import bytes_to_base64url

    app, _ = _make_app(store=_registered_store)
    client = TestClient(app)
    begin = client.post("/passkey/login/begin").json()

    response = client.post(
        "/passkey/login/complete",
        json={
            "challenge_token": begin["challenge_token"],
            "credential": {
                "id": bytes_to_base64url(b"never-registered"),
                "response": {"userHandle": None},
            },
        },
    )

    assert response.status_code == 404


def test_login_complete_rejects_invalid_challenge_token(
    _registered_store: InMemoryCredentialStore,
) -> None:
    from webauthn.helpers import bytes_to_base64url

    app, _ = _make_app(store=_registered_store)
    client = TestClient(app)

    response = client.post(
        "/passkey/login/complete",
        json={
            "challenge_token": "not-a-real-token",
            "credential": {
                "id": bytes_to_base64url(b"credential-id-bytes"),
                "response": {"userHandle": None},
            },
        },
    )

    assert response.status_code == 400


def test_logout_clears_cookie() -> None:
    app, _ = _make_app(cookie_name="app_session")
    client = TestClient(app)

    response = client.post("/passkey/logout")

    assert response.status_code == 200
    # FastAPI/Starletteはdelete_cookieで有効期限切れのSet-Cookieヘッダを返す。
    assert "app_session" in response.headers.get("set-cookie", "")
