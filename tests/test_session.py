"""`passkey_auth.session`のユニットテスト。"""

from __future__ import annotations

import datetime

import pytest

from passkey_auth.session import SessionError, SessionSigner


@pytest.fixture
def signer() -> SessionSigner:
    return SessionSigner(secret_key="test-secret-key")


def test_access_token_roundtrip(signer: SessionSigner) -> None:
    token = signer.create_access_token("staff-001")
    payload = signer.verify_access_token(token)
    assert payload["sub"] == "staff-001"


def test_access_token_carries_custom_claims(signer: SessionSigner) -> None:
    token = signer.create_access_token("staff-001", claims={"role": "区役所"})
    payload = signer.verify_access_token(token)
    assert payload["role"] == "区役所"


def test_access_token_wrong_type_rejected(signer: SessionSigner) -> None:
    """チャレンジトークンをアクセストークンとして検証するとエラーになる。"""
    challenge_token = signer.create_challenge_token("dummy-challenge", "auth")
    with pytest.raises(SessionError):
        signer.verify_access_token(challenge_token)


def test_challenge_token_roundtrip(signer: SessionSigner) -> None:
    token = signer.create_challenge_token("dGVzdGNoYWxsZW5nZQ", "reg")
    decoded = signer.decode_challenge_token(token, "reg")
    assert decoded == "dGVzdGNoYWxsZW5nZQ"


def test_challenge_token_wrong_type_rejected(signer: SessionSigner) -> None:
    """regチャレンジトークンをauthとして検証するとエラーになる。"""
    token = signer.create_challenge_token("abc", "reg")
    with pytest.raises(SessionError):
        signer.decode_challenge_token(token, "auth")


def test_invalid_signature_rejected(signer: SessionSigner) -> None:
    """署名が不正なトークンを拒否する。"""
    token = signer.create_access_token("staff-001")
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(SessionError):
        signer.verify_access_token(tampered)


def test_different_secret_rejects_token() -> None:
    """異なる鍵で署名されたトークンは検証に失敗する。"""
    signer_a = SessionSigner(secret_key="secret-a")
    signer_b = SessionSigner(secret_key="secret-b")
    token = signer_a.create_access_token("staff-001")
    with pytest.raises(SessionError):
        signer_b.verify_access_token(token)


def test_expired_access_token_rejected() -> None:
    signer = SessionSigner(
        secret_key="test-secret-key",
        access_token_ttl=datetime.timedelta(seconds=-1),
    )
    token = signer.create_access_token("staff-001")
    with pytest.raises(SessionError):
        signer.verify_access_token(token)
