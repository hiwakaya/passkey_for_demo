"""`passkey_auth.ceremony`のオプション生成部分のユニットテスト。

`generate_registration_options`/`generate_authentication_options`はローカルで完結する
（実際の認証器を必要としない）ため、本物の`webauthn`ライブラリを直接使ってテストする。
`verify_registration`/`verify_authentication`（実際のアテステーション検証）は、
仮想認証器が必要になるため`tests/test_router.py`でモックを通じて配線のみ検証する。
"""

from __future__ import annotations

import json

from passkey_auth.ceremony import (
    RelyingParty,
    generate_authentication_options,
    generate_registration_options,
)

_RP = RelyingParty(id="localhost", name="テストデモ", origin="http://localhost")


def test_generate_registration_options_shape() -> None:
    options_json, challenge = generate_registration_options(
        _RP, user_id="staff-001", display_name="山田太郎"
    )
    options = json.loads(options_json)

    assert options["rp"]["id"] == "localhost"
    assert options["rp"]["name"] == "テストデモ"
    assert options["user"]["name"] == "山田太郎"
    assert isinstance(challenge, bytes)
    assert len(challenge) >= 16  # WebAuthn仕様上チャレンジは十分な長さのランダムバイト列


def test_generate_registration_options_challenge_is_random_each_call() -> None:
    _, challenge_a = generate_registration_options(_RP, user_id="u1", display_name="A")
    _, challenge_b = generate_registration_options(_RP, user_id="u1", display_name="A")
    assert challenge_a != challenge_b


def test_generate_registration_options_defaults_to_platform_authenticator() -> None:
    """既定では`authenticatorAttachment: "platform"`を要求し、ブラウザに端末内蔵の

    認証器（Windows Hello・Touch ID等）のみを候補として提示させる（USBセキュリティ
    キー等の外部認証器は選択肢から外れる）。
    """
    options_json, _ = generate_registration_options(_RP, user_id="u1", display_name="A")
    options = json.loads(options_json)
    assert options["authenticatorSelection"]["authenticatorAttachment"] == "platform"


def test_generate_registration_options_can_allow_any_authenticator() -> None:
    """`authenticator_attachment=None`を渡すと制限を外し、外部認証器も許可する。"""
    options_json, _ = generate_registration_options(
        _RP, user_id="u1", display_name="A", authenticator_attachment=None
    )
    options = json.loads(options_json)
    assert "authenticatorAttachment" not in options["authenticatorSelection"]


def test_generate_authentication_options_lists_allowed_credentials() -> None:
    options_json, challenge = generate_authentication_options(
        _RP, credential_ids=[b"cred-1", b"cred-2"]
    )
    options = json.loads(options_json)

    assert options["rpId"] == "localhost"
    assert len(options["allowCredentials"]) == 2
    assert isinstance(challenge, bytes)


def test_generate_authentication_options_with_no_credentials() -> None:
    options_json, _ = generate_authentication_options(_RP, credential_ids=[])
    options = json.loads(options_json)
    assert options["allowCredentials"] == []
