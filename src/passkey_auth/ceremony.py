"""WebAuthn（FIDO2）の登録・認証オプション生成と検証（決定論・純粋関数群）。

`webauthn`（PyPI）ライブラリへの薄いラッパー。RP（Relying Party）設定は
モジュール読込み時の環境変数ではなく`RelyingParty`として明示的に受け取る
（同一プロセス内で複数デモ・複数設定をテストしやすくするため）。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import webauthn
from webauthn.authentication.verify_authentication_response import VerifiedAuthentication
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
    AuthenticatorAttestationResponse,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialType,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.verify_registration_response import VerifiedRegistration


@dataclass(frozen=True)
class RelyingParty:
    """WebAuthnのRelying Party（RP）設定。デモごとに1つ用意する。"""

    id: str  # RP ID（例："localhost"。本番はサービスのドメイン名）
    name: str  # 表示名（例："札幌市児童扶養手当デモ"）
    origin: str  # 期待するオリジン（例："http://localhost:8000"）


def generate_registration_options(
    rp: RelyingParty, *, user_id: str, display_name: str
) -> tuple[str, bytes]:
    """パスキー登録オプションを生成する。`(options_json, challenge_bytes)`を返す。"""
    options = webauthn.generate_registration_options(
        rp_id=rp.id,
        rp_name=rp.name,
        user_id=user_id.encode(),
        user_name=display_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
        supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_256],
    )
    return webauthn.options_to_json(options), options.challenge


def verify_registration(
    rp: RelyingParty, *, credential_data: dict[str, Any], expected_challenge: bytes
) -> VerifiedRegistration:
    """登録レスポンス（ブラウザからのJSON）を検証する。失敗時は`webauthn`側の例外を送出する。"""
    resp = credential_data.get("response", {})
    credential = RegistrationCredential(
        id=credential_data["id"],
        raw_id=base64url_to_bytes(credential_data["rawId"]),
        response=AuthenticatorAttestationResponse(
            client_data_json=base64url_to_bytes(resp["clientDataJSON"]),
            attestation_object=base64url_to_bytes(resp["attestationObject"]),
        ),
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )
    return webauthn.verify_registration_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=rp.id,
        expected_origin=rp.origin,
        require_user_verification=False,
    )


def generate_authentication_options(
    rp: RelyingParty, *, credential_ids: list[bytes]
) -> tuple[str, bytes]:
    """パスキー認証オプションを生成する。`(options_json, challenge_bytes)`を返す。"""
    descriptors = [PublicKeyCredentialDescriptor(id=cid) for cid in credential_ids]
    options = webauthn.generate_authentication_options(
        rp_id=rp.id,
        allow_credentials=descriptors,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return webauthn.options_to_json(options), options.challenge


def verify_authentication(
    rp: RelyingParty,
    *,
    credential_data: dict[str, Any],
    expected_challenge: bytes,
    public_key: bytes,
    sign_count: int,
) -> VerifiedAuthentication:
    """認証レスポンス（ブラウザからのJSON）を検証する。失敗時は`webauthn`側の例外を送出する。"""
    resp = credential_data.get("response", {})
    user_handle_raw = resp.get("userHandle")
    credential = AuthenticationCredential(
        id=credential_data["id"],
        raw_id=base64url_to_bytes(credential_data["rawId"]),
        response=AuthenticatorAssertionResponse(
            client_data_json=base64url_to_bytes(resp["clientDataJSON"]),
            authenticator_data=base64url_to_bytes(resp["authenticatorData"]),
            signature=base64url_to_bytes(resp["signature"]),
            user_handle=base64url_to_bytes(user_handle_raw) if user_handle_raw else None,
        ),
        type=PublicKeyCredentialType.PUBLIC_KEY,
    )
    return webauthn.verify_authentication_response(
        credential=credential,
        expected_challenge=expected_challenge,
        expected_rp_id=rp.id,
        expected_origin=rp.origin,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
        require_user_verification=False,
    )
