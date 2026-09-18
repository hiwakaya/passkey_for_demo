"""FastAPI ルーター：パスキー登録・ログインのHTTPエンドポイント。

`build_router()`が返す`APIRouter`を、既存のFastAPIアプリへ`app.include_router(...)`で
マウントする（同一プロセス構成）。独立した認証マイクロサービスとして動かす場合も、
空の`FastAPI()`を作りこのルーターをマウントするだけでよい（`examples/`参照）。
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Any, Protocol

from fastapi import APIRouter, HTTPException, Response
from pydantic import BaseModel
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from passkey_auth.ceremony import (
    RelyingParty,
    generate_authentication_options,
    generate_registration_options,
    verify_authentication,
    verify_registration,
)
from passkey_auth.session import SessionError, SessionSigner
from passkey_auth.store import CredentialStore, StoredCredential

logger = logging.getLogger(__name__)


class RegistrationGate(Protocol):
    """新規パスキー登録を許可するかどうかを判定する。

    例：管理トークンとの一致、既存の職員名簿との照合など。デモごとに実装を差し替える。
    """

    def allow(self, *, user_id: str, display_name: str, registration_secret: str) -> bool: ...


class AllowAllRegistrationGate:
    """登録を常に許可する（ローカルデモ専用。本番では必ず適切なゲートに差し替える）。"""

    def allow(self, *, user_id: str, display_name: str, registration_secret: str) -> bool:
        return True


class SharedSecretRegistrationGate:
    """共有シークレット（管理者トークン）との一致のみで登録を許可する簡易ゲート。"""

    def __init__(self, secret: str) -> None:
        self._secret = secret

    def allow(self, *, user_id: str, display_name: str, registration_secret: str) -> bool:
        return bool(self._secret) and registration_secret == self._secret


class _RegisterBeginRequest(BaseModel):
    user_id: str
    display_name: str
    registration_secret: str = ""


class _RegisterCompleteRequest(BaseModel):
    challenge_token: str
    user_id: str
    display_name: str
    credential: dict[str, Any]


class _LoginCompleteRequest(BaseModel):
    challenge_token: str
    credential: dict[str, Any]


class LoginResult(BaseModel):
    access_token: str
    user_id: str
    claims: dict[str, Any] = {}


def build_router(
    *,
    rp: RelyingParty,
    store: CredentialStore,
    signer: SessionSigner,
    registration_gate: RegistrationGate | None = None,
    claims_for_user: Callable[[str], dict[str, Any]] | None = None,
    prefix: str = "/passkey",
    cookie_name: str | None = None,
) -> APIRouter:
    """パスキー登録・ログインのAPIRouterを組み立てる。

    - `claims_for_user`：ログイン成功時にアクセストークンへ埋め込む追加クレーム
      （例：役割）を`user_id`から解決するフック。本パッケージ自体は役割の概念を持たない。
    - `cookie_name`：指定すると、ログイン成功時にhttponly Cookieとしてもアクセス
      トークンを設定する（同一プロセスにマウントするFastAPI+Jinja2構成向け）。
      指定しない場合はレスポンスJSONの`access_token`のみを返す（別プロセス・
      別オリジンへのトークン受け渡し構成向け。`CLAUDE.md`等の各デモが方式を選ぶ）。
    """
    gate = registration_gate or AllowAllRegistrationGate()
    router = APIRouter(prefix=prefix, tags=["passkey-auth"])

    @router.post("/register/begin")
    def register_begin(req: _RegisterBeginRequest) -> dict[str, Any]:
        if not gate.allow(
            user_id=req.user_id,
            display_name=req.display_name,
            registration_secret=req.registration_secret,
        ):
            raise HTTPException(status_code=403, detail="登録が許可されていません。")
        options_json, challenge = generate_registration_options(
            rp, user_id=req.user_id, display_name=req.display_name
        )
        token = signer.create_challenge_token(bytes_to_base64url(challenge), token_type="reg")
        return {"options": json.loads(options_json), "challenge_token": token}

    @router.post("/register/complete")
    def register_complete(req: _RegisterCompleteRequest) -> dict[str, str]:
        try:
            challenge_b64 = signer.decode_challenge_token(req.challenge_token, token_type="reg")
        except SessionError as exc:
            raise HTTPException(status_code=400, detail=f"セッションが無効です: {exc}") from exc

        try:
            verification = verify_registration(
                rp,
                credential_data=req.credential,
                expected_challenge=base64url_to_bytes(challenge_b64),
            )
        except Exception as exc:
            logger.exception("パスキー登録検証エラー")
            raise HTTPException(status_code=400, detail=f"登録検証に失敗しました: {exc}") from exc

        store.save(
            StoredCredential(
                credential_id=verification.credential_id,
                public_key=verification.credential_public_key,
                sign_count=verification.sign_count,
                user_id=req.user_id,
                display_name=req.display_name,
            )
        )
        return {"status": "ok", "user_id": req.user_id}

    @router.post("/login/begin")
    def login_begin() -> dict[str, Any]:
        credentials = store.list_all()
        if not credentials:
            raise HTTPException(status_code=404, detail="登録済みのパスキーがありません。")
        options_json, challenge = generate_authentication_options(
            rp, credential_ids=[c.credential_id for c in credentials]
        )
        token = signer.create_challenge_token(bytes_to_base64url(challenge), token_type="auth")
        return {"options": json.loads(options_json), "challenge_token": token}

    @router.post("/login/complete", response_model=LoginResult)
    def login_complete(req: _LoginCompleteRequest, response: Response) -> LoginResult:
        try:
            challenge_b64 = signer.decode_challenge_token(req.challenge_token, token_type="auth")
        except SessionError as exc:
            raise HTTPException(status_code=400, detail=f"セッションが無効です: {exc}") from exc

        credential_id = base64url_to_bytes(req.credential.get("id", ""))
        stored = store.get(credential_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="パスキーが見つかりません。")

        try:
            verification = verify_authentication(
                rp,
                credential_data=req.credential,
                expected_challenge=base64url_to_bytes(challenge_b64),
                public_key=stored.public_key,
                sign_count=stored.sign_count,
            )
        except Exception as exc:
            logger.exception("パスキー認証検証エラー")
            raise HTTPException(status_code=400, detail=f"認証に失敗しました: {exc}") from exc

        store.update_sign_count(credential_id, verification.new_sign_count)
        claims = claims_for_user(stored.user_id) if claims_for_user else {}
        token = signer.create_access_token(stored.user_id, claims=claims)

        if cookie_name:
            response.set_cookie(
                cookie_name,
                token,
                httponly=True,
                samesite="lax",
                max_age=int(signer.access_token_ttl.total_seconds()),
            )
        return LoginResult(access_token=token, user_id=stored.user_id, claims=claims)

    @router.post("/logout")
    def logout(response: Response) -> dict[str, str]:
        if cookie_name:
            response.delete_cookie(cookie_name)
        return {"status": "ok"}

    return router
