"""passkey_auth: FastAPI向けパスキー（FIDO2/WebAuthn）認証の再利用可能コンポーネント。

GLAVIS の複数の自治体AIデモ（child_allowance／child_benefit 等）で共通利用する。
最小構成：

    from passkey_auth import RelyingParty, SessionSigner, InMemoryCredentialStore, build_router

    router = build_router(
        rp=RelyingParty(id="localhost", name="デモ", origin="http://localhost:8000"),
        store=InMemoryCredentialStore(),
        signer=SessionSigner(secret_key="change-me"),
        cookie_name="app_session",
    )
    app.include_router(router)

静的ファイル（ブラウザ側WebAuthn儀式のJS）は`passkey_auth/static/passkey.js`に同梱している。
FastAPIアプリ側で`app.mount("/static/passkey_auth", StaticFiles(packages=["passkey_auth"]), ...)`
のように配信するか、`importlib.resources`でファイル自体をコピーして使う（`README.md`参照）。
"""

from __future__ import annotations

from passkey_auth.ceremony import RelyingParty
from passkey_auth.deps import get_session, require_session
from passkey_auth.router import (
    AllowAllRegistrationGate,
    LoginResult,
    RegistrationGate,
    SharedSecretRegistrationGate,
    build_router,
)
from passkey_auth.session import SessionError, SessionSigner
from passkey_auth.store import CredentialStore, InMemoryCredentialStore, StoredCredential

__all__ = [
    "AllowAllRegistrationGate",
    "CredentialStore",
    "InMemoryCredentialStore",
    "LoginResult",
    "RegistrationGate",
    "RelyingParty",
    "SessionError",
    "SessionSigner",
    "SharedSecretRegistrationGate",
    "StoredCredential",
    "build_router",
    "get_session",
    "require_session",
]
