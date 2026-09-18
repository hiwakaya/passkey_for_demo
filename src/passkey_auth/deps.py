"""FastAPIルート保護用の依存関数（Cookieベースのセッション読取り）。

`router.py::build_router(..., cookie_name=...)`でCookie発行を有効にした構成向け。
トークンを自前でヘッダ等から取り出す構成では使わなくてよい（`SessionSigner.verify_access_token`
を直接呼べばよい）。
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request

from passkey_auth.session import SessionError, SessionSigner


def get_session(
    request: Request, *, signer: SessionSigner, cookie_name: str
) -> dict[str, Any] | None:
    """Cookieからアクセストークンを読み取り検証する。無ければ／無効なら`None`を返す。"""
    token = request.cookies.get(cookie_name)
    if not token:
        return None
    try:
        return signer.verify_access_token(token)
    except SessionError:
        return None


def require_session(request: Request, *, signer: SessionSigner, cookie_name: str) -> dict[str, Any]:
    """`get_session`のうえ、未ログインならHTTP 401を送出する版。"""
    session = get_session(request, signer=signer, cookie_name=cookie_name)
    if session is None:
        raise HTTPException(status_code=401, detail="ログインが必要です。")
    return session
