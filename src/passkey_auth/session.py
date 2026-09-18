"""JWTベースのステートレスセッション管理（アクセストークン・チャレンジトークン）。

サーバー側セッションストアを持たず、署名付きJWTのみで完結する。これにより
「同一プロセス内にFastAPI Routerとしてマウントする」構成（例：child_allowance）と
「独立した認証マイクロサービスとして動かす」構成（例：child_benefit）の両方で
同じセッション実装を再利用できる。
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

import jwt


class SessionError(Exception):
    """トークンの生成・検証に失敗した場合に送出する（`jwt`側の例外を薄くラップする）。"""


@dataclass(frozen=True)
class SessionSigner:
    """JWT署名鍵とTTLをまとめた設定（デモごとに1つ用意する）。"""

    secret_key: str
    algorithm: str = "HS256"
    access_token_ttl: datetime.timedelta = field(
        default_factory=lambda: datetime.timedelta(hours=8)
    )
    challenge_token_ttl: datetime.timedelta = field(
        default_factory=lambda: datetime.timedelta(minutes=5)
    )

    def create_challenge_token(self, challenge_b64url: str, token_type: str) -> str:
        """チャレンジを含む短命のJWTを生成する（既定：有効期間5分）。"""
        payload: dict[str, Any] = {
            "type": f"challenge_{token_type}",
            "challenge": challenge_b64url,
            "exp": datetime.datetime.now(tz=datetime.UTC) + self.challenge_token_ttl,
        }
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def decode_challenge_token(self, token: str, token_type: str) -> str:
        """チャレンジトークンを検証してチャレンジ（base64url文字列）を返す。"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.PyJWTError as exc:
            raise SessionError(str(exc)) from exc
        if payload.get("type") != f"challenge_{token_type}":
            raise SessionError("トークンタイプが不正です")
        challenge = payload.get("challenge")
        if not challenge:
            raise SessionError("チャレンジが含まれていません")
        return str(challenge)

    def create_access_token(self, user_id: str, *, claims: dict[str, Any] | None = None) -> str:
        """認証済みセッションJWTを生成する（既定：有効期間8時間）。

        `claims`：デモ固有の追加情報（例：役割）を埋め込むフック。本パッケージ自体は
        役割の概念を持たない。
        """
        payload: dict[str, Any] = {
            "sub": user_id,
            "type": "access",
            "exp": datetime.datetime.now(tz=datetime.UTC) + self.access_token_ttl,
        }
        if claims:
            payload.update(claims)
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def verify_access_token(self, token: str) -> dict[str, Any]:
        """アクセスJWTを検証してペイロード（`sub`＋追加クレーム）を返す。"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.PyJWTError as exc:
            raise SessionError(str(exc)) from exc
        if payload.get("type") != "access":
            raise SessionError("アクセストークンではありません")
        if not payload.get("sub"):
            raise SessionError("ユーザー情報が含まれていません")
        return payload
