"""パスキークレデンシャルの永続化インターフェースと参照実装。

各デモは`CredentialStore`を自分のデータ基盤（Excel・Firestore・RDB等）向けに実装する。
本パッケージは`InMemoryCredentialStore`のみを参照実装として同梱する（ローカルデモ・テスト用。
プロセス再起動で失われる）。
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class StoredCredential:
    """登録済みパスキー1件分のデータ。"""

    credential_id: bytes
    public_key: bytes
    sign_count: int
    user_id: str
    display_name: str


class CredentialStore(Protocol):
    """パスキークレデンシャルの永続化インターフェース。"""

    def save(self, credential: StoredCredential) -> None: ...

    def get(self, credential_id: bytes) -> StoredCredential | None: ...

    def list_all(self) -> list[StoredCredential]: ...

    def update_sign_count(self, credential_id: bytes, sign_count: int) -> None: ...


class InMemoryCredentialStore:
    """プロセス内メモリのみに保持する参照実装（ローカルデモ・テスト用）。"""

    def __init__(self) -> None:
        self._credentials: dict[bytes, StoredCredential] = {}

    def save(self, credential: StoredCredential) -> None:
        self._credentials[credential.credential_id] = credential

    def get(self, credential_id: bytes) -> StoredCredential | None:
        return self._credentials.get(credential_id)

    def list_all(self) -> list[StoredCredential]:
        return list(self._credentials.values())

    def update_sign_count(self, credential_id: bytes, sign_count: int) -> None:
        existing = self._credentials.get(credential_id)
        if existing is None:
            raise KeyError(f"credential not found: {credential_id!r}")
        self._credentials[credential_id] = dataclasses.replace(existing, sign_count=sign_count)

    def clear(self) -> None:
        """保持している全クレデンシャルを削除する（テストでの分離用）。"""
        self._credentials.clear()
