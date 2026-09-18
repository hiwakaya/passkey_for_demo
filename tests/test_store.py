"""`passkey_auth.store.InMemoryCredentialStore`のユニットテスト。"""

from __future__ import annotations

import pytest

from passkey_auth.store import InMemoryCredentialStore, StoredCredential


def _credential(credential_id: bytes = b"cred-1", sign_count: int = 0) -> StoredCredential:
    return StoredCredential(
        credential_id=credential_id,
        public_key=b"public-key-bytes",
        sign_count=sign_count,
        user_id="staff-001",
        display_name="山田太郎",
    )


def test_save_and_get_round_trip() -> None:
    store = InMemoryCredentialStore()
    store.save(_credential())
    fetched = store.get(b"cred-1")
    assert fetched is not None
    assert fetched.user_id == "staff-001"
    assert fetched.display_name == "山田太郎"


def test_get_returns_none_for_unknown_credential() -> None:
    store = InMemoryCredentialStore()
    assert store.get(b"missing") is None


def test_list_all_returns_every_saved_credential() -> None:
    store = InMemoryCredentialStore()
    store.save(_credential(b"cred-1"))
    store.save(_credential(b"cred-2"))
    ids = {c.credential_id for c in store.list_all()}
    assert ids == {b"cred-1", b"cred-2"}


def test_save_overwrites_existing_credential_with_same_id() -> None:
    store = InMemoryCredentialStore()
    store.save(_credential(b"cred-1", sign_count=0))
    store.save(_credential(b"cred-1", sign_count=5))
    assert len(store.list_all()) == 1
    assert store.get(b"cred-1").sign_count == 5  # type: ignore[union-attr]


def test_update_sign_count_updates_existing_credential() -> None:
    store = InMemoryCredentialStore()
    store.save(_credential(b"cred-1", sign_count=1))
    store.update_sign_count(b"cred-1", 2)
    fetched = store.get(b"cred-1")
    assert fetched is not None
    assert fetched.sign_count == 2
    # 他のフィールドは変化しない（不変オブジェクトの部分更新）。
    assert fetched.user_id == "staff-001"


def test_update_sign_count_raises_for_unknown_credential() -> None:
    store = InMemoryCredentialStore()
    with pytest.raises(KeyError):
        store.update_sign_count(b"missing", 1)
