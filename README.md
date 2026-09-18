# passkey-auth

FastAPI向け パスキー（FIDO2/WebAuthn）認証の再利用可能コンポーネント。
GLAVIS の複数の自治体AIデモ（`child_allowance`／`child_benefit` 等）で共通利用するために、
`child_benefit/auth/`にあった実装（Firestore永続化・独立マイクロサービス構成）を土台に、
デモごとに差し替え可能な形へ一般化したもの。

## 特徴

- **パスワードレス**：職員はパスキー（既定では端末内蔵の認証器＝Windows Hello・Touch ID等）でログインする。
- **ステートレスなセッション**：JWTのみでセッションを表現し、サーバー側セッションストアを持たない。
  そのため以下の両方の構成で同じ実装を再利用できる。
  - 各デモのFastAPIアプリへ`APIRouter`として直接マウントする構成（同一プロセス）
  - 独立した認証マイクロサービスとして動かし、トークンを別アプリへ受け渡す構成
    （`child_benefit`が採用する Streamlit へのリダイレクト等）
- **永続化はプラガブル**：`CredentialStore`インターフェースを実装するだけで、Excel・Firestore・
  RDB等どのデータ基盤にも接続できる。本パッケージは`InMemoryCredentialStore`（プロセス内メモリ・
  ローカルデモ用）のみを同梱する。
- **役割（ロール）の概念を持たない**：区役所／本庁のような役割分けはデモごとに異なるため、
  本パッケージはユーザーIDと表示名のみを扱う。ログイン成功時に発行するJWTへ任意の追加クレーム
  （例：役割）を埋め込むフック（`claims_for_user`）を用意している。

## インストール

```bash
pip install -e "../passkye-for-demo"   # ローカルパスから（開発中）
# または git URL 経由（デモ側 pyproject.toml の dependencies に追加）
# "passkey-auth @ git+https://github.com/hiwakaya/passkye-for-demo.git@main"
```

## クイックスタート（同一プロセスにマウントする構成）

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from passkey_auth import (
    InMemoryCredentialStore,
    RelyingParty,
    SessionSigner,
    SharedSecretRegistrationGate,
    build_router,
)

app = FastAPI()

rp = RelyingParty(
    id="localhost",                        # 本番はサービスのドメイン名
    name="○○市△△デモ",
    origin="http://localhost:8000",         # 本番は https://の実オリジン
)
store = InMemoryCredentialStore()           # 本番・永続化が要る場合は自作のCredentialStoreに差し替える
signer = SessionSigner(secret_key="CHANGE-ME-32-BYTES-OR-MORE")  # 環境変数等から注入する

router = build_router(
    rp=rp,
    store=store,
    signer=signer,
    cookie_name="app_session",              # 指定するとログイン成功時にhttponly Cookieを発行する
    registration_gate=SharedSecretRegistrationGate("dev-admin-token"),  # 初回登録を制限する
    claims_for_user=lambda user_id: {"role": "区役所"},  # デモ固有の追加クレーム（任意）
)
app.include_router(router)
```

ブラウザ側は同梱の`src/passkey_auth/static/passkey.js`を配信し、ログインページから呼び出す：

```html
<script src="/static/passkey_auth/passkey.js"></script>
<button onclick="doLogin()">パスキーでログイン</button>
<script>
  async function doLogin() {
    const result = await passkeyLogin();       // Cookie発行済みなら以後のリクエストは自動でログイン状態
    console.log(result.user_id, result.claims);
    location.href = "/";
  }
  async function doRegister() {
    await passkeyRegister("staff-001", "山田太郎", "dev-admin-token");
  }
</script>
```

ルートの保護には`passkey_auth.deps.require_session`を使う（Cookie構成の場合）：

```python
from fastapi import Depends, Request
from passkey_auth import SessionSigner, require_session

def current_session(request: Request):
    return require_session(request, signer=signer, cookie_name="app_session")

@app.get("/dashboard")
def dashboard(session: dict = Depends(current_session)):
    ...
```

## エンドポイント一覧（既定プレフィックス `/passkey`）

| メソッド／パス | 用途 |
|---|---|
| `POST /passkey/register/begin` | 登録オプション（チャレンジ）を発行する |
| `POST /passkey/register/complete` | ブラウザからのアテステーションを検証し、クレデンシャルを保存する |
| `POST /passkey/login/begin` | 認証オプション（チャレンジ）を発行する |
| `POST /passkey/login/complete` | ブラウザからのアサーションを検証し、アクセストークン（＋任意でCookie）を発行する |
| `POST /passkey/logout` | `cookie_name`指定時、Cookieを削除する |

## 設計上の注意

- **RP ID とオリジン**：WebAuthnはRP ID（`localhost`または実ドメイン）とオリジンが一致しないと
  検証に失敗する。ローカル開発は`http://localhost:<port>`でアクセスすること（`127.0.0.1`は
  ブラウザによって扱いが異なるため避ける）。本番は必ずHTTPS。
- **登録ゲート（`RegistrationGate`）**：`AllowAllRegistrationGate`（無条件許可）はローカルデモ専用。
  本番相当の検証を行う場合は、職員名簿との照合など適切な`RegistrationGate`実装に差し替えること。
- **署名鍵（`SessionSigner.secret_key`）**：コードに埋め込まず環境変数・Secret Manager等から注入する。
  デモ既定値のまま本番相当の環境で使わないこと。
- **`sign_count`によるリプレイ対策**：認証のたびに`CredentialStore.update_sign_count`を呼び、
  認証器側のカウンタと突き合わせる（`webauthn`ライブラリが検証する）。
- **端末内蔵の認証器（Windows Hello等）を既定にする**：`build_router(..., authenticator_attachment=...)`
  の既定値`AuthenticatorAttachment.PLATFORM`により、登録時ブラウザはWindows Hello・Touch ID等の
  端末内蔵認証器のみを候補にする（USBセキュリティキー等の外部認証器は選択肢から外れ、
  ブラウザの選択ダイアログを経ずに済む）。共有端末でのデモ等、外部認証器も許可したい場合は
  `authenticator_attachment=None`を渡す。

## 開発

```bash
python -m venv .venv
./.venv/Scripts/pip install -e ".[dev]"
./.venv/Scripts/python -m ruff check .
./.venv/Scripts/python -m mypy .
./.venv/Scripts/python -m pytest -q
```

`verify_registration`/`verify_authentication`（実際のアテステーション・アサーション検証）は
仮想FIDO2認証器が無いと本物の入力を用意できないため、`tests/test_router.py`ではこの2関数を
モックしてルーターの配線（チャレンジトークンの発行・検証、ストアへの保存、Cookie発行、
クレームの埋め込み等）のみを検証する。`tests/test_ceremony.py`はオプション生成部分
（認証器を必要としない）を本物の`webauthn`ライブラリで検証する。
