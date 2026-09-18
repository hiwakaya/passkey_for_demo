// passkey.js — 汎用パスキー登録・ログインヘルパー（ブラウザ側WebAuthn儀式）。
// サーバー側は passkey_auth.router.build_router() が生成するエンドポイント
// （既定パス: /passkey/register/begin, /passkey/register/complete,
//  /passkey/login/begin, /passkey/login/complete）を前提とする。
// 使い方：<script src=".../passkey.js"></script> のあと
//   await passkeyRegister(userId, displayName, registrationSecret);
//   const result = await passkeyLogin();  // result.access_token / result.user_id / result.claims
(function (global) {
  "use strict";

  function base64UrlToArrayBuffer(b64url) {
    const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
    const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  function arrayBufferToBase64Url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
  }

  function prepareCreationOptions(options) {
    options.challenge = base64UrlToArrayBuffer(options.challenge);
    options.user.id = base64UrlToArrayBuffer(options.user.id);
    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map((c) => ({
        ...c,
        id: base64UrlToArrayBuffer(c.id),
      }));
    }
    return options;
  }

  function prepareRequestOptions(options) {
    options.challenge = base64UrlToArrayBuffer(options.challenge);
    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((c) => ({
        ...c,
        id: base64UrlToArrayBuffer(c.id),
      }));
    }
    return options;
  }

  function serializeRegistrationCredential(credential) {
    return {
      id: credential.id,
      rawId: arrayBufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
        attestationObject: arrayBufferToBase64Url(credential.response.attestationObject),
      },
    };
  }

  function serializeAuthenticationCredential(credential) {
    return {
      id: credential.id,
      rawId: arrayBufferToBase64Url(credential.rawId),
      type: credential.type,
      response: {
        clientDataJSON: arrayBufferToBase64Url(credential.response.clientDataJSON),
        authenticatorData: arrayBufferToBase64Url(credential.response.authenticatorData),
        signature: arrayBufferToBase64Url(credential.response.signature),
        userHandle: credential.response.userHandle
          ? arrayBufferToBase64Url(credential.response.userHandle)
          : null,
      },
    };
  }

  async function fetchJson(url, body) {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || `リクエストに失敗しました（${response.status}）`);
    }
    return data;
  }

  async function passkeyRegister(userId, displayName, registrationSecret, opts) {
    const basePath = (opts && opts.basePath) || "/passkey";
    const begin = await fetchJson(`${basePath}/register/begin`, {
      user_id: userId,
      display_name: displayName,
      registration_secret: registrationSecret || "",
    });

    const credential = await navigator.credentials.create({
      publicKey: prepareCreationOptions(begin.options),
    });
    if (!credential) {
      throw new Error("パスキーの作成がキャンセルされました。");
    }

    return fetchJson(`${basePath}/register/complete`, {
      challenge_token: begin.challenge_token,
      user_id: userId,
      display_name: displayName,
      credential: serializeRegistrationCredential(credential),
    });
  }

  async function passkeyLogin(opts) {
    const basePath = (opts && opts.basePath) || "/passkey";
    const begin = await fetchJson(`${basePath}/login/begin`, {});

    const credential = await navigator.credentials.get({
      publicKey: prepareRequestOptions(begin.options),
    });
    if (!credential) {
      throw new Error("パスキーでのログインがキャンセルされました。");
    }

    return fetchJson(`${basePath}/login/complete`, {
      challenge_token: begin.challenge_token,
      credential: serializeAuthenticationCredential(credential),
    });
  }

  global.passkeyRegister = passkeyRegister;
  global.passkeyLogin = passkeyLogin;
})(window);
