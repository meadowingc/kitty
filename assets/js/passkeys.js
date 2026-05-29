// Shared WebAuthn (passkey) helpers for kitty.
(function () {
  "use strict";

  function b64urlToBuf(b64url) {
    const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
    const str = atob(b64 + pad);
    const buf = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
    return buf.buffer;
  }

  function bufToB64url(buf) {
    const bytes = new Uint8Array(buf);
    let str = "";
    for (let i = 0; i < bytes.length; i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function postJSON(url, body) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrfToken(),
      },
      body: body == null ? null : JSON.stringify(body),
    });
  }

  // Convert the server's credential-creation options into the binary form the
  // browser API expects.
  function decodeCreationOptions(publicKey) {
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    publicKey.user.id = b64urlToBuf(publicKey.user.id);
    if (publicKey.excludeCredentials) {
      publicKey.excludeCredentials = publicKey.excludeCredentials.map((c) => ({
        ...c,
        id: b64urlToBuf(c.id),
      }));
    }
    return publicKey;
  }

  function decodeRequestOptions(publicKey) {
    publicKey.challenge = b64urlToBuf(publicKey.challenge);
    if (publicKey.allowCredentials) {
      publicKey.allowCredentials = publicKey.allowCredentials.map((c) => ({
        ...c,
        id: b64urlToBuf(c.id),
      }));
    }
    return publicKey;
  }

  function attestationToJSON(cred) {
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: bufToB64url(cred.response.attestationObject),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      },
    };
  }

  function assertionToJSON(cred) {
    return {
      id: cred.id,
      rawId: bufToB64url(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: bufToB64url(cred.response.authenticatorData),
        clientDataJSON: bufToB64url(cred.response.clientDataJSON),
        signature: bufToB64url(cred.response.signature),
        userHandle: cred.response.userHandle
          ? bufToB64url(cred.response.userHandle)
          : null,
      },
    };
  }

  async function registerPasskey(name) {
    if (!window.PublicKeyCredential) {
      throw new Error("This browser does not support passkeys.");
    }
    const beginResp = await postJSON("/dashboard/passkeys/register/begin", null);
    if (!beginResp.ok) throw new Error(await beginResp.text());
    const options = await beginResp.json();

    const cred = await navigator.credentials.create({
      publicKey: decodeCreationOptions(options.publicKey),
    });

    const finishUrl =
      "/dashboard/passkeys/register/finish?name=" + encodeURIComponent(name || "Passkey");
    const finishResp = await postJSON(finishUrl, attestationToJSON(cred));
    if (!finishResp.ok) throw new Error(await finishResp.text());
    return finishResp.json();
  }

  async function loginWithPasskey() {
    if (!window.PublicKeyCredential) {
      throw new Error("This browser does not support passkeys.");
    }
    const beginResp = await postJSON("/passkeys/login/begin", null);
    if (!beginResp.ok) throw new Error(await beginResp.text());
    const options = await beginResp.json();

    const cred = await navigator.credentials.get({
      publicKey: decodeRequestOptions(options.publicKey),
    });

    const finishResp = await postJSON("/passkeys/login/finish", assertionToJSON(cred));
    if (!finishResp.ok) throw new Error(await finishResp.text());
    return finishResp.json();
  }

  window.Passkeys = {
    register: registerPasskey,
    login: loginWithPasskey,
    csrfToken: csrfToken,
  };
})();
