// In the page's own world: a site's passkey requests go to the vault, through Vault Autofill and
// Touch ID, when the vault has a passkey for the site or is asked to save one. Anything else goes on
// to Chromium as before (a security key, a phone's QR code).
(() => {
  const container = globalThis.CredentialsContainer?.prototype;
  if (!container || !window.isSecureContext || window !== window.top || container.get.__vaultPasskey) return;
  const native = { get: container.get, create: container.create };
  const { stringify, parse } = JSON;
  // How long the extension has to say it heard a request (it may still be loading), and how often
  // the request is sent again until it does.
  const HEARD_WITHIN = 15_000;
  const RESEND = 400;

  const toB64 = (source) => {
    const view = source instanceof ArrayBuffer ? new Uint8Array(source) : new Uint8Array(source.buffer, source.byteOffset, source.byteLength);
    let text = "";
    for (const byte of view) text += String.fromCharCode(byte);
    return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const fromB64 = (text) => {
    const plain = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    const bytes = new Uint8Array(plain.length);
    for (let i = 0; i < plain.length; i++) bytes[i] = plain.charCodeAt(i);
    return bytes.buffer;
  };
  const failure = (name, message) => new DOMException(message ?? "The operation either timed out or was not allowed.", name);

  // Strings only between the two worlds. The extension answers { ack } at once, then the result,
  // { fallback } to let Chromium handle it, or { error }.
  function relay(request, signal) {
    return new Promise((resolve, reject) => {
      const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
      let heard = false;
      const send = () => document.dispatchEvent(new CustomEvent("vault-passkey", { detail: stringify({ id, ...request }) }));
      const end = () => {
        clearInterval(resend);
        clearTimeout(giveUp);
        document.removeEventListener("vault-passkey-answer", onAnswer);
        signal?.removeEventListener("abort", onAbort);
      };
      const onAnswer = (event) => {
        let answer;
        try { answer = parse(event.detail); } catch { return; }
        if (answer?.id !== id) return;
        if (answer.ack) {
          heard = true;
          clearInterval(resend);
          return;
        }
        end();
        resolve(answer);
      };
      const onAbort = () => {
        end();
        document.dispatchEvent(new CustomEvent("vault-passkey-cancel", { detail: stringify({ id }) }));
        reject(signal.reason ?? failure("AbortError", "The operation was aborted."));
      };
      document.addEventListener("vault-passkey-answer", onAnswer);
      signal?.addEventListener("abort", onAbort);
      const resend = setInterval(() => heard || send(), RESEND);
      const giveUp = setTimeout(() => { if (!heard) { end(); resolve({ fallback: true }); } }, HEARD_WITHIN);
      send();
    });
  }

  // Objects that behave as Chromium's own: own properties in front of the real prototypes.
  function credential(id, response, extensions, responseJSON) {
    return Object.setPrototypeOf({
      id,
      rawId: fromB64(id),
      type: "public-key",
      response,
      authenticatorAttachment: "platform",
      getClientExtensionResults: () => structuredClone(extensions),
      toJSON: () => ({ id, rawId: id, type: "public-key", authenticatorAttachment: "platform", response: structuredClone(responseJSON), clientExtensionResults: structuredClone(extensions) }),
    }, PublicKeyCredential.prototype);
  }

  function registration(answer, publicKey) {
    const transports = ["hybrid", "internal"];
    const authenticatorData = fromB64(answer.authenticatorData), key = fromB64(answer.publicKey);
    const response = Object.setPrototypeOf({
      clientDataJSON: fromB64(answer.clientDataJSON),
      attestationObject: fromB64(answer.attestationObject),
      getAuthenticatorData: () => authenticatorData.slice(0),
      getPublicKey: () => key.slice(0),
      getPublicKeyAlgorithm: () => answer.publicKeyAlgorithm,
      getTransports: () => transports.slice(),
    }, AuthenticatorAttestationResponse.prototype);
    const extensions = publicKey.extensions?.credProps ? { credProps: { rk: true } } : {};
    return credential(answer.credentialId, response, extensions, {
      clientDataJSON: answer.clientDataJSON, attestationObject: answer.attestationObject, authenticatorData: answer.authenticatorData,
      publicKey: answer.publicKey, publicKeyAlgorithm: answer.publicKeyAlgorithm, transports,
    });
  }

  function assertion(answer) {
    const response = Object.setPrototypeOf({
      clientDataJSON: fromB64(answer.clientDataJSON),
      authenticatorData: fromB64(answer.authenticatorData),
      signature: fromB64(answer.signature),
      userHandle: answer.userHandle ? fromB64(answer.userHandle) : null,
    }, AuthenticatorAssertionResponse.prototype);
    return credential(answer.credentialId, response, {}, {
      clientDataJSON: answer.clientDataJSON, authenticatorData: answer.authenticatorData, signature: answer.signature,
      ...(answer.userHandle ? { userHandle: answer.userHandle } : {}),
    });
  }

  const settle = (answer, make) => {
    if (answer.error) throw failure(answer.error, answer.message);
    return make(answer);
  };

  container.get = async function get(options) {
    const publicKey = options?.publicKey;
    if (!publicKey) return native.get.call(this, options);
    if (options.signal?.aborted) throw options.signal.reason ?? failure("AbortError", "The operation was aborted.");
    const answer = await relay({
      kind: "get",
      mediation: options.mediation ?? "optional",
      rpId: publicKey.rpId || location.hostname,
      challenge: toB64(publicKey.challenge),
      allow: (publicKey.allowCredentials ?? []).map((allowed) => toB64(allowed.id)),
    }, options.signal);
    return answer.fallback ? native.get.call(this, options) : settle(answer, assertion);
  };

  container.create = async function create(options) {
    const publicKey = options?.publicKey;
    if (!publicKey) return native.create.call(this, options);
    if (options.signal?.aborted) throw options.signal.reason ?? failure("AbortError", "The operation was aborted.");
    // The vault makes ES256 passkeys on this device; a security key or an automatic upgrade
    // after a password sign-in stays Chromium's.
    const es256 = (publicKey.pubKeyCredParams ?? []).some((param) => param.alg === -7);
    const securityKey = publicKey.authenticatorSelection?.authenticatorAttachment === "cross-platform";
    if (!es256 || securityKey || options.mediation === "conditional") return native.create.call(this, options);
    const answer = await relay({
      kind: "create",
      rpId: publicKey.rp?.id || location.hostname,
      userName: publicKey.user?.name ?? "",
      userDisplayName: publicKey.user?.displayName ?? "",
      userHandle: toB64(publicKey.user.id),
      challenge: toB64(publicKey.challenge),
      exclude: (publicKey.excludeCredentials ?? []).map((excluded) => toB64(excluded.id)),
    }, options.signal);
    return answer.fallback ? native.create.call(this, options) : settle(answer, (made) => registration(made, publicKey));
  };
  Object.defineProperty(container.get, "__vaultPasskey", { value: true });

  // Sites offer passkeys only where they're told a passkey can be made and used here.
  const PKC = globalThis.PublicKeyCredential;
  if (PKC) {
    PKC.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    PKC.isConditionalMediationAvailable = async () => true;
    const capabilities = PKC.getClientCapabilities;
    if (capabilities) {
      PKC.getClientCapabilities = async function getClientCapabilities() {
        const own = await capabilities.call(PKC).catch(() => ({}));
        return { ...own, conditionalGet: true, passkeyPlatformAuthenticator: true, userVerifyingPlatformAuthenticator: true, hybridTransport: true };
      };
    }
  }
})();
