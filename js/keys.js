/* keys.js — turn user key material (secret / PEM / JWK / raw) into CryptoKeys.
   Depends on: utils.js */
(function (root) {
  'use strict';
  const U = root.JWTUtils;
  const subtle = (root.crypto || {}).subtle;

  const HASH_BY_ALG = {
    HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512',
    RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512',
    PS256: 'SHA-256', PS384: 'SHA-384', PS512: 'SHA-512',
    ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512'
  };
  const CURVE_BY_ALG = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };

  /* Single registry of supported JWE key-management algorithms — drives the
     import logic, the "Supported: ..." error text, and the UI hints. */
  const KEY_MGMT = {
    'RSA-OAEP': { kind: 'rsa', hash: 'SHA-1' },
    'RSA-OAEP-256': { kind: 'rsa', hash: 'SHA-256' },
    A128KW: { kind: 'aeskw', keyBytes: 16 },
    A192KW: { kind: 'aeskw', keyBytes: 24 },
    A256KW: { kind: 'aeskw', keyBytes: 32 },
    dir: { kind: 'dir' }
  };
  const SUPPORTED_KEY_MGMT = Object.keys(KEY_MGMT).join(', ');

  function keyMgmtKind(alg) {
    return KEY_MGMT[alg] ? KEY_MGMT[alg].kind : null;
  }

  /** Chromium's WebCrypto rejects 192-bit AES keys outright — name the real cause. */
  function aesImportError(e, keyByteLength) {
    if (keyByteLength === 24) {
      return new Error('192-bit AES keys are not supported by Chromium-based browsers (Chrome/Edge) — try Firefox.');
    }
    return e;
  }

  function requireSubtle() {
    if (!subtle) {
      throw new Error('WebCrypto is unavailable. Open this page in a modern browser (https:// or file:// both work).');
    }
  }

  /** Extract DER bytes from a PEM block. Returns { der, label } or null. */
  function pemToDer(pem) {
    const match = /-----BEGIN ([^-]+)-----([\s\S]+?)-----END \1-----/.exec(pem);
    if (!match) return null;
    return { label: match[1].trim(), der: U.b64ToBytes(match[2].replace(/\s+/g, '')) };
  }

  function looksLikePem(text) { return /-----BEGIN [^-]+-----/.test(text); }

  function looksLikeJwk(text) {
    const parsed = U.tryParseJSON(text.trim());
    return parsed.ok && parsed.value && typeof parsed.value === 'object' && 'kty' in parsed.value;
  }

  /** Auto-detect the key input format: 'pem' | 'jwk' | 'secret'. */
  function detectFormat(text) {
    if (looksLikePem(text)) return 'pem';
    if (looksLikeJwk(text)) return 'jwk';
    return 'secret';
  }

  /** Decode a raw symmetric key: utf-8 secret, or base64/base64url/hex encoded bytes. */
  function secretToBytes(secret, encoding) {
    switch (encoding) {
      case 'base64': return U.b64ToBytes(secret.trim());
      case 'hex': return U.hexToBytes(secret.trim());
      default: return U.strToBytes(secret);
    }
  }

  function algParamsForVerify(alg) {
    const hash = HASH_BY_ALG[alg];
    if (!hash) throw new Error('Unsupported signature algorithm "' + alg + '".');
    if (alg.startsWith('HS')) return { import: { name: 'HMAC', hash: hash }, verify: { name: 'HMAC' } };
    if (alg.startsWith('RS')) return { import: { name: 'RSASSA-PKCS1-v1_5', hash: hash }, verify: { name: 'RSASSA-PKCS1-v1_5' } };
    if (alg.startsWith('PS')) {
      const saltLength = parseInt(alg.slice(2), 10) / 8;
      return { import: { name: 'RSA-PSS', hash: hash }, verify: { name: 'RSA-PSS', saltLength: saltLength } };
    }
    return {
      import: { name: 'ECDSA', namedCurve: CURVE_BY_ALG[alg] },
      verify: { name: 'ECDSA', hash: hash }
    };
  }

  /**
   * Import key material for verifying a JWS with the given alg.
   * keyText: the raw user input. opts.secretEncoding: 'utf8'|'base64'|'hex'.
   * Returns { key: CryptoKey, verifyParams }.
   */
  async function importVerificationKey(alg, keyText, opts) {
    requireSubtle();
    opts = opts || {};
    const params = algParamsForVerify(alg);
    const format = opts.format && opts.format !== 'auto' ? opts.format : detectFormat(keyText);

    if (alg.startsWith('HS')) {
      if (format !== 'secret' && format !== 'jwk') {
        throw new Error('HS* algorithms use a shared secret, not a PEM key.');
      }
      if (format === 'jwk') {
        const jwk = JSON.parse(keyText.trim());
        if (jwk.kty !== 'oct' || !jwk.k) throw new Error('An HMAC JWK must have kty "oct" and a "k" member.');
        delete jwk.alg; delete jwk.use; delete jwk.key_ops; // the JWS header decides
        const key = await subtle.importKey('jwk', jwk, params.import, false, ['verify']);
        return { key: key, verifyParams: params.verify };
      }
      const bytes = secretToBytes(keyText, opts.secretEncoding || 'utf8');
      if (!bytes.length) throw new Error('The secret is empty.');
      const key = await subtle.importKey('raw', bytes, params.import, false, ['verify']);
      return { key: key, verifyParams: params.verify };
    }

    // Asymmetric: need the PUBLIC key.
    if (format === 'jwk') {
      const jwk = JSON.parse(keyText.trim());
      delete jwk.alg; // avoid alg-mismatch rejections; the JWS header decides
      delete jwk.use; delete jwk.key_ops;
      if (jwk.d) throw new Error('That JWK is a private key — paste the public key for verification.');
      const key = await subtle.importKey('jwk', jwk, params.import, false, ['verify']);
      return { key: key, verifyParams: params.verify };
    }
    if (format === 'pem') {
      const block = pemToDer(keyText);
      if (!block) throw new Error('Could not find a PEM block (-----BEGIN ... -----END ...).');
      if (/PRIVATE KEY/.test(block.label)) throw new Error('That is a private key — paste the PUBLIC key for verification.');
      if (block.label === 'CERTIFICATE') throw new Error('Certificates are not supported — extract the public key (SPKI PEM) first.');
      const key = await subtle.importKey('spki', block.der, params.import, false, ['verify']);
      return { key: key, verifyParams: params.verify };
    }
    throw new Error(alg + ' needs a public key (PEM "BEGIN PUBLIC KEY" or JWK) — a plain secret cannot verify it.');
  }

  /**
   * Import key material for decrypting a JWE.
   * alg: key-management algorithm from the protected header.
   * Returns { kind: 'rsa'|'aeskw'|'dir', key } where key is a CryptoKey (rsa/aeskw) or raw bytes (dir).
   */
  async function importDecryptionKey(alg, keyText, opts) {
    requireSubtle();
    opts = opts || {};
    const spec = KEY_MGMT[alg];
    if (!spec) {
      throw new Error('Unsupported key-management algorithm "' + alg + '". Supported: ' + SUPPORTED_KEY_MGMT + '.');
    }
    const format = opts.format && opts.format !== 'auto' ? opts.format : detectFormat(keyText);

    if (spec.kind === 'rsa') {
      const importParams = { name: 'RSA-OAEP', hash: spec.hash };
      if (format === 'jwk') {
        const jwk = JSON.parse(keyText.trim());
        delete jwk.alg; delete jwk.use; delete jwk.key_ops;
        if (!jwk.d) throw new Error('Decryption needs the RSA PRIVATE key (the JWK is missing "d").');
        const key = await subtle.importKey('jwk', jwk, importParams, false, ['decrypt']);
        return { kind: 'rsa', key: key };
      }
      if (format === 'pem') {
        const block = pemToDer(keyText);
        if (!block) throw new Error('Could not find a PEM block.');
        if (block.label === 'RSA PRIVATE KEY') {
          throw new Error('PKCS#1 keys ("BEGIN RSA PRIVATE KEY") are not supported by WebCrypto — convert to PKCS#8:\nopenssl pkcs8 -topk8 -nocrypt -in key.pem');
        }
        if (block.label !== 'PRIVATE KEY') throw new Error('Decryption needs a private key ("BEGIN PRIVATE KEY"), got "' + block.label + '".');
        const key = await subtle.importKey('pkcs8', block.der, importParams, false, ['decrypt']);
        return { kind: 'rsa', key: key };
      }
      throw new Error(alg + ' needs the recipient\'s RSA private key (PKCS#8 PEM or JWK).');
    }

    // symmetric: aeskw or dir
    let bytes;
    if (format === 'jwk') {
      const jwk = JSON.parse(keyText.trim());
      if (jwk.kty !== 'oct' || !jwk.k) throw new Error('A symmetric JWK must have kty "oct" and a "k" member.');
      bytes = U.b64urlToBytes(jwk.k);
    } else if (format === 'pem') {
      throw new Error(alg + ' uses a symmetric key — paste it as base64/hex/JWK, not PEM.');
    } else {
      bytes = secretToBytes(keyText, opts.secretEncoding || 'base64');
    }
    if (spec.kind === 'dir') return { kind: 'dir', key: bytes };
    if (bytes.length !== spec.keyBytes) {
      throw new Error(alg + ' needs a ' + spec.keyBytes + '-byte key, got ' + bytes.length + ' bytes.');
    }
    let key;
    try {
      key = await subtle.importKey('raw', bytes, { name: 'AES-KW' }, false, ['unwrapKey']);
    } catch (e) {
      throw aesImportError(e, bytes.length);
    }
    return { kind: 'aeskw', key: key };
  }

  root.JWTKeys = {
    importVerificationKey: importVerificationKey,
    importDecryptionKey: importDecryptionKey,
    keyMgmtKind: keyMgmtKind,
    aesImportError: aesImportError
  };
}(typeof window !== 'undefined' ? window : globalThis));
