/* decrypt.js — JWE decryption via WebCrypto.
   Key management: RSA-OAEP, RSA-OAEP-256, A128/192/256KW, dir.
   Content encryption: A128/192/256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512.
   Depends on: utils.js, keys.js */
(function (root) {
  'use strict';
  const U = root.JWTUtils;
  const K = root.JWTKeys;
  const subtle = (root.crypto || {}).subtle;

  const CBC_PARAMS = {
    'A128CBC-HS256': { keyLen: 32, hash: 'SHA-256', tagLen: 16 },
    'A192CBC-HS384': { keyLen: 48, hash: 'SHA-384', tagLen: 24 },
    'A256CBC-HS512': { keyLen: 64, hash: 'SHA-512', tagLen: 32 }
  };
  const GCM_KEYLEN = { A128GCM: 16, A192GCM: 24, A256GCM: 32 };

  /** Obtain the raw Content Encryption Key bytes. */
  async function obtainCEK(alg, imported, encryptedKey) {
    if (imported.kind === 'dir') {
      if (encryptedKey.length) {
        throw new Error('alg "dir" must have an empty encrypted-key segment, but this token has one.');
      }
      return imported.key;
    }
    if (imported.kind === 'rsa') {
      if (!encryptedKey.length) throw new Error('The encrypted-key segment is empty, but alg is ' + alg + '.');
      const cek = await subtle.decrypt({ name: 'RSA-OAEP' }, imported.key, encryptedKey);
      return new Uint8Array(cek);
    }
    if (imported.kind === 'aeskw') {
      // AES-KW has no subtle.decrypt — unwrap into an extractable throwaway key, then export.
      const tmp = await subtle.unwrapKey(
        'raw', encryptedKey, imported.key, { name: 'AES-KW' },
        { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']
      );
      return new Uint8Array(await subtle.exportKey('raw', tmp));
    }
    throw new Error('Unsupported key kind.');
  }

  /** 64-bit big-endian bit length of the AAD, per RFC 7516 §5.2. */
  function aadBitLength(aadBytes) {
    const out = new Uint8Array(8);
    let bits = aadBytes.length * 8;
    for (let i = 7; i >= 0; i--) { out[i] = bits & 0xff; bits = Math.floor(bits / 256); }
    return out;
  }

  async function decryptContent(enc, cek, jwe) {
    const aad = U.strToBytes(jwe.headerB64); // ASCII of the b64url protected header

    if (GCM_KEYLEN[enc]) {
      if (cek.length !== GCM_KEYLEN[enc]) {
        throw new Error(enc + ' needs a ' + GCM_KEYLEN[enc] + '-byte CEK, got ' + cek.length + ' — the key probably does not match this token.');
      }
      if (jwe.iv.length !== 12) throw new Error(enc + ' requires a 96-bit IV, got ' + (jwe.iv.length * 8) + ' bits.');
      const key = await subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['decrypt']);
      try {
        const plain = await subtle.decrypt(
          { name: 'AES-GCM', iv: jwe.iv, additionalData: aad, tagLength: 128 },
          key, U.concatBytes(jwe.ciphertext, jwe.tag)
        );
        return new Uint8Array(plain);
      } catch (e) {
        throw new Error('Authenticated decryption failed — wrong key, or the token was modified.');
      }
    }

    const cbc = CBC_PARAMS[enc];
    if (cbc) {
      if (cek.length !== cbc.keyLen) {
        throw new Error(enc + ' needs a ' + cbc.keyLen + '-byte CEK, got ' + cek.length + ' — the key probably does not match this token.');
      }
      if (jwe.iv.length !== 16) throw new Error(enc + ' requires a 128-bit IV.');
      const macKeyBytes = cek.slice(0, cbc.keyLen / 2);
      const encKeyBytes = cek.slice(cbc.keyLen / 2);

      const macKey = await subtle.importKey('raw', macKeyBytes, { name: 'HMAC', hash: cbc.hash }, false, ['sign']);
      const macInput = U.concatBytes(aad, jwe.iv, jwe.ciphertext, aadBitLength(aad));
      const mac = new Uint8Array(await subtle.sign('HMAC', macKey, macInput));
      const expectedTag = mac.slice(0, cbc.tagLen);
      if (jwe.tag.length !== cbc.tagLen) throw new Error('Authentication tag has the wrong length for ' + enc + '.');
      let diff = 0;
      for (let i = 0; i < cbc.tagLen; i++) diff |= expectedTag[i] ^ jwe.tag[i];
      if (diff !== 0) throw new Error('Authentication tag mismatch — wrong key, or the token was modified.');

      const encKey = await subtle.importKey('raw', encKeyBytes, { name: 'AES-CBC' }, false, ['decrypt']);
      try {
        const plain = await subtle.decrypt({ name: 'AES-CBC', iv: jwe.iv }, encKey, jwe.ciphertext);
        return new Uint8Array(plain);
      } catch (e) {
        throw new Error('AES-CBC decryption failed (bad padding) — wrong key, or the token was modified.');
      }
    }

    throw new Error('Unsupported content-encryption algorithm "' + enc + '". Supported: A128/192/256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512.');
  }

  async function inflateRaw(bytes) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error('The payload is DEFLATE-compressed (zip: "DEF") and this browser has no DecompressionStream support.');
    }
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  /** Heuristic: does the plaintext look like a nested compact JWS/JWE? */
  function looksLikeToken(text) {
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*(\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)?$/.test(text.trim());
  }

  /**
   * Decrypt a parsed JWE with user-provided key material.
   * Returns { ok, plaintext?, plaintextBytes?, isNested?, json?, error? }.
   */
  async function decrypt(parsed, keyText, opts) {
    if (!parsed || parsed.type !== 'JWE') return { ok: false, error: 'Not an encrypted token (JWE).' };
    const alg = parsed.header.alg, enc = parsed.header.enc;
    if (!alg || !enc) return { ok: false, error: 'The protected header must contain both "alg" and "enc".' };
    if (!keyText || !keyText.trim()) return { ok: false, error: 'Provide the decryption key first.' };

    try {
      const imported = await K.importDecryptionKey(alg, keyText, opts);
      const cek = await obtainCEK(alg, imported, parsed.jwe.encryptedKey);
      let plainBytes = await decryptContent(enc, cek, parsed.jwe);
      if (parsed.header.zip === 'DEF') plainBytes = await inflateRaw(plainBytes);

      const plaintext = U.bytesToStr(plainBytes);
      const out = { ok: true, plaintext: plaintext, plaintextBytes: plainBytes };
      const cty = String(parsed.header.cty || '').toUpperCase();
      out.isNested = cty === 'JWT' || cty === 'APPLICATION/JWT' || looksLikeToken(plaintext);
      if (!out.isNested) {
        const json = U.tryParseJSON(plaintext);
        if (json.ok) out.json = json.value;
      }
      return out;
    } catch (e) {
      return { ok: false, error: e && e.message ? e.message : String(e) };
    }
  }

  root.JWTDecrypt = { decrypt: decrypt, looksLikeToken: looksLikeToken };
}(typeof window !== 'undefined' ? window : globalThis));
