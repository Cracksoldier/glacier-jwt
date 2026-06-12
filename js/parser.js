/* parser.js — token cleanup, JWS/JWE structure detection, segment decoding.
   Depends on: utils.js */
(function (root) {
  'use strict';
  const U = root.JWTUtils;

  /** Strip "Bearer " prefixes, quotes, header names, and all whitespace. */
  function cleanToken(raw) {
    let t = String(raw || '').trim();
    t = t.replace(/^authorization\s*:\s*/i, '');
    t = t.replace(/^bearer\s+/i, '');
    t = t.replace(/^["'`]+|["'`,;]+$/g, '');
    t = t.replace(/\s+/g, '');
    return t;
  }

  /**
   * Parse a compact-serialization token.
   * Returns { ok, type: 'JWS'|'JWE', token, parts, header, payload?, errors, warnings, ... }
   * or { ok: false, errors } when the structure is unusable.
   */
  function parse(raw) {
    const token = cleanToken(raw);
    const result = {
      ok: false, type: null, token: token, parts: [],
      header: null, headerRaw: null, payload: null, payloadRaw: null,
      signatureBytes: null, signingInput: null,
      errors: [], warnings: []
    };
    if (!token) { result.errors.push('No token provided.'); return result; }

    const parts = token.split('.');
    result.parts = parts;

    for (let i = 0; i < parts.length; i++) {
      // Empty segments are legal only for the JWS signature (alg "none") and the
      // JWE encrypted-key (alg "dir") — validated per type below.
      if (parts[i] && !/^[A-Za-z0-9_-]+$/.test(parts[i])) {
        result.errors.push('Segment ' + (i + 1) + ' contains characters outside the base64url alphabet.');
        return result;
      }
    }

    if (parts.length === 3) result.type = 'JWS';
    else if (parts.length === 5) result.type = 'JWE';
    else {
      result.errors.push(
        'A token in compact serialization has 3 segments (signed JWS) or 5 segments (encrypted JWE) — found ' +
        parts.length + '.'
      );
      return result;
    }

    // --- protected header (segment 1, always JSON) ---
    if (!parts[0]) { result.errors.push('The protected header segment is empty.'); return result; }
    try {
      result.headerRaw = U.b64urlToString(parts[0]);
    } catch (e) {
      result.errors.push('The header segment is not valid base64url: ' + e.message);
      return result;
    }
    const headerJSON = U.tryParseJSON(result.headerRaw);
    if (!headerJSON.ok) {
      result.errors.push('The header decodes, but is not valid JSON: ' + headerJSON.error);
      return result;
    }
    result.header = headerJSON.value;
    if (typeof result.header !== 'object' || result.header === null || Array.isArray(result.header)) {
      result.errors.push('The header must be a JSON object.');
      return result;
    }

    if (result.type === 'JWS') {
      result.signingInput = parts[0] + '.' + parts[1];
      try {
        result.payloadRaw = U.b64urlToString(parts[1]);
      } catch (e) {
        result.errors.push('The payload segment is not valid base64url: ' + e.message);
        return result;
      }
      const payloadJSON = U.tryParseJSON(result.payloadRaw);
      if (payloadJSON.ok && typeof payloadJSON.value === 'object' &&
          payloadJSON.value !== null && !Array.isArray(payloadJSON.value)) {
        result.payload = payloadJSON.value;
      } else {
        result.warnings.push('The payload is not a JSON claims object — shown as raw text.');
      }
      if (parts[2]) {
        try { result.signatureBytes = U.b64urlToBytes(parts[2]); }
        catch (e) { result.errors.push('The signature segment is not valid base64url: ' + e.message); return result; }
      } else {
        result.signatureBytes = new Uint8Array(0);
        if (String(result.header.alg).toLowerCase() !== 'none') {
          result.warnings.push('The signature segment is empty, but the header algorithm is not "none".');
        }
      }
      if (!result.header.alg) result.warnings.push('The header has no "alg" field — verification is impossible.');
    } else {
      // JWE: header.encryptedKey.iv.ciphertext.tag
      const names = ['', 'encrypted key', 'initialization vector', 'ciphertext', 'authentication tag'];
      const fields = ['', 'encryptedKey', 'iv', 'ciphertext', 'tag'];
      result.jwe = { headerB64: parts[0] };
      for (let i = 1; i < 5; i++) {
        if (!parts[i] && i !== 1) { // encrypted key may be empty (alg "dir" / ECDH-ES)
          result.errors.push('The ' + names[i] + ' segment is empty.');
          return result;
        }
        try {
          result.jwe[fields[i]] = U.b64urlToBytes(parts[i] || '');
        } catch (e) {
          result.errors.push('The ' + names[i] + ' segment is not valid base64url: ' + e.message);
          return result;
        }
      }
      if (!result.header.alg) result.warnings.push('The header has no "alg" (key management algorithm).');
      if (!result.header.enc) result.warnings.push('The header has no "enc" (content encryption algorithm).');
    }

    result.ok = true;
    return result;
  }

  root.JWTParser = { cleanToken: cleanToken, parse: parse };
}(typeof window !== 'undefined' ? window : globalThis));
