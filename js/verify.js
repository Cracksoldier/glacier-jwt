/* verify.js — JWS signature verification via WebCrypto.
   Depends on: utils.js, keys.js */
(function (root) {
  'use strict';
  const U = root.JWTUtils;
  const K = root.JWTKeys;
  const subtle = (root.crypto || {}).subtle;

  /**
   * Verify a parsed JWS against user-provided key material.
   * parsed: result of JWTParser.parse (type 'JWS').
   * Returns { valid: boolean, error?: string }.
   */
  async function verify(parsed, keyText, opts) {
    if (!parsed || parsed.type !== 'JWS') return { valid: false, error: 'Not a signed token (JWS).' };
    const alg = parsed.header && parsed.header.alg;
    if (!alg) return { valid: false, error: 'The header has no "alg" — nothing to verify.' };
    if (String(alg).toLowerCase() === 'none') {
      return { valid: false, error: 'Algorithm "none" means the token is UNSIGNED — there is no signature to verify.' };
    }
    if (!parsed.signatureBytes || !parsed.signatureBytes.length) {
      return { valid: false, error: 'The token has an empty signature segment.' };
    }
    if (!keyText || !keyText.trim()) return { valid: false, error: 'Provide a key or secret first.' };

    let imported;
    try {
      imported = await K.importVerificationKey(alg, keyText, opts);
    } catch (e) {
      return { valid: false, error: 'Key import failed: ' + (e && e.message ? e.message : e) };
    }

    try {
      const data = U.strToBytes(parsed.signingInput);
      const ok = await subtle.verify(imported.verifyParams, imported.key, parsed.signatureBytes, data);
      return ok
        ? { valid: true }
        : { valid: false, error: 'The signature does not match — wrong key, or the token was tampered with.' };
    } catch (e) {
      return { valid: false, error: 'Verification failed: ' + (e && e.message ? e.message : e) };
    }
  }

  root.JWTVerify = { verify: verify };
}(typeof window !== 'undefined' ? window : globalThis));
