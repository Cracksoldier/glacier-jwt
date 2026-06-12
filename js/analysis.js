/* analysis.js — security findings derived from a parsed token.
   Depends on: claims.js */
(function (root) {
  'use strict';
  const C = root.JWTClaims;

  const SEVERITY = { HIGH: 'high', WARN: 'warn', INFO: 'info', OK: 'ok' };

  /** Returns an array of findings: { severity, icon, title, detail }. */
  function analyze(parsed, nowMs) {
    const findings = [];
    if (!parsed || !parsed.ok) return findings;
    const header = parsed.header || {};
    const alg = String(header.alg || '');

    // --- header-level checks (both JWS and JWE) ---
    if (alg.toLowerCase() === 'none') {
      findings.push({
        severity: SEVERITY.HIGH, icon: 'fa-ban',
        title: 'Unsigned token (alg "none")',
        detail: 'This token carries no signature at all. Any consumer that accepts it can be fed arbitrary claims. "none" must be rejected by verifiers.'
      });
    } else if (parsed.type === 'JWS' && alg && parsed.signatureBytes && !parsed.signatureBytes.length) {
      findings.push({
        severity: SEVERITY.HIGH, icon: 'fa-scissors',
        title: 'Signature segment is empty',
        detail: 'The header claims ' + alg + ', but the signature was removed — a classic signature-stripping attack. Verifiers must reject this token.'
      });
    }
    if (header.jku) {
      findings.push({
        severity: SEVERITY.WARN, icon: 'fa-link',
        title: 'Header contains "jku" (JWK Set URL)',
        detail: 'If a verifier fetches keys from this URL without an allow-list, an attacker can point it at their own keys and forge tokens.'
      });
    }
    if (header.jwk) {
      findings.push({
        severity: SEVERITY.WARN, icon: 'fa-key',
        title: 'Header embeds its own public key ("jwk")',
        detail: 'A verifier that trusts the embedded key is verifying the attacker\'s signature with the attacker\'s key. The key must be matched against a trusted set.'
      });
    }
    if (header.x5u) {
      findings.push({
        severity: SEVERITY.WARN, icon: 'fa-link',
        title: 'Header contains "x5u" (certificate URL)',
        detail: 'Like "jku", attacker-controlled certificate URLs are a known token-forgery vector if not allow-listed.'
      });
    }
    if (header.crit) {
      findings.push({
        severity: SEVERITY.INFO, icon: 'fa-circle-exclamation',
        title: 'Header declares critical extensions ("crit")',
        detail: 'Consumers that do not understand ' + JSON.stringify(header.crit) + ' must reject this token.'
      });
    }

    if (parsed.type === 'JWE') {
      findings.push({
        severity: SEVERITY.INFO, icon: 'fa-lock',
        title: 'Encrypted token (JWE)',
        detail: 'Claims are confidential: only the holder of the decryption key can read them. Key management: ' +
          (header.alg || '?') + ', content encryption: ' + (header.enc || '?') + '.'
      });
      if (header.alg === 'RSA1_5') {
        findings.push({
          severity: SEVERITY.HIGH, icon: 'fa-triangle-exclamation',
          title: 'Deprecated key encryption (RSA1_5)',
          detail: 'RSAES-PKCS1-v1_5 is vulnerable to padding-oracle (Bleichenbacher) attacks and is deprecated. Use RSA-OAEP-256.'
        });
      }
      if (header.zip === 'DEF') {
        findings.push({
          severity: SEVERITY.INFO, icon: 'fa-file-zipper',
          title: 'Compressed plaintext (zip "DEF")',
          detail: 'Compression before encryption can leak information about the plaintext (CRIME-style) when attacker-controlled data is included.'
        });
      }
      return findings; // claims are not visible without decryption
    }

    // --- JWS-specific ---
    if (/^HS/i.test(alg)) {
      findings.push({
        severity: SEVERITY.INFO, icon: 'fa-key',
        title: 'Symmetric signature (' + alg + ')',
        detail: 'Anyone who can verify this token can also mint new ones — the same secret signs and verifies. Beware of RS→HS algorithm-confusion attacks on misconfigured verifiers.'
      });
    }
    if (parsed.payload === null && parsed.payloadRaw !== null) {
      findings.push({
        severity: SEVERITY.INFO, icon: 'fa-file-circle-question',
        title: 'Non-JSON payload',
        detail: 'The payload is not a JSON claims object. This may be a detached/raw-content JWS rather than a JWT.'
      });
      return findings;
    }

    const payload = parsed.payload || {};
    const now = (nowMs !== undefined ? nowMs : Date.now()) / 1000;

    const status = C.timeStatus(payload, nowMs);
    if (status) {
      if (status.state === 'expired') {
        findings.push({ severity: SEVERITY.WARN, icon: 'fa-hourglass-end', title: 'Token is expired', detail: status.detail + ' Verifiers must reject it.' });
      } else if (status.state === 'not-yet-valid') {
        findings.push({ severity: SEVERITY.WARN, icon: 'fa-hourglass-start', title: 'Token is not valid yet', detail: status.detail });
      } else if (status.state === 'no-expiry') {
        findings.push({ severity: SEVERITY.WARN, icon: 'fa-infinity', title: 'No expiration claim', detail: 'Without "exp" the token never expires on its own — if leaked, it stays usable until actively revoked.' });
      } else {
        findings.push({ severity: SEVERITY.OK, icon: 'fa-circle-check', title: 'Token is currently valid (time-wise)', detail: status.detail });
      }
    }

    for (const key of ['exp', 'nbf', 'iat']) {
      if (C.isNumericDate(payload[key]) && payload[key] > 1e12) {
        findings.push({
          severity: SEVERITY.WARN, icon: 'fa-stopwatch',
          title: '"' + key + '" looks like milliseconds',
          detail: 'NumericDate values are seconds since the epoch (RFC 7519). ' + payload[key] + ' as seconds is year ' +
            (isFinite(new Date(payload[key] * 1000).getTime()) ? new Date(payload[key] * 1000).getUTCFullYear() : '> 275760') +
            ' — the issuer probably emitted milliseconds.'
        });
      }
    }

    if (C.isNumericDate(payload.exp) && C.isNumericDate(payload.iat)) {
      const lifetime = payload.exp - payload.iat;
      if (lifetime > 86400 * 30) {
        findings.push({
          severity: SEVERITY.WARN, icon: 'fa-calendar-days',
          title: 'Very long lifetime (' + Math.round(lifetime / 86400) + ' days)',
          detail: 'Access tokens should live minutes to hours. Long-lived tokens dramatically increase the impact of a leak.'
        });
      }
    }
    if (C.isNumericDate(payload.iat) && payload.iat > now + 300) {
      findings.push({
        severity: SEVERITY.WARN, icon: 'fa-clock-rotate-left',
        title: '"iat" lies in the future',
        detail: 'The token claims to be issued ' + C.relativeTime(payload.iat, nowMs) + ' — issuer/consumer clocks may be skewed, or the token is forged.'
      });
    }
    if (!payload.iss) {
      findings.push({ severity: SEVERITY.INFO, icon: 'fa-building-circle-xmark', title: 'No issuer ("iss") claim', detail: 'Consumers cannot pin the token to a trusted issuer.' });
    }
    if (!payload.aud) {
      findings.push({ severity: SEVERITY.INFO, icon: 'fa-bullseye', title: 'No audience ("aud") claim', detail: 'Without "aud" the token can potentially be replayed against other services of the same issuer.' });
    }
    if (!payload.jti) {
      findings.push({ severity: SEVERITY.INFO, icon: 'fa-fingerprint', title: 'No token ID ("jti") claim', detail: 'Individual tokens cannot be revoked or tracked for replay without a unique ID.' });
    }

    const SENSITIVE = /password|passwd|secret|ssn|credit|iban|api[_-]?key|private/i;
    for (const key of Object.keys(payload)) {
      if (SENSITIVE.test(key)) {
        findings.push({
          severity: SEVERITY.HIGH, icon: 'fa-eye',
          title: 'Possibly sensitive claim "' + key + '" in plaintext',
          detail: 'JWS payloads are only base64url-encoded, NOT encrypted — anyone holding the token can read this value.'
        });
      }
    }

    return findings;
  }

  root.JWTAnalysis = { analyze: analyze, SEVERITY: SEVERITY };
}(typeof window !== 'undefined' ? window : globalThis));
