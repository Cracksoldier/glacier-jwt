/* utils.js — encoding helpers + JSON rendering. No dependencies. */
(function (root) {
  'use strict';

  /** Decode base64url to a Uint8Array. Tolerates interior whitespace (wrapped keys). */
  function b64urlToBytes(input) {
    let b64 = String(input).replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    const pad = b64.length % 4;
    if (pad === 1) throw new Error('Invalid base64url length');
    if (pad) b64 += '='.repeat(4 - pad);
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  /** Decode standard base64 (also tolerates base64url and missing padding). */
  function b64ToBytes(input) {
    return b64urlToBytes(String(input).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'));
  }

  function bytesToB64url(bytes) {
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlToString(input) {
    return new TextDecoder('utf-8', { fatal: false }).decode(b64urlToBytes(input));
  }

  function strToBytes(str) {
    return new TextEncoder().encode(str);
  }

  function bytesToStr(bytes) {
    return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  }

  function hexToBytes(hex) {
    const clean = hex.replace(/^0x/i, '').replace(/[\s:]/g, '');
    if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2) throw new Error('Invalid hex string');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    return bytes;
  }

  function concatBytes() {
    let total = 0;
    for (const a of arguments) total += a.length;
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arguments) { out.set(a, off); off += a.length; }
    return out;
  }

  function tryParseJSON(text) {
    try { return { ok: true, value: JSON.parse(text) }; }
    catch (e) { return { ok: false, error: e.message }; }
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /** Pretty-print a JS value as syntax-highlighted JSON HTML.
      Tokenizes the raw JSON first, escaping each piece on emission — escaping
      first would destroy the quotes the string rule matches on. */
  function highlightJSON(value, indent) {
    const json = JSON.stringify(value, null, indent || 2);
    if (json === undefined) return '';
    const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(?:true|false)\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
    let out = '', last = 0, m;
    while ((m = re.exec(json)) !== null) {
      out += escapeHtml(json.slice(last, m.index));
      const tok = m[0];
      if (m[1] !== undefined) {
        out += m[2] !== undefined
          ? '<span class="j-key">' + escapeHtml(m[1]) + '</span>' + m[2]
          : '<span class="j-str">' + escapeHtml(m[1]) + '</span>';
      } else if (tok === 'true' || tok === 'false') {
        out += '<span class="j-bool">' + tok + '</span>';
      } else if (tok === 'null') {
        out += '<span class="j-null">null</span>';
      } else {
        out += '<span class="j-num">' + tok + '</span>';
      }
      last = m.index + tok.length;
    }
    return out + escapeHtml(json.slice(last));
  }

  root.JWTUtils = {
    b64urlToBytes: b64urlToBytes,
    b64ToBytes: b64ToBytes,
    bytesToB64url: bytesToB64url,
    b64urlToString: b64urlToString,
    strToBytes: strToBytes,
    bytesToStr: bytesToStr,
    hexToBytes: hexToBytes,
    concatBytes: concatBytes,
    tryParseJSON: tryParseJSON,
    escapeHtml: escapeHtml,
    highlightJSON: highlightJSON
  };
}(typeof window !== 'undefined' ? window : globalThis));
