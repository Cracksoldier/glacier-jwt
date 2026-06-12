/* claims.js — registered-claim knowledge base and timestamp formatting.
   Depends on: nothing */
(function (root) {
  'use strict';

  const CLAIM_INFO = {
    iss: { name: 'Issuer', icon: 'fa-building-shield', desc: 'Identifies who issued the token (usually the auth server URL).' },
    sub: { name: 'Subject', icon: 'fa-user', desc: 'The principal the token is about — typically the user ID.' },
    aud: { name: 'Audience', icon: 'fa-bullseye', desc: 'The recipient(s) the token is intended for. Consumers must reject tokens not addressed to them.' },
    exp: { name: 'Expiration', icon: 'fa-hourglass-end', desc: 'Unix timestamp after which the token must be rejected.', time: true },
    nbf: { name: 'Not before', icon: 'fa-hourglass-start', desc: 'Unix timestamp before which the token must not be accepted.', time: true },
    iat: { name: 'Issued at', icon: 'fa-stopwatch', desc: 'Unix timestamp when the token was created.', time: true },
    jti: { name: 'JWT ID', icon: 'fa-fingerprint', desc: 'Unique identifier for this token — used for replay protection / revocation.' },
    auth_time: { name: 'Auth time', icon: 'fa-clock', desc: 'When the end-user authentication actually happened (OIDC).', time: true },
    nonce: { name: 'Nonce', icon: 'fa-dice', desc: 'Value binding the token to a client session, mitigating replay attacks (OIDC).' },
    azp: { name: 'Authorized party', icon: 'fa-id-badge', desc: 'The client ID the token was issued to (OIDC).' },
    scope: { name: 'Scope', icon: 'fa-list-check', desc: 'Space-delimited OAuth scopes granted to this token.' },
    scp: { name: 'Scopes', icon: 'fa-list-check', desc: 'Granted scopes (array form, used by some providers).' },
    roles: { name: 'Roles', icon: 'fa-users-gear', desc: 'Application roles assigned to the subject.' },
    groups: { name: 'Groups', icon: 'fa-people-group', desc: 'Group memberships of the subject.' },
    email: { name: 'Email', icon: 'fa-envelope', desc: 'Email address of the subject.' },
    email_verified: { name: 'Email verified', icon: 'fa-envelope-circle-check', desc: 'Whether the issuer verified the email address.' },
    name: { name: 'Name', icon: 'fa-signature', desc: 'Display name of the subject.' },
    preferred_username: { name: 'Username', icon: 'fa-at', desc: 'Username the subject prefers to be referred to as.' },
    given_name: { name: 'Given name', icon: 'fa-signature', desc: 'First name of the subject.' },
    family_name: { name: 'Family name', icon: 'fa-signature', desc: 'Last name of the subject.' },
    sid: { name: 'Session ID', icon: 'fa-window-restore', desc: 'Identifier of the login session.' },
    client_id: { name: 'Client ID', icon: 'fa-id-badge', desc: 'OAuth client the token was issued to.' },
    tid: { name: 'Tenant ID', icon: 'fa-sitemap', desc: 'Tenant / directory identifier (e.g. Entra ID).' },
    amr: { name: 'Auth methods', icon: 'fa-key', desc: 'Authentication methods used (e.g. pwd, mfa, otp).' },
    acr: { name: 'Auth context', icon: 'fa-shield-halved', desc: 'Authentication context class — how strong the login was.' },
    at_hash: { name: 'AT hash', icon: 'fa-hashtag', desc: 'Hash binding this ID token to an access token (OIDC).' },
    cnf: { name: 'Confirmation', icon: 'fa-link', desc: 'Proof-of-possession key binding (RFC 7800).' }
  };

  const HEADER_INFO = {
    alg: { name: 'Algorithm', desc: 'Signature or key-management algorithm.' },
    enc: { name: 'Encryption', desc: 'Content-encryption algorithm (JWE).' },
    typ: { name: 'Type', desc: 'Media type of the token, usually "JWT".' },
    cty: { name: 'Content type', desc: 'Media type of the payload — "JWT" means a nested token.' },
    kid: { name: 'Key ID', desc: 'Identifier of the key used — look it up in the issuer\'s JWKS.' },
    jku: { name: 'JWK Set URL', desc: 'URL of the key set. Attacker-controlled values are a known attack vector.' },
    jwk: { name: 'Embedded JWK', desc: 'Public key embedded in the header. Must never be blindly trusted.' },
    x5u: { name: 'X.509 URL', desc: 'URL of the certificate chain.' },
    x5c: { name: 'X.509 chain', desc: 'Embedded certificate chain.' },
    x5t: { name: 'Cert thumbprint', desc: 'SHA-1 thumbprint of the signing certificate.' },
    'x5t#S256': { name: 'Cert thumbprint', desc: 'SHA-256 thumbprint of the signing certificate.' },
    zip: { name: 'Compression', desc: 'Compression applied to the plaintext before encryption (JWE).' },
    crit: { name: 'Critical', desc: 'Header parameters the consumer must understand or reject the token.' }
  };

  function describeClaim(key) { return CLAIM_INFO[key] || null; }
  function describeHeader(key) { return HEADER_INFO[key] || null; }

  function isTimeClaim(key) {
    const info = CLAIM_INFO[key];
    return !!(info && info.time);
  }

  /** Sanity window: seconds-since-epoch between 1990 and 2200. */
  function looksLikeTimestamp(value) {
    return typeof value === 'number' && isFinite(value) && value > 631152000 && value < 7258118400;
  }

  function formatTimestamp(seconds) {
    const d = new Date(seconds * 1000);
    return {
      utc: d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'),
      local: d.toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
      })
    };
  }

  function relativeTime(seconds, nowMs) {
    const now = (nowMs !== undefined ? nowMs : Date.now()) / 1000;
    let diff = seconds - now;
    const future = diff >= 0;
    diff = Math.abs(diff);
    const units = [
      [31557600, 'year'], [2629800, 'month'], [86400, 'day'],
      [3600, 'hour'], [60, 'minute'], [1, 'second']
    ];
    for (const [size, label] of units) {
      if (diff >= size || size === 1) {
        const n = Math.round(diff / size);
        const phrase = n + ' ' + label + (n === 1 ? '' : 's');
        return future ? 'in ' + phrase : phrase + ' ago';
      }
    }
  }

  /**
   * Token lifecycle status from exp / nbf.
   * Returns { state: 'active'|'expired'|'not-yet-valid'|'no-expiry', label, detail }
   */
  function timeStatus(payload, nowMs) {
    const now = (nowMs !== undefined ? nowMs : Date.now()) / 1000;
    if (!payload || typeof payload !== 'object') return null;
    const exp = payload.exp, nbf = payload.nbf;
    if (looksLikeTimestamp(nbf) && nbf > now) {
      return { state: 'not-yet-valid', label: 'Not yet valid', detail: 'Becomes valid ' + relativeTime(nbf, nowMs) + '.' };
    }
    if (looksLikeTimestamp(exp)) {
      if (exp <= now) return { state: 'expired', label: 'Expired', detail: 'Expired ' + relativeTime(exp, nowMs) + '.' };
      return { state: 'active', label: 'Active', detail: 'Expires ' + relativeTime(exp, nowMs) + '.' };
    }
    return { state: 'no-expiry', label: 'No expiry', detail: 'The token has no (usable) "exp" claim.' };
  }

  root.JWTClaims = {
    describeClaim: describeClaim,
    describeHeader: describeHeader,
    isTimeClaim: isTimeClaim,
    looksLikeTimestamp: looksLikeTimestamp,
    formatTimestamp: formatTimestamp,
    relativeTime: relativeTime,
    timeStatus: timeStatus
  };
}(typeof window !== 'undefined' ? window : globalThis));
