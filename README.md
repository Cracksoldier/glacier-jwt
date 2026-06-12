# GLACIER — JWT Token Forensics

A fully static, client-side analyzer for JWT bearer tokens — signed (JWS) **and** encrypted (JWE).
No backend, no build step, no network calls with your token: everything runs in the browser via WebCrypto.

## Features

- **Decode** — color-coded token anatomy, pretty-printed header & payload, annotated registered claims
  (`exp`/`iat`/`nbf` as absolute + relative times with a live lifecycle badge).
- **Verify signatures** — HS256/384/512, RS256/384/512, PS256/384/512, ES256/384/512 with an
  HMAC secret (UTF-8 / base64 / hex), a public key PEM (SPKI), or a JWK.
- **Decrypt JWE** — key management `RSA-OAEP`, `RSA-OAEP-256`, `A128/192/256KW`, `dir`;
  content encryption `A128/192/256GCM`, `A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`;
  `zip: DEF` payloads are inflated automatically. Nested JWTs found inside a JWE can be
  analyzed in place with one click. *Caveat:* Chromium-based browsers (Chrome/Edge) reject
  192-bit AES keys in WebCrypto, so the `A192*` variants only work in Firefox — the app
  reports this clearly instead of a generic failure.
- **Security findings** — flags `alg: none`, expired / not-yet-valid tokens, missing `exp`/`aud`/`jti`,
  very long lifetimes, `jku`/`jwk`/`x5u` header injection vectors, deprecated `RSA1_5`, and
  sensitive-looking claims in plaintext payloads.
- **Sample tokens** — one-click HS256, RS256 and JWE (with nested JWT) demos including matching demo keys.

## Running

- **Locally**: just open `index.html` in any modern browser — it works from `file://`.
- **Any static host / GitHub Pages**: serve the repo as-is.

### Deploying to GitHub Pages

1. Push this repository to GitHub.
2. *Settings → Pages → Source*: select **Deploy from a branch**, branch `main`, folder `/ (root)`.
3. Done — the app is served at `https://<user>.github.io/<repo>/`.

## Privacy

Tokens and keys are processed exclusively in the browser tab (WebCrypto / `crypto.subtle`).
The app makes zero runtime network requests — fonts and Font Awesome are vendored locally,
so it also works fully offline.

## Development notes

- Plain HTML/CSS/JS, classic `<script>` tags (no ES modules — they would break on `file://`).
- `tools/gen-samples.mjs` regenerates `js/samples.js` (demo tokens + keys) and doubles as the
  self-test suite for the parser / verification / decryption modules: `node tools/gen-samples.mjs`.
