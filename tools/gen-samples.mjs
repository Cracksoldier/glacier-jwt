/* One-off generator: builds sample tokens + demo keys and writes js/samples.js.
   Also serves as an integration test for parser/verify/decrypt (they attach to globalThis in Node).
   Run: node tools/gen-samples.mjs */
import { webcrypto } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const subtle = webcrypto.subtle;
const root = join(dirname(fileURLToPath(import.meta.url)), '..');

// load the browser modules (classic scripts -> globalThis)
for (const f of ['utils.js', 'parser.js', 'claims.js', 'keys.js', 'verify.js', 'decrypt.js', 'analysis.js']) {
  await import('file://' + join(root, 'js', f).replace(/\\/g, '/'));
}
const { JWTUtils: U, JWTParser, JWTVerify, JWTDecrypt } = globalThis;

const b64url = (bytes) => U.bytesToB64url(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
const enc = (obj) => b64url(new TextEncoder().encode(JSON.stringify(obj)));

const NOW = Math.floor(Date.now() / 1000);
const YEAR = 31536000;

// ---------- HS256 ----------
const HS_SECRET = 'glacier-demo-secret';
async function signHS256(header, payload, secret) {
  const input = enc(header) + '.' + enc(payload);
  const key = await subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await subtle.sign('HMAC', key, new TextEncoder().encode(input));
  return input + '.' + b64url(sig);
}
const hsToken = await signHS256(
  { alg: 'HS256', typ: 'JWT' },
  {
    iss: 'https://auth.glacier.example', sub: 'usr_8842',
    aud: 'api://frost-gateway', name: 'Erika Mustermann',
    email: 'erika@glacier.example', scope: 'profile token:read',
    roles: ['analyst'], jti: 'f3b1c2d4-demo',
    iat: NOW, nbf: NOW, exp: NOW + 4 * YEAR
  },
  HS_SECRET
);

// ---------- RS256 ----------
const rsaPair = await subtle.generateKey(
  { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true, ['sign', 'verify']
);
function toPem(der, label) {
  const b64 = Buffer.from(der).toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${b64}\n-----END ${label}-----`;
}
const rsPubPem = toPem(await subtle.exportKey('spki', rsaPair.publicKey), 'PUBLIC KEY');
async function signRS256(header, payload) {
  const input = enc(header) + '.' + enc(payload);
  const sig = await subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, rsaPair.privateKey, new TextEncoder().encode(input));
  return input + '.' + b64url(sig);
}
const rsToken = await signRS256(
  { alg: 'RS256', typ: 'JWT', kid: 'glacier-2026-rsa' },
  {
    iss: 'https://auth.glacier.example', sub: 'svc_pipeline',
    aud: ['api://frost-gateway', 'api://icefield'],
    scope: 'pipeline:run artifacts:write', client_id: 'frost-ci',
    jti: '7a1d9e30-demo', iat: NOW, exp: NOW + 4 * YEAR
  }
);

// ---------- JWE: RSA-OAEP-256 + A256GCM, nested HS256 JWT ----------
const jwePair = await subtle.generateKey(
  { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
  true, ['encrypt', 'decrypt']
);
const jwePrivPem = toPem(await subtle.exportKey('pkcs8', jwePair.privateKey), 'PRIVATE KEY');

const nestedJws = await signHS256(
  { alg: 'HS256', typ: 'JWT' },
  {
    iss: 'https://auth.glacier.example', sub: 'usr_8842',
    aud: 'api://vault', acr: 'urn:mfa', amr: ['pwd', 'otp'],
    clearance: 'restricted', jti: '0cc1e5b2-demo',
    iat: NOW, exp: NOW + 4 * YEAR
  },
  HS_SECRET
);

async function encryptJWE(headerObj, plaintextStr) {
  const headerB64 = enc(headerObj);
  const cek = webcrypto.getRandomValues(new Uint8Array(32));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const encKeyBytes = await subtle.encrypt({ name: 'RSA-OAEP' }, jwePair.publicKey, cek);
  const gcmKey = await subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const sealed = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(headerB64), tagLength: 128 },
    gcmKey, new TextEncoder().encode(plaintextStr)
  ));
  const ct = sealed.slice(0, sealed.length - 16);
  const tag = sealed.slice(sealed.length - 16);
  return [headerB64, b64url(encKeyBytes), b64url(iv), b64url(ct), b64url(tag)].join('.');
}
const jweToken = await encryptJWE({ alg: 'RSA-OAEP-256', enc: 'A256GCM', cty: 'JWT', kid: 'glacier-2026-enc' }, nestedJws);

// ---------- self-test with the app's own modules ----------
let failures = 0;
const check = (label, cond) => { console.log((cond ? 'PASS' : 'FAIL') + '  ' + label); if (!cond) failures++; };

const pHS = JWTParser.parse('Bearer ' + hsToken);
check('HS256 parses as JWS', pHS.ok && pHS.type === 'JWS' && pHS.header.alg === 'HS256');
check('HS256 verifies with correct secret', (await JWTVerify.verify(pHS, HS_SECRET)).valid === true);
check('HS256 rejects wrong secret', (await JWTVerify.verify(pHS, 'wrong')).valid === false);

const tampered = JWTParser.parse(hsToken.replace(/\.([^.]+)\./, (m, p) => '.' + b64url(new TextEncoder().encode(JSON.stringify({ hacked: true }))) + '.'));
check('Tampered HS256 fails verification', (await JWTVerify.verify(tampered, HS_SECRET)).valid === false);

const pRS = JWTParser.parse(rsToken);
check('RS256 parses as JWS', pRS.ok && pRS.type === 'JWS');
check('RS256 verifies with public PEM', (await JWTVerify.verify(pRS, rsPubPem)).valid === true);
const rsPubJwk = JSON.stringify(await subtle.exportKey('jwk', rsaPair.publicKey));
check('RS256 verifies with public JWK', (await JWTVerify.verify(pRS, rsPubJwk)).valid === true);

const pJWE = JWTParser.parse(jweToken);
check('JWE parses with 5 parts', pJWE.ok && pJWE.type === 'JWE');
const dec = await JWTDecrypt.decrypt(pJWE, jwePrivPem);
check('JWE decrypts with private PEM', dec.ok === true);
check('JWE plaintext is the nested JWS', dec.ok && dec.plaintext === nestedJws && dec.isNested === true);
const decBad = await JWTDecrypt.decrypt(pJWE, rsPubPem);
check('JWE rejects wrong key', decBad.ok === false);

// dir + A128CBC-HS256 round-trip (exercises the manual CBC-HMAC path)
{
  const cek = webcrypto.getRandomValues(new Uint8Array(32));
  const headerObj = { alg: 'dir', enc: 'A128CBC-HS256' };
  const headerB64 = enc(headerObj);
  const aad = new TextEncoder().encode(headerB64);
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const plaintext = new TextEncoder().encode('{"msg":"direct cbc"}');
  const encKey = await subtle.importKey('raw', cek.slice(16), { name: 'AES-CBC' }, false, ['encrypt']);
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-CBC', iv }, encKey, plaintext));
  const macKey = await subtle.importKey('raw', cek.slice(0, 16), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const al = new Uint8Array(8); new DataView(al.buffer).setBigUint64(0, BigInt(aad.length * 8));
  const macInput = new Uint8Array([...aad, ...iv, ...ct, ...al]);
  const tag = new Uint8Array(await subtle.sign('HMAC', macKey, macInput)).slice(0, 16);
  const dirToken = [headerB64, '', b64url(iv), b64url(ct), b64url(tag)].join('.');
  const pDir = JWTParser.parse(dirToken);
  const decDir = await JWTDecrypt.decrypt(pDir, b64url(cek), { secretEncoding: 'base64' });
  check('dir + A128CBC-HS256 decrypts', decDir.ok === true && decDir.plaintext === '{"msg":"direct cbc"}');
  const decDirBad = await JWTDecrypt.decrypt(pDir, b64url(webcrypto.getRandomValues(new Uint8Array(32))), { secretEncoding: 'base64' });
  check('dir CBC rejects wrong key', decDirBad.ok === false);
}

// A256KW + A128GCM round-trip (exercises the AES-KW unwrap path)
{
  const kek = webcrypto.getRandomValues(new Uint8Array(32));
  const cek = webcrypto.getRandomValues(new Uint8Array(16));
  const headerObj = { alg: 'A256KW', enc: 'A128GCM' };
  const headerB64 = enc(headerObj);
  const kekKey = await subtle.importKey('raw', kek, { name: 'AES-KW' }, false, ['wrapKey']);
  const cekAsKey = await subtle.importKey('raw', cek, { name: 'AES-GCM' }, true, ['encrypt']);
  const wrapped = new Uint8Array(await subtle.wrapKey('raw', cekAsKey, kekKey, { name: 'AES-KW' }));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const sealed = new Uint8Array(await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(headerB64), tagLength: 128 },
    cekAsKey, new TextEncoder().encode('kw works')
  ));
  const kwToken = [headerB64, b64url(wrapped), b64url(iv), b64url(sealed.slice(0, -16)), b64url(sealed.slice(-16))].join('.');
  const pKw = JWTParser.parse(kwToken);
  const decKw = await JWTDecrypt.decrypt(pKw, b64url(kek), { secretEncoding: 'base64' });
  check('A256KW + A128GCM decrypts', decKw.ok === true && decKw.plaintext === 'kw works');
}

// RFC 7515 appendix A.1 HS256 test vector
{
  const rfcToken = 'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const rfcJwk = '{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}';
  const pRfc = JWTParser.parse(rfcToken);
  check('RFC 7515 A.1 token verifies via oct JWK', (await JWTVerify.verify(pRfc, rfcJwk)).valid === true);
}

// negative structural cases
check('Garbage input rejected', JWTParser.parse('not a token!!').ok === false);
check('4-part token rejected', JWTParser.parse('a.b.c.d').ok === false);

if (failures) { console.error('\n' + failures + ' test(s) FAILED'); process.exit(1); }
console.log('\nAll self-tests passed.');

// ---------- emit js/samples.js ----------
const samples = {
  hs256: {
    label: 'HS256 signed', icon: 'fa-signature',
    token: hsToken,
    keyHint: 'Secret (UTF-8): ' + HS_SECRET,
    key: HS_SECRET, keyFormat: 'secret', secretEncoding: 'utf8'
  },
  rs256: {
    label: 'RS256 signed', icon: 'fa-certificate',
    token: rsToken,
    keyHint: 'RSA public key (SPKI PEM)',
    key: rsPubPem, keyFormat: 'pem'
  },
  jwe: {
    label: 'JWE encrypted', icon: 'fa-lock',
    token: jweToken,
    keyHint: 'RSA private key (PKCS#8 PEM) — contains a nested HS256 JWT (secret: ' + HS_SECRET + ')',
    key: jwePrivPem, keyFormat: 'pem',
    nestedKey: HS_SECRET
  }
};
const banner = '/* samples.js — demo tokens + matching demo keys, generated by tools/gen-samples.mjs.\n' +
  '   These keys are throwaway material for demonstration only. */\n';
writeFileSync(join(root, 'js', 'samples.js'),
  banner + '(function (root) {\n  \'use strict\';\n  root.JWTSamples = ' +
  JSON.stringify(samples, null, 2).replace(/\n/g, '\n  ') +
  ';\n}(typeof window !== \'undefined\' ? window : globalThis));\n');
console.log('Wrote js/samples.js');
