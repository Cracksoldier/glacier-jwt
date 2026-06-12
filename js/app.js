/* app.js — DOM wiring and rendering.
   Depends on: all other js/ modules (classic scripts, loaded before this one). */
(function () {
  'use strict';
  const U = window.JWTUtils, P = window.JWTParser, C = window.JWTClaims,
        V = window.JWTVerify, D = window.JWTDecrypt, A = window.JWTAnalysis,
        SAMPLES = window.JWTSamples || {};

  const $ = (sel) => document.querySelector(sel);
  const el = {
    input: $('#token-input'), statusStrip: $('#status-strip'), parseErrors: $('#parse-errors'),
    emptyState: $('#empty-state'), results: $('#results'),
    anatomy: $('#anatomy'), legend: $('#anatomy-legend'),
    jsonHeader: $('#json-header'), headerChips: $('#header-chips'),
    panelPayload: $('#panel-payload'), jsonPayload: $('#json-payload'),
    panelClaims: $('#panel-claims'), claimsList: $('#claims-list'),
    panelVerify: $('#panel-verify'), verifyHint: $('#verify-hint'),
    verifyKey: $('#verify-key'), verdict: $('#verdict'),
    panelDecrypt: $('#panel-decrypt'), decryptHint: $('#decrypt-hint'),
    decryptKey: $('#decrypt-key'), decryptResult: $('#decrypt-result'),
    findingsList: $('#findings-list'),
    nestedNav: $('#nested-nav'), sampleButtons: $('#sample-buttons')
  };

  let current = null;          // last parse result
  let envelope = null;         // { token, key } of the JWE we descended from
  let pendingVerifyKey = null; // key to prefill after loading a nested token

  /* ---------------- segmented controls ---------------- */
  function initSegSelect(id) {
    const box = document.getElementById(id);
    box.addEventListener('click', (ev) => {
      const btn = ev.target.closest('button[data-val]');
      if (!btn) return;
      box.dataset.value = btn.dataset.val;
      box.querySelectorAll('button').forEach(b => b.classList.toggle('active', b === btn));
    });
    return box;
  }
  const verifyFormat = initSegSelect('verify-format');
  const verifyEncoding = initSegSelect('verify-encoding');
  const decryptFormat = initSegSelect('decrypt-format');
  const decryptEncoding = initSegSelect('decrypt-encoding');

  function setSegValue(box, val) {
    box.dataset.value = val;
    box.querySelectorAll('button').forEach(b => b.classList.toggle('active', b.dataset.val === val));
  }

  /* ---------------- rendering ---------------- */
  const SEG_CLASSES = ['seg-1', 'seg-2', 'seg-3', 'seg-4', 'seg-5'];
  const JWS_SEG_NAMES = ['header', 'payload', 'signature'];
  const JWE_SEG_NAMES = ['header', 'encrypted key', 'init vector', 'ciphertext', 'auth tag'];

  function renderAnatomy(parsed) {
    const names = parsed.type === 'JWE' ? JWE_SEG_NAMES : JWS_SEG_NAMES;
    let html = '';
    parsed.parts.forEach((part, i) => {
      if (i) html += '<span class="dot">.</span>';
      html += '<span class="seg ' + SEG_CLASSES[i] + '" title="' + names[i] + '">' +
              (part ? U.escapeHtml(part) : '<em class="seg-empty">(empty)</em>') + '</span>';
    });
    el.anatomy.innerHTML = html;
    el.legend.innerHTML = names.map((n, i) =>
      '<span class="legend-item"><span class="swatch ' + SEG_CLASSES[i] + '"></span>' + n + '</span>'
    ).join('');
  }

  function badge(cls, icon, text, title) {
    return '<span class="badge ' + cls + '"' + (title ? ' title="' + U.escapeHtml(title) + '"' : '') + '>' +
           (icon ? '<i class="fa-solid ' + icon + '" aria-hidden="true"></i>' : '') + U.escapeHtml(text) + '</span>';
  }

  function renderStatusStrip(parsed) {
    let html = '';
    if (parsed.type === 'JWS') {
      const alg = String(parsed.header.alg || '?');
      const unsigned = alg.toLowerCase() === 'none';
      html += badge(unsigned ? 'b-bad' : 'b-type', unsigned ? 'fa-shield-slash' : 'fa-file-signature',
                    unsigned ? 'UNSIGNED' : 'SIGNED · JWS');
      html += badge('b-alg', 'fa-gears', 'alg ' + alg);
      const status = parsed.payload ? C.timeStatus(parsed.payload) : null;
      if (status) {
        const map = { active: 'b-ok', expired: 'b-bad', 'not-yet-valid': 'b-warn', 'no-expiry': 'b-warn' };
        html += '<span class="badge ' + map[status.state] + '" id="time-badge" title="' + U.escapeHtml(status.detail) + '">' +
                '<i class="fa-solid fa-clock" aria-hidden="true"></i><span>' + U.escapeHtml(status.label + ' — ' + status.detail) + '</span></span>';
      }
    } else {
      html += badge('b-enc', 'fa-lock', 'ENCRYPTED · JWE');
      html += badge('b-alg', 'fa-key', 'alg ' + (parsed.header.alg || '?'));
      html += badge('b-alg', 'fa-shuffle', 'enc ' + (parsed.header.enc || '?'));
    }
    html += badge('b-dim', 'fa-ruler-horizontal', parsed.token.length + ' chars');
    el.statusStrip.innerHTML = html;
    el.statusStrip.classList.remove('hidden');
  }

  function refreshTimeBadge() {
    const node = document.getElementById('time-badge');
    if (!node || !current || !current.ok || current.type !== 'JWS' || !current.payload) return;
    const status = C.timeStatus(current.payload);
    if (!status) return;
    const map = { active: 'b-ok', expired: 'b-bad', 'not-yet-valid': 'b-warn', 'no-expiry': 'b-warn' };
    node.className = 'badge ' + map[status.state];
    node.title = status.detail;
    node.innerHTML = '<i class="fa-solid fa-clock" aria-hidden="true"></i><span>' +
                     U.escapeHtml(status.label + ' — ' + status.detail) + '</span>';
  }

  function renderHeaderPanel(parsed) {
    el.jsonHeader.innerHTML = U.highlightJSON(parsed.header);
    el.headerChips.innerHTML = Object.keys(parsed.header).map((key) => {
      const info = C.describeHeader(key);
      if (!info) return '';
      return '<span class="chip" title="' + U.escapeHtml(info.desc) + '">' +
             '<strong>' + U.escapeHtml(key) + '</strong> ' + U.escapeHtml(info.name) +
             ' <i class="fa-regular fa-circle-question" aria-hidden="true"></i></span>';
    }).join('');
  }

  function formatClaimValue(key, value) {
    if (C.isTimeClaim(key) && C.looksLikeTimestamp(value)) {
      const t = C.formatTimestamp(value);
      return '<span class="claim-time"><span class="mono">' + value + '</span>' +
             '<span class="time-abs">' + U.escapeHtml(t.utc) + '</span>' +
             '<span class="time-abs">' + U.escapeHtml(t.local) + ' (local)</span>' +
             '<span class="time-rel">' + U.escapeHtml(C.relativeTime(value)) + '</span></span>';
    }
    if (typeof value === 'object' && value !== null) {
      return '<span class="mono claim-json">' + U.highlightJSON(value, 1) + '</span>';
    }
    return '<span class="mono">' + U.escapeHtml(JSON.stringify(value)) + '</span>';
  }

  function renderClaims(payload) {
    const keys = Object.keys(payload);
    if (!keys.length) {
      el.claimsList.innerHTML = '<p class="muted">The payload object is empty.</p>';
      return;
    }
    el.claimsList.innerHTML = keys.map((key) => {
      const info = C.describeClaim(key);
      return '<div class="claim-row">' +
        '<i class="fa-solid ' + (info ? info.icon : 'fa-tag') + ' claim-icon" aria-hidden="true"></i>' +
        '<div class="claim-main">' +
          '<div class="claim-head"><code>' + U.escapeHtml(key) + '</code>' +
          (info ? '<span class="claim-name">' + U.escapeHtml(info.name) + '</span>' : '') + '</div>' +
          '<div class="claim-value">' + formatClaimValue(key, payload[key]) + '</div>' +
          (info ? '<div class="claim-desc">' + U.escapeHtml(info.desc) + '</div>' : '') +
        '</div></div>';
    }).join('');
  }

  function renderFindings(parsed) {
    const findings = A.analyze(parsed);
    if (!findings.length) {
      el.findingsList.innerHTML = '<li class="finding sev-ok"><i class="fa-solid fa-circle-check" aria-hidden="true"></i>' +
        '<div><strong>Nothing suspicious found</strong><p>No structural red flags in this token.</p></div></li>';
      return;
    }
    el.findingsList.innerHTML = findings.map((f) =>
      '<li class="finding sev-' + f.severity + '">' +
      '<i class="fa-solid ' + f.icon + '" aria-hidden="true"></i>' +
      '<div><strong>' + U.escapeHtml(f.title) + '</strong><p>' + U.escapeHtml(f.detail) + '</p></div></li>'
    ).join('');
  }

  function show(node, on) { node.classList.toggle('hidden', !on); }

  function replayReveals() {
    document.querySelectorAll('#results .reveal').forEach((node, i) => {
      node.style.animation = 'none';
      void node.offsetWidth; // restart the reveal animation
      node.style.animation = '';
      node.style.animationDelay = (i * 70) + 'ms';
    });
  }

  function render(parsed) {
    current = parsed;
    const hasToken = !!parsed.token;
    show(el.emptyState, !hasToken);
    el.statusStrip.classList.add('hidden');
    show(el.parseErrors, false);

    if (!hasToken) { show(el.results, false); return; }

    if (!parsed.ok) {
      show(el.results, false);
      el.parseErrors.innerHTML = parsed.errors.map((e) =>
        '<p><i class="fa-solid fa-circle-xmark" aria-hidden="true"></i> ' + U.escapeHtml(e) + '</p>').join('');
      show(el.parseErrors, true);
      show(el.emptyState, true);
      return;
    }

    renderStatusStrip(parsed);
    if (parsed.warnings.length) {
      el.parseErrors.innerHTML = parsed.warnings.map((w) =>
        '<p class="warn"><i class="fa-solid fa-triangle-exclamation" aria-hidden="true"></i> ' + U.escapeHtml(w) + '</p>').join('');
      show(el.parseErrors, true);
    }

    renderAnatomy(parsed);
    renderHeaderPanel(parsed);
    renderFindings(parsed);

    const isJWS = parsed.type === 'JWS';
    show(el.panelPayload, isJWS);
    show(el.panelDecrypt, !isJWS);
    show(el.panelClaims, isJWS && !!parsed.payload);

    const alg = String(parsed.header.alg || '');
    if (isJWS) {
      if (parsed.payload) {
        el.jsonPayload.innerHTML = U.highlightJSON(parsed.payload);
        renderClaims(parsed.payload);
      } else {
        el.jsonPayload.innerHTML = '<span class="muted">' + U.escapeHtml(parsed.payloadRaw || '(empty)') + '</span>';
      }
      const verifiable = alg && alg.toLowerCase() !== 'none';
      show(el.panelVerify, verifiable);
      if (verifiable) {
        el.verifyHint.innerHTML = alg.startsWith('HS')
          ? 'Algorithm <code>' + U.escapeHtml(alg) + '</code> &mdash; paste the <strong>shared secret</strong>.'
          : 'Algorithm <code>' + U.escapeHtml(alg) + '</code> &mdash; paste the issuer\'s <strong>public key</strong> (PEM or JWK).';
        if (pendingVerifyKey !== null) {
          el.verifyKey.value = pendingVerifyKey;
          pendingVerifyKey = null;
        }
      }
      el.verdict.innerHTML = '';
      el.verdict.className = 'verdict';
    } else {
      el.decryptHint.innerHTML = 'Key management <code>' + U.escapeHtml(String(parsed.header.alg || '?')) +
        '</code>, content encryption <code>' + U.escapeHtml(String(parsed.header.enc || '?')) + '</code>.' +
        (/^RSA/.test(alg) ? ' Paste the recipient\'s <strong>RSA private key</strong> (PKCS#8 PEM or JWK).'
                          : ' Paste the <strong>symmetric key</strong> (base64 / hex / JWK).');
      show(el.panelVerify, false);
      el.decryptResult.innerHTML = '';
    }

    show(el.results, true);
    replayReveals();
  }

  function analyzeInput() {
    render(P.parse(el.input.value));
  }

  /* ---------------- verification ---------------- */
  async function doVerify() {
    if (!current || !current.ok) return;
    el.verdict.className = 'verdict pending';
    el.verdict.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin" aria-hidden="true"></i> verifying&hellip;';
    const res = await V.verify(current, el.verifyKey.value, {
      format: verifyFormat.dataset.value,
      secretEncoding: verifyEncoding.dataset.value
    });
    if (res.valid) {
      el.verdict.className = 'verdict valid';
      el.verdict.innerHTML = '<i class="fa-solid fa-circle-check" aria-hidden="true"></i>' +
        '<div><strong>SIGNATURE VALID</strong><p>The token was signed with the corresponding key and has not been altered.</p></div>';
    } else {
      el.verdict.className = 'verdict invalid';
      el.verdict.innerHTML = '<i class="fa-solid fa-circle-xmark" aria-hidden="true"></i>' +
        '<div><strong>NOT VERIFIED</strong><p>' + U.escapeHtml(res.error || 'Unknown error.') + '</p></div>';
    }
  }

  /* ---------------- decryption ---------------- */
  async function doDecrypt() {
    if (!current || !current.ok || current.type !== 'JWE') return;
    el.decryptResult.innerHTML = '<div class="verdict pending"><i class="fa-solid fa-circle-notch fa-spin" aria-hidden="true"></i> decrypting&hellip;</div>';
    const res = await D.decrypt(current, el.decryptKey.value, {
      format: decryptFormat.dataset.value,
      secretEncoding: decryptEncoding.dataset.value
    });
    if (!res.ok) {
      el.decryptResult.innerHTML = '<div class="verdict invalid"><i class="fa-solid fa-circle-xmark" aria-hidden="true"></i>' +
        '<div><strong>DECRYPTION FAILED</strong><p>' + U.escapeHtml(res.error) + '</p></div></div>';
      return;
    }
    let html = '<div class="verdict valid"><i class="fa-solid fa-lock-open" aria-hidden="true"></i>' +
      '<div><strong>DECRYPTED</strong><p>Authenticity confirmed by the AEAD tag &mdash; the ciphertext was produced with this key and is intact.</p></div></div>';
    if (res.isNested) {
      html += '<p class="panel-hint">The plaintext is itself a compact token (nested JWT):</p>' +
        '<pre class="json mono plaintext-box">' + U.escapeHtml(res.plaintext) + '</pre>' +
        '<button id="btn-nested" class="action-btn" type="button">' +
        '<i class="fa-solid fa-magnifying-glass" aria-hidden="true"></i> analyze nested token</button>';
    } else if (res.json !== undefined) {
      html += '<p class="panel-hint">Decrypted JSON payload:</p>' +
        '<pre class="json mono plaintext-box">' + U.highlightJSON(res.json) + '</pre>';
    } else {
      html += '<p class="panel-hint">Decrypted plaintext:</p>' +
        '<pre class="json mono plaintext-box">' + U.escapeHtml(res.plaintext) + '</pre>';
    }
    el.decryptResult.innerHTML = html;

    const nestedBtn = document.getElementById('btn-nested');
    if (nestedBtn) {
      nestedBtn.addEventListener('click', () => {
        envelope = { token: current.token, key: el.decryptKey.value };
        // if this is our demo JWE, prefill the nested token's verification secret
        if (SAMPLES.jwe && current.token === SAMPLES.jwe.token && SAMPLES.jwe.nestedKey) {
          pendingVerifyKey = SAMPLES.jwe.nestedKey;
          setSegValue(verifyFormat, 'secret');
          setSegValue(verifyEncoding, 'utf8');
        }
        el.input.value = res.plaintext;
        show(el.nestedNav, true);
        analyzeInput();
        window.scrollTo({ top: 0, behavior: 'smooth' });
      });
    }
  }

  /* ---------------- samples / clear / back ---------------- */
  function loadSample(sample) {
    envelope = null;
    show(el.nestedNav, false);
    el.input.value = sample.token;
    if (sample.keyFormat === 'pem' || sample.keyFormat === 'jwk') {
      el.verifyKey.value = sample.key; setSegValue(verifyFormat, 'auto');
      el.decryptKey.value = sample.key; setSegValue(decryptFormat, 'auto');
    } else {
      el.verifyKey.value = sample.key;
      setSegValue(verifyFormat, 'secret');
      setSegValue(verifyEncoding, sample.secretEncoding || 'utf8');
    }
    analyzeInput();
  }

  Object.keys(SAMPLES).forEach((id) => {
    const s = SAMPLES[id];
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'ghost-btn sample-btn';
    btn.innerHTML = '<i class="fa-solid ' + s.icon + '" aria-hidden="true"></i> ' + U.escapeHtml(s.label);
    btn.title = s.keyHint;
    btn.addEventListener('click', () => loadSample(s));
    el.sampleButtons.appendChild(btn);
  });

  $('#btn-clear').addEventListener('click', () => {
    el.input.value = ''; el.verifyKey.value = ''; el.decryptKey.value = '';
    envelope = null; show(el.nestedNav, false);
    analyzeInput();
    el.input.focus();
  });

  $('#btn-back').addEventListener('click', () => {
    if (!envelope) return;
    el.input.value = envelope.token;
    el.decryptKey.value = envelope.key;
    envelope = null;
    show(el.nestedNav, false);
    analyzeInput();
  });

  /* ---------------- copy buttons ---------------- */
  async function copyText(text, btn) {
    let ok = false;
    try { await navigator.clipboard.writeText(text); ok = true; }
    catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      try { ok = document.execCommand('copy'); } catch (e2) { /* ignore */ }
      ta.remove();
    }
    const original = btn.innerHTML;
    btn.innerHTML = ok ? '<i class="fa-solid fa-check" aria-hidden="true"></i> copied'
                       : '<i class="fa-solid fa-xmark" aria-hidden="true"></i> failed';
    setTimeout(() => { btn.innerHTML = original; }, 1200);
  }

  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (!current || !current.ok) return;
      const what = btn.dataset.copy;
      let text = '';
      if (what === 'token') text = current.token;
      else if (what === 'header') text = JSON.stringify(current.header, null, 2);
      else if (what === 'payload') text = current.payload ? JSON.stringify(current.payload, null, 2) : (current.payloadRaw || '');
      copyText(text, btn);
    });
  });

  /* ---------------- events ---------------- */
  let debounce = null;
  el.input.addEventListener('input', () => {
    show(el.nestedNav, false); envelope = null;
    clearTimeout(debounce);
    debounce = setTimeout(analyzeInput, 150);
  });
  $('#btn-verify').addEventListener('click', doVerify);
  $('#btn-decrypt').addEventListener('click', doDecrypt);
  el.verifyKey.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) doVerify();
  });
  el.decryptKey.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) doDecrypt();
  });

  setInterval(refreshTimeBadge, 1000);
  analyzeInput();
}());
