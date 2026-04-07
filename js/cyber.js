// ═══════════════════════════════════════════════════════════════════════
//  cyber.js — Practical cybersecurity tools
//  CTF Toolkit, Malware Deobfuscation, Incident Response
//  Dependencies: ciphers.js, encoders.js, crackers.js
// ═══════════════════════════════════════════════════════════════════════

// CTF Recipe Chaining - chain multiple decode operations

const RECIPE_OPS = {
  'Base64 Decode': t => { try { return atob(t.trim()); } catch(e) { return '[base64 error]'; } },
  'Base64 Encode': t => btoa(t),
  'Hex Decode': t => { const c=t.replace(/\s/g,''); let s=''; for(let i=0;i<c.length;i+=2) s+=String.fromCharCode(parseInt(c.substr(i,2),16)); return s; },
  'Hex Encode': t => [...t].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(''),
  'URL Decode': t => { try { return decodeURIComponent(t); } catch(e) { return t; } },
  'URL Encode': t => encodeURIComponent(t),
  'Binary Decode': t => t.replace(/\s+/g,' ').split(' ').filter(Boolean).map(b=>String.fromCharCode(parseInt(b,2))).join(''),
  'Binary Encode': t => [...t].map(c=>c.charCodeAt(0).toString(2).padStart(8,'0')).join(' '),
  'Reverse': t => [...t].reverse().join(''),
  'ROT13': t => Caesar.shift(t, 13),
  'ROT47': t => ROT47.transform(t),
  'Atbash': t => Atbash.transform(t),
  'To Uppercase': t => t.toUpperCase(),
  'To Lowercase': t => t.toLowerCase(),
  'Remove Whitespace': t => t.replace(/\s/g,''),
  'Strip Non-Printable': t => t.replace(/[^\x20-\x7E]/g,''),
  'Caesar +1…+25 (best)': t => { const r=Caesar.crack(t); return r[0].shift ? r[0].text : t; },
  'XOR Brute (best)': t => { const r=XorCipher.crackSingle(t); return r[0]&&r[0].score>0.3 ? r[0].text : t; },
  'Unescape Unicode': t => t.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16))),
  'Unescape Hex': t => t.replace(/\\x([0-9a-fA-F]{2})/g, (_,h) => String.fromCharCode(parseInt(h,16))),
  'From Char Codes': t => { const nums=t.match(/\d+/g); return nums ? nums.map(n=>String.fromCharCode(+n)).join('') : t; },
  'Base64url Decode': t => { let s=t.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; try{return atob(s);}catch(e){return '[error]';} },
  'PowerShell -Enc Decode': t => { try { const raw=atob(t.trim()); let s=''; for(let i=0;i<raw.length;i+=2) { const code=raw.charCodeAt(i)|(raw.charCodeAt(i+1)<<8); if(code) s+=String.fromCharCode(code); } return s; } catch(e) { return '[decode error]'; } },
};

let recipeSteps = [];

function addRecipeStep() {
  recipeSteps.push('Base64 Decode');
  renderRecipe();
}

function removeRecipeStep(idx) {
  recipeSteps.splice(idx, 1);
  renderRecipe();
}

function moveRecipeStep(idx, dir) {
  const newIdx = idx + dir;
  if (newIdx < 0 || newIdx >= recipeSteps.length) return;
  [recipeSteps[idx], recipeSteps[newIdx]] = [recipeSteps[newIdx], recipeSteps[idx]];
  renderRecipe();
}

function renderRecipe() {
  const el = $('recipeSteps');
  if (!recipeSteps.length) {
    el.innerHTML = '<span class="ldim">No steps added. Click "Add Step" to build a recipe.</span>';
    return;
  }
  el.innerHTML = recipeSteps.map((op, i) =>
    `<div class="row" style="margin-bottom:6px;align-items:center">
      <span style="font-family:var(--mono);font-size:.63rem;color:var(--dim);min-width:24px">${i+1}.</span>
      <select onchange="recipeSteps[${i}]=this.value;runRecipe()" style="flex:1">${Object.keys(RECIPE_OPS).map(k=>`<option${k===op?' selected':''}>${k}</option>`).join('')}</select>
      <button class="bs" onclick="moveRecipeStep(${i},-1)" style="padding:4px 8px">↑</button>
      <button class="bs" onclick="moveRecipeStep(${i},1)" style="padding:4px 8px">↓</button>
      <button class="bs" onclick="removeRecipeStep(${i})" style="padding:4px 8px;border-color:rgba(255,92,92,.3);color:var(--red)">×</button>
    </div>`
  ).join('');
  runRecipe();
}

function runRecipe() {
  const input = $('ctfInput').value;
  if (!input || !recipeSteps.length) { $('ctfRecipeOut').innerHTML = ''; return; }
  let val = input;
  const trace = [];
  for (const op of recipeSteps) {
    const fn = RECIPE_OPS[op];
    if (fn) {
      const prev = val;
      val = fn(val);
      trace.push({ op, preview: val.substring(0, 120) });
    }
  }
  let h = `<div class="rb"><div class="rl">RECIPE OUTPUT</div><div class="rv">${H(val)}</div></div>`;
  h += `<div class="pipe"><div class="pt">RECIPE TRACE</div>`;
  trace.forEach((s, i) => h += `<div class="ps"><div class="pn">${i+1}</div><div class="pl">${H(s.op)}</div><div class="pd">${H(s.preview)}</div></div>`);
  h += `</div>`;
  $('ctfRecipeOut').innerHTML = h;
}

// CTF Flag Finder - search for common flag patterns

const FLAG_PATTERNS = [
  /flag\{[^}]+\}/gi, /ctf\{[^}]+\}/gi, /picoCTF\{[^}]+\}/gi,
  /HTB\{[^}]+\}/gi, /THM\{[^}]+\}/gi, /FLAG\{[^}]+\}/gi,
  /key\{[^}]+\}/gi, /secret\{[^}]+\}/gi,
];

function ctfAutoSolve() {
  const input = $('ctfInput').value.trim();
  if (!input) return;
  const out = $('ctfAutoOut');
  const results = [];

  // Check raw input for flags
  const rawFlags = findFlags(input);
  if (rawFlags.length) results.push({ method: 'Plaintext', text: input, flags: rawFlags });

  // Try every encoding decode
  for (const [name, fn] of Object.entries(RECIPE_OPS)) {
    if (!name.includes('Decode') && !name.includes('ROT') && !name.includes('Atbash') && !name.includes('Caesar') && !name.includes('XOR')) continue;
    try {
      const decoded = fn(input);
      if (decoded && decoded !== input && decoded !== '[base64 error]' && decoded !== '[error]' && decoded !== '[decode error]') {
        const flags = findFlags(decoded);
        const isReadable = scoreEnglish(decoded) > 0.15 || flags.length > 0;
        if (isReadable || flags.length) results.push({ method: name, text: decoded, flags });
      }
    } catch (e) {}
  }

  // Try multi-layer peeling
  const ml = Encoders.multi.decode(input);
  if (ml.depth > 0) {
    const flags = findFlags(ml.final);
    results.push({ method: `Multi-layer (${ml.layers.join(' → ')})`, text: ml.final, flags });
  }

  // Try Vigenère crack
  if (input.length >= 20 && /^[a-zA-Z\s]+$/.test(input)) {
    const vig = crackVigenere(input, 'vigenere');
    if (vig && vig.score > 0.4) {
      const flags = findFlags(vig.text);
      results.push({ method: `Vigenère (key="${vig.key}")`, text: vig.text, flags });
    }
  }

  // Full decrypt pipeline
  const dec = decodeInput(input);
  if (dec.decoded !== input) {
    const flags = findFlags(dec.decoded);
    results.push({ method: `Auto-pipeline (${dec.method})`, text: dec.decoded, flags });
  }

  // ML Classification — use trained model to identify the type
  if (typeof mlModel !== 'undefined' && mlModel.trained) {
    const features = extractFeatures(input);
    const pred = mlModel.predict(features);
    if (pred.cls !== 'plaintext' && pred.confidence > 0.4) {
      results.push({ method: `ML Classifier: ${pred.cls} (${(pred.confidence*100).toFixed(0)}% confidence)`, text: `The ML model identifies this as ${pred.cls}. Top probabilities: ${Object.entries(pred.probs).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([k,v])=>`${k}:${(v*100).toFixed(0)}%`).join(', ')}`, flags: [] });
    }
  }

  if (!results.length) {
    out.innerHTML = '<div class="rb err"><div class="rl">NO RESULTS</div><div class="rv">No decodable content or flags found. Try the Recipe builder for manual chaining.</div></div>';
    return;
  }

  // Deduplicate and sort (flagged results first)
  const seen = new Set();
  const unique = results.filter(r => { const k = r.text.substring(0, 100); if (seen.has(k)) return false; seen.add(k); return true; });
  unique.sort((a, b) => (b.flags.length - a.flags.length) || (scoreEnglish(b.text) - scoreEnglish(a.text)));

  let h = '';
  const allFlags = [...new Set(unique.flatMap(r => r.flags))];
  if (allFlags.length) {
    h += `<div class="rb" style="border-color:rgba(255,159,67,.3);background:rgba(255,159,67,.04)"><div class="rl" style="color:var(--orange)">FLAGS FOUND</div><div class="rv">${allFlags.map(f => H(f)).join('\n')}</div></div>`;
  }
  for (const r of unique.slice(0, 8)) {
    const border = r.flags.length ? 'border-color:rgba(0,255,136,.3)' : '';
    h += `<div class="rb" style="${border}"><div class="rl">${H(r.method)}</div><div class="rv">${H(r.text.substring(0, 500))}</div></div>`;
  }
  out.innerHTML = h;
}

function findFlags(text) {
  const flags = [];
  for (const pat of FLAG_PATTERNS) {
    pat.lastIndex = 0;
    let m; while ((m = pat.exec(text)) !== null) flags.push(m[0]);
  }
  return [...new Set(flags)];
}

// Malware Deobfuscation Engine - detect and reverse obfuscation techniques

function deobfuscate() {
  const input = $('deobInput').value.trim();
  if (!input) return;
  const out = $('deobOut');
  const findings = [];

  // 1. PowerShell -EncodedCommand (Base64 UTF-16LE)
  const b64Match = input.match(/[A-Za-z0-9+/=]{20,}/);
  if (b64Match) {
    try {
      const raw = atob(b64Match[0]);
      // Check if it's UTF-16LE (every other byte is 0x00 for ASCII)
      let isUtf16 = true;
      for (let i = 1; i < Math.min(raw.length, 20); i += 2) { if (raw.charCodeAt(i) !== 0) { isUtf16 = false; break; } }
      if (isUtf16 && raw.length > 4) {
        let decoded = '';
        for (let i = 0; i < raw.length; i += 2) { const code = raw.charCodeAt(i) | (raw.charCodeAt(i+1) << 8); if (code) decoded += String.fromCharCode(code); }
        findings.push({ type: 'PowerShell Encoded Command', severity: 'high', decoded, detail: 'Base64-encoded UTF-16LE string, commonly used with powershell -EncodedCommand' });
      }
    } catch (e) {}
  }

  // 2. JavaScript/VBScript char code arrays
  const charCodeMatch = input.match(/(?:char(?:code)?|chr|String\.fromCharCode)\s*\([\s\d,]+\)/gi) ||
                         input.match(/\[\s*\d+(?:\s*,\s*\d+){3,}\s*\]/g);
  if (charCodeMatch) {
    for (const m of charCodeMatch) {
      const nums = m.match(/\d+/g);
      if (nums && nums.length >= 3) {
        const decoded = nums.map(n => String.fromCharCode(+n)).join('');
        if (decoded.length >= 3) findings.push({ type: 'Char Code Array', severity: 'medium', decoded, detail: `${nums.length} character codes resolved` });
      }
    }
  }

  // 3. Hex-encoded strings (\x41\x42 or 0x41,0x42)
  const hexEscapes = input.match(/(?:\\x[0-9a-fA-F]{2}){3,}/g);
  if (hexEscapes) {
    for (const m of hexEscapes) {
      const decoded = m.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      findings.push({ type: 'Hex Escape Sequence', severity: 'medium', decoded, detail: `${m.length / 4} hex-escaped bytes` });
    }
  }

  // 4. Unicode escapes (\u0041)
  const uniEscapes = input.match(/(?:\\u[0-9a-fA-F]{4}){3,}/g);
  if (uniEscapes) {
    for (const m of uniEscapes) {
      const decoded = m.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
      findings.push({ type: 'Unicode Escape Sequence', severity: 'medium', decoded, detail: `${m.length / 6} unicode-escaped characters` });
    }
  }

  // 5. Reversed strings (check if reversing produces English)
  const reversed = [...input].reverse().join('');
  if (scoreEnglish(reversed) > scoreEnglish(input) + 0.15) {
    findings.push({ type: 'Reversed String', severity: 'low', decoded: reversed, detail: 'Reversing produces more readable text' });
  }

  // 6. XOR with common keys (single-byte brute force)
  const xorRes = XorCipher.crackSingle(input);
  if (xorRes[0] && xorRes[0].score > 0.35) {
    findings.push({ type: `XOR Obfuscation (key=0x${xorRes[0].key.toString(16).padStart(2, '0')})`, severity: 'high', decoded: xorRes[0].text, detail: 'Single-byte XOR — common malware string obfuscation' });
  }

  // 7. Base64 layers
  let peeled = input;
  let layers = 0;
  for (let i = 0; i < 5; i++) {
    try {
      const decoded = atob(peeled.trim());
      if ([...decoded].some(c => c.charCodeAt(0) > 126 || c.charCodeAt(0) < 9)) break;
      peeled = decoded; layers++;
    } catch (e) { break; }
  }
  if (layers > 0) {
    findings.push({ type: `Base64 (${layers} layer${layers > 1 ? 's' : ''})`, severity: 'medium', decoded: peeled, detail: `Peeled ${layers} Base64 encoding layer(s)` });
  }

  // 8. Printable string extraction from binary-ish data
  const printableRuns = input.match(/[\x20-\x7E]{8,}/g);
  if (printableRuns && printableRuns.length > 0) {
    const nonPrintable = [...input].filter(c => c.charCodeAt(0) < 32 || c.charCodeAt(0) > 126).length;
    if (nonPrintable > input.length * 0.2) {
      findings.push({ type: 'Extracted Strings', severity: 'info', decoded: printableRuns.join('\n'), detail: `${printableRuns.length} printable string(s) found in binary data` });
    }
  }

  // 9. Known crib XOR (try common malware strings as plaintext cribs)
  const cribs = ['http://', 'https://', 'cmd.exe', 'powershell', '.exe', 'GET ', 'POST ', 'User-Agent'];
  for (const crib of cribs) {
    if (input.length >= crib.length) {
      const keyBytes = [];
      for (let i = 0; i < crib.length; i++) keyBytes.push(input.charCodeAt(i) ^ crib.charCodeAt(i));
      // Check if key is consistent (repeating pattern)
      if (keyBytes.length >= 3) {
        const key = keyBytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
        const fullDecode = [...input].map((c, i) => String.fromCharCode(c.charCodeAt(0) ^ keyBytes[i % keyBytes.length])).join('');
        if (scoreEnglish(fullDecode) > 0.3) {
          findings.push({ type: `XOR Crib Attack (crib="${crib}")`, severity: 'high', decoded: fullDecode, detail: `Key bytes: ${key}` });
        }
      }
    }
  }

  // ML Classification — add model insight to findings
  if (typeof mlModel !== 'undefined' && mlModel.trained) {
    const features = extractFeatures(input);
    const pred = mlModel.predict(features);
    if (pred.cls !== 'plaintext' && pred.confidence > 0.3) {
      findings.push({ type: `ML Classification: ${pred.cls}`, severity: 'info', decoded: `${(pred.confidence*100).toFixed(0)}% confidence. Statistical fingerprint matches ${pred.cls}. Top: ${Object.entries(pred.probs).sort((a,b)=>b[1]-a[1]).slice(0,3).map(([k,v])=>`${k}:${(v*100).toFixed(0)}%`).join(', ')}`, detail: 'Random Forest on 128 features (byte entropy, n-gram analysis, IC probing, structural shape, positional, charset, etc.)' });
    }
  }

  if (!findings.length) {
    out.innerHTML = '<div class="rb"><div class="rl">ANALYSIS COMPLETE</div><div class="rv">No recognized obfuscation patterns found. The data may use a custom encoding or be genuinely encrypted.</div></div>';
    return;
  }

  // Sort by severity
  const sevOrder = { high: 0, medium: 1, low: 2, info: 3 };
  findings.sort((a, b) => sevOrder[a.severity] - sevOrder[b.severity]);

  let h = `<div class="rb blu"><div class="rl">FOUND ${findings.length} PATTERN${findings.length > 1 ? 'S' : ''}</div></div>`;
  for (const f of findings) {
    const color = f.severity === 'high' ? 'var(--red)' : f.severity === 'medium' ? 'var(--orange)' : f.severity === 'low' ? 'var(--teal)' : 'var(--dim)';
    h += `<div class="rb" style="border-color:${color}33;background:${color}08">
      <div class="rl" style="color:${color}">${H(f.type)} <span style="opacity:.5">[${f.severity}]</span></div>
      <div style="font-family:var(--mono);font-size:.68rem;color:var(--dim);margin-bottom:8px">${H(f.detail)}</div>
      <div class="rv">${H(f.decoded.substring(0, 800))}</div>
    </div>`;
  }
  out.innerHTML = h;
}

// Incident Response Tools - extract IOCs and decode commands from logs

function irAnalyze() {
  const input = $('irInput').value.trim();
  if (!input) return;
  const out = $('irOut');
  const findings = [];

  // 1. JWT Detection and Decoding
  const jwtMatch = input.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
  if (jwtMatch) {
    const parts = jwtMatch[0].split('.');
    const b64url = s => { let p = s.replace(/-/g, '+').replace(/_/g, '/'); while (p.length % 4) p += '='; try { return JSON.parse(atob(p)); } catch(e) { return atob(p); } };
    const header = b64url(parts[0]);
    const payload = b64url(parts[1]);
    findings.push({
      type: 'JSON Web Token (JWT)',
      content: `Header:\n${JSON.stringify(header, null, 2)}\n\nPayload:\n${JSON.stringify(payload, null, 2)}\n\nSignature: ${parts[2].substring(0, 20)}...`,
      detail: `Algorithm: ${header.alg || 'unknown'}, Type: ${header.typ || 'unknown'}${payload.exp ? ', Expires: ' + new Date(payload.exp * 1000).toISOString() : ''}${payload.iat ? ', Issued: ' + new Date(payload.iat * 1000).toISOString() : ''}`
    });
  }

  // 2. HTTP Basic Auth
  const basicMatch = input.match(/Basic\s+([A-Za-z0-9+/=]+)/i);
  if (basicMatch) {
    try {
      const decoded = atob(basicMatch[1]);
      const [user, pass] = decoded.split(':');
      findings.push({ type: 'HTTP Basic Auth Credentials', content: `Username: ${user}\nPassword: ${pass}`, detail: `Decoded from Basic auth header` });
    } catch (e) {}
  }

  // 3. Unix timestamps
  const tsMatches = input.match(/\b1[0-9]{9}\b/g);
  if (tsMatches) {
    const decoded = [...new Set(tsMatches)].map(ts => `${ts} → ${new Date(+ts * 1000).toISOString()}`).join('\n');
    findings.push({ type: 'Unix Timestamps', content: decoded, detail: `${tsMatches.length} timestamp(s) found` });
  }

  // 4. Windows FILETIME (100ns since 1601)
  const ftMatches = input.match(/\b1[23]\d{16,17}\b/g);
  if (ftMatches) {
    const decoded = [...new Set(ftMatches)].map(ft => {
      const ms = (+ft - 116444736000000000) / 10000;
      return `${ft} → ${new Date(ms).toISOString()}`;
    }).join('\n');
    findings.push({ type: 'Windows FILETIME', content: decoded, detail: `${ftMatches.length} FILETIME value(s) found` });
  }

  // 5. Base64 blocks (potential encoded commands/payloads)
  const b64Blocks = input.match(/[A-Za-z0-9+/]{40,}={0,2}/g);
  if (b64Blocks) {
    for (const block of b64Blocks.slice(0, 3)) {
      try {
        const raw = atob(block);
        // Check for UTF-16LE (PowerShell)
        let isUtf16 = raw.length > 4;
        for (let i = 1; i < Math.min(raw.length, 20); i += 2) { if (raw.charCodeAt(i) !== 0) { isUtf16 = false; break; } }
        if (isUtf16) {
          let decoded = '';
          for (let i = 0; i < raw.length; i += 2) { const code = raw.charCodeAt(i) | (raw.charCodeAt(i+1) << 8); if (code) decoded += String.fromCharCode(code); }
          findings.push({ type: 'PowerShell Encoded Command', content: decoded, detail: 'Base64 UTF-16LE — likely powershell -EncodedCommand' });
        } else if ([...raw].every(c => c.charCodeAt(0) >= 10 && c.charCodeAt(0) <= 126)) {
          findings.push({ type: 'Base64 Encoded Payload', content: raw.substring(0, 500), detail: `${raw.length} bytes decoded` });
        }
      } catch (e) {}
    }
  }

  // 6. IP addresses
  const ips = input.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
  if (ips) {
    const unique = [...new Set(ips)];
    const priv = unique.filter(ip => ip.startsWith('10.') || ip.startsWith('192.168.') || ip.match(/^172\.(1[6-9]|2\d|3[01])\./));
    const pub = unique.filter(ip => !priv.includes(ip) && ip !== '127.0.0.1' && ip !== '0.0.0.0');
    let content = '';
    if (pub.length) content += `Public: ${pub.join(', ')}\n`;
    if (priv.length) content += `Private: ${priv.join(', ')}\n`;
    content += `Loopback/Special: ${unique.filter(ip => !pub.includes(ip) && !priv.includes(ip)).join(', ') || 'none'}`;
    findings.push({ type: 'IP Addresses', content, detail: `${unique.length} unique IP(s): ${pub.length} public, ${priv.length} private` });
  }

  // 7. URLs and domains
  const urls = input.match(/https?:\/\/[^\s<>"']+/gi);
  if (urls) {
    findings.push({ type: 'URLs', content: [...new Set(urls)].join('\n'), detail: `${new Set(urls).size} unique URL(s)` });
  }

  // 8. Email addresses
  const emails = input.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
  if (emails) {
    findings.push({ type: 'Email Addresses', content: [...new Set(emails)].join('\n'), detail: `${new Set(emails).size} unique email(s)` });
  }

  // 9. Hashes (MD5, SHA1, SHA256)
  const md5s = input.match(/\b[a-fA-F0-9]{32}\b/g);
  const sha1s = input.match(/\b[a-fA-F0-9]{40}\b/g);
  const sha256s = input.match(/\b[a-fA-F0-9]{64}\b/g);
  if (sha256s) findings.push({ type: 'SHA-256 Hashes', content: [...new Set(sha256s)].join('\n'), detail: `${new Set(sha256s).size} hash(es)` });
  if (sha1s) { const filtered = (sha1s||[]).filter(h => !sha256s || !sha256s.some(s => s.includes(h))); if(filtered.length) findings.push({ type: 'SHA-1 Hashes', content: [...new Set(filtered)].join('\n'), detail: `${new Set(filtered).size} hash(es)` }); }
  if (md5s) { const filtered = (md5s||[]).filter(h => !(sha1s||[]).some(s => s.includes(h)) && !(sha256s||[]).some(s => s.includes(h))); if(filtered.length) findings.push({ type: 'MD5 Hashes', content: [...new Set(filtered)].join('\n'), detail: `${new Set(filtered).size} hash(es)` }); }

  // 10. Registry keys
  const regKeys = input.match(/HK(?:LM|CU|CR|U|CC)\\[^\s"']+/g);
  if (regKeys) {
    findings.push({ type: 'Windows Registry Keys', content: [...new Set(regKeys)].join('\n'), detail: `${new Set(regKeys).size} registry path(s)` });
  }

  // 11. File paths
  const winPaths = input.match(/[A-Z]:\\(?:[^\s\\<>"']+\\)*[^\s\\<>"']+/g);
  const nixPaths = input.match(/\/(?:etc|var|tmp|usr|home|opt|bin|sbin)\/[^\s<>"']+/g);
  const paths = [...(winPaths||[]), ...(nixPaths||[])];
  if (paths.length) {
    findings.push({ type: 'File Paths', content: [...new Set(paths)].join('\n'), detail: `${new Set(paths).size} path(s) found` });
  }

  if (!findings.length) {
    out.innerHTML = '<div class="rb"><div class="rl">NO IOCs FOUND</div><div class="rv">No indicators of compromise, encoded commands, or notable artifacts detected in this input.</div></div>';
    return;
  }

  let h = `<div class="rb blu"><div class="rl">EXTRACTED ${findings.length} ARTIFACT${findings.length > 1 ? 'S' : ''}</div></div>`;
  for (const f of findings) {
    h += `<div class="rb"><div class="rl">${H(f.type)}</div><div style="font-family:var(--mono);font-size:.68rem;color:var(--dim);margin-bottom:8px">${H(f.detail)}</div><div class="rv">${H(f.content)}</div></div>`;
  }
  out.innerHTML = h;
}
