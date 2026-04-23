/**
 * CipherLab - Cybersecurity Tools Module
 * 
 * This module provides practical cybersecurity tools including CTF challenge
 * solvers, malware deobfuscation utilities, and incident response helpers.
 * It implements recipe chaining for complex multi-layer decoding scenarios.
 * 
 * Dependencies: ciphers.js, encoders.js, crackers.js
 */

/**
 * CTF Recipe Operations
 * Chainable operations for solving multi-layer encoding puzzles
 */

const RECIPE_OPS = {
  // Encoding Decoders
  'Base64 Decode':      t => { try { return atob(t.trim()); } catch(e) { return '[base64 error]'; } },
  'Base64url Decode':   t => { let s=t.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; try{return atob(s);}catch(e){return '[error]';} },
  'Hex Decode':         t => { const c=t.replace(/\s/g,''); let s=''; for(let i=0;i<c.length;i+=2) s+=String.fromCharCode(parseInt(c.substr(i,2),16)); return s; },
  'Binary Decode':      t => Encoders.binary.decode(t),
  'Octal Decode':       t => Encoders.octal.decode(t),
  'Decimal Decode':     t => Encoders.decimal.decode(t),
  'URL Decode':         t => { try { return decodeURIComponent(t); } catch(e) { return t; } },
  'Morse Decode':       t => { try { return Encoders.morse.decode(t); } catch(e) { return '[morse error]'; } },
  'Bacon Decode':       t => { try { return Encoders.bacon.decode(t); } catch(e) { return '[bacon error]'; } },
  'A1Z26 Decode':       t => { try { return A1Z26.decode(t); } catch(e) { return '[a1z26 error]'; } },
  'Base32 Decode':      t => { try { return Base32.decode(t.trim()); } catch(e) { return '[base32 error]'; } },
  'Base58 Decode':      t => { try { return Base58.decode(t.trim()); } catch(e) { return '[base58 error]'; } },
  'Ascii85 Decode':     t => { try { return Ascii85.decode(t); } catch(e) { return '[ascii85 error]'; } },
  'UUEncode Decode':    t => { try { return UUEncode.decode(t); } catch(e) { return '[uuencode error]'; } },
  'HTML Entities Decode': t => { try { return HTMLEntities.decode(t); } catch(e) { return '[html error]'; } },
  'Polybius Decode':    t => { try { return PolybiusSquare.decode(t); } catch(e) { return '[polybius error]'; } },
  'ADFGVX Decode':      t => { try { return ADFGVX.decode(t); } catch(e) { return '[adfgvx error]'; } },
  'Tap Code Decode':    t => { try { return TapCode.decode(t); } catch(e) { return '[tap error]'; } },
  'NATO Phonetic Decode': t => { try { return NATOPhonetic.decode(t); } catch(e) { return '[nato error]'; } },
  'Phone Keypad Decode':  t => { try { return PhoneKeypad.decode(t.replace(/\s/g,'')); } catch(e) { return '[phone error]'; } },
  // Encoding Encoders
  'Base64 Encode':      t => btoa(t),
  'Hex Encode':         t => Encoders.hex.encode(t),
  'Binary Encode':      t => Encoders.binary.encode(t),
  'Octal Encode':       t => Encoders.octal.encode(t),
  'Decimal Encode':     t => Encoders.decimal.encode(t),
  'URL Encode':         t => encodeURIComponent(t),
  'Morse Encode':       t => Encoders.morse.encode(t),
  'Bacon Encode':       t => Encoders.bacon.encode(t),
  'A1Z26 Encode':       t => A1Z26.encode(t),
  'Base32 Encode':      t => Base32.encode(t),
  'Base58 Encode':      t => Base58.encode(t),
  'Ascii85 Encode':     t => Ascii85.encode(t),
  'UUEncode Encode':    t => UUEncode.encode(t),
  'HTML Entities Encode': t => HTMLEntities.encode(t),
  'Polybius Encode':    t => PolybiusSquare.encode(t),
  'ADFGVX Encode':      t => ADFGVX.encode(t),
  'Tap Code Encode':    t => TapCode.encode(t),
  'NATO Phonetic Encode': t => NATOPhonetic.encode(t),
  'Phone Keypad Encode':  t => PhoneKeypad.encode(t),
  // Classical Cipher Decoders
  'Caesar Decrypt':    t => Caesar.decrypt(t, 3),
  'Caesar Decrypt (ROT13)':   t => Caesar.decrypt(t, 13),
  'Caesar Crack (best shift)':   t => { const r=Caesar.crack(t); return r[0].shift ? r[0].text : t; },
  'ROT13':                       t => ROT13_cipher.decrypt(t),
  'ROT47':                       t => ROT47.transform(t),
  'Atbash':                      t => Atbash.transform(t),
  'Vigenère Decrypt':  t => Vigenere.decrypt(t, 'KEY'),
  'Vigenère Crack (auto-key)':   t => { const r=crackVigenere(t,'vigenere'); return r ? r.text : t; },
  'Beaufort Decrypt':  t => Beaufort.decrypt(t, 'KEY'),
  'Beaufort Crack (auto-key)':   t => { const r=crackVigenere(t,'beaufort'); return r ? r.text : t; },
  'Porta Decrypt':     t => Porta.decrypt(t, 'KEY'),
  'Porta Crack (auto-key)':      t => { const r=crackVigenere(t,'porta'); return r ? r.text : t; },
  'Affine Decrypt':   t => affineDec(t, 5, 8),
  'Affine Crack (best key)':     t => { const r=AffineCracker.crack(t); return r[0] ? r[0].text : t; },
  'Playfair Decrypt': t => Playfair.decrypt(t, 'CIPHER'),
  'Autokey Decrypt':   t => VigenereAutokey.decrypt(t, 'KEY'),
  'Bifid Decrypt':  t => Bifid.decrypt(t, 'CIPHER'),
  'Rail Fence Decrypt': t => RailFenceCracker.decrypt(t, 3),
  'Rail Fence Crack (best rails)': t => { const r=RailFenceCracker.crack(t.replace(/\s/g,'')); return r[0] ? r[0].text : t; },
  'Columnar Decrypt': t => Columnar.decrypt(t.toUpperCase().replace(/[^A-Z]/g,''), 'ZEBRA'),
  'Columnar Crack (best key)':   t => { if(t.length>200)return '[too long for columnar crack]'; const r=ColumnarCracker.crack(t.replace(/\s/g,'')); return r[0] ? r[0].text : t; },
  'Scytale Decrypt':    t => Scytale.decrypt(t.replace(/\s/g,''), 5),
  'Route Cipher Decrypt': t => RouteCipher.decrypt(t.replace(/\s/g,''), 5),
  'Substitution Crack (hill-climb)': t => { const r=SubstitutionCracker.crack(t); return r ? r.text : t; },
  'Enigma Crack (III-II-I)':     t => { const r=EnigmaCracker.crack(t); return r ? r.text : t; },
  // Classical Cipher Encoders
  'Caesar Encrypt':    t => Caesar.encrypt(t, 3),
  'Caesar Encrypt (ROT13)':   t => Caesar.encrypt(t, 13),
  'Vigenère Encrypt':  t => Vigenere.encrypt(t, 'KEY'),
  'Beaufort Encrypt':  t => Beaufort.encrypt(t, 'KEY'),
  'Porta Encrypt':     t => Porta.encrypt(t, 'KEY'),
  'Affine Encrypt':   t => affineEnc(t, 5, 8),
  'Playfair Encrypt': t => Playfair.encrypt(t, 'CIPHER'),
  'Autokey Encrypt':   t => VigenereAutokey.encrypt(t, 'KEY'),
  'Bifid Encrypt':  t => Bifid.encrypt(t, 'CIPHER'),
  'Rail Fence Encrypt': t => railEnc(t, 3),
  'Columnar Encrypt': t => Columnar.encrypt(t.toUpperCase().replace(/[^A-Z]/g,''), 'ZEBRA'),
  'Scytale Encrypt':    t => Scytale.encrypt(t, 5),
  'Route Cipher Encrypt': t => RouteCipher.encrypt(t, 5),
  'Reverse':                     t => ReverseText.encrypt(t),
  // Modern and Byte-level Operations
  'XOR Single Byte': t => { return [...t].map(c=>String.fromCharCode(c.charCodeAt(0)^0x41)).join(''); },
  'XOR Brute (best single-byte)': t => { const r=XorCipher.crackSingle(t); return r[0]&&r[0].score>0.3 ? r[0].text : t; },
  'XOR Repeating Encrypt':    t => XorCipher.encryptRepeating(t, 'SECRET'),
  'RC4 Decrypt':        t => { try { return RC4.encrypt(t,'AB'); } catch(e) { return '[rc4 error]'; } },
  'RC4 Crack (1-2 byte key)':    t => { try { const r=RC4.crackShort(t,2); return r[0]&&r[0].score>0.3?r[0].text:t; } catch(e) { return t; } },
  // ── Utilities ────────────────────────────────────────────────────────
  'To Uppercase':                t => t.toUpperCase(),
  'To Lowercase':                t => t.toLowerCase(),
  'Remove Whitespace':           t => t.replace(/\s/g,''),
  'Remove Non-Alpha':            t => t.replace(/[^a-zA-Z]/g,''),
  'Strip Non-Printable':         t => t.replace(/[^\x20-\x7E]/g,''),
  'Unescape Unicode':            t => t.replace(/\\u([0-9a-fA-F]{4})/g, (_,h) => String.fromCharCode(parseInt(h,16))),
  'Unescape Hex':                t => t.replace(/\\x([0-9a-fA-F]{2})/g, (_,h) => String.fromCharCode(parseInt(h,16))),
  'From Char Codes':             t => { const nums=t.match(/\d+/g); return nums ? nums.map(n=>String.fromCharCode(+n)).join('') : t; },
  'To Char Codes':               t => [...t].map(c=>c.charCodeAt(0)).join(' '),
  'PowerShell -Enc Decode':      t => { try { const raw=atob(t.trim()); let s=''; for(let i=0;i<raw.length;i+=2) { const code=raw.charCodeAt(i)|(raw.charCodeAt(i+1)<<8); if(code) s+=String.fromCharCode(code); } return s; } catch(e) { return '[decode error]'; } },
};

// Key config — defines which ops take a user-editable key and what kind
// type: 'text' = string key, 'number' = numeric param, 'affine' = two numbers (a, b)
const RECIPE_KEY_CONFIG = {
  'Vigenère Decrypt':      { type:'text',   label:'Key',    def:'KEY' },
  'Vigenère Encrypt':      { type:'text',   label:'Key',    def:'KEY' },
  'Beaufort Decrypt':      { type:'text',   label:'Key',    def:'KEY' },
  'Beaufort Encrypt':      { type:'text',   label:'Key',    def:'KEY' },
  'Porta Decrypt':         { type:'text',   label:'Key',    def:'KEY' },
  'Porta Encrypt':         { type:'text',   label:'Key',    def:'KEY' },
  'Autokey Decrypt':       { type:'text',   label:'Key',    def:'KEY' },
  'Autokey Encrypt':       { type:'text',   label:'Key',    def:'KEY' },
  'Playfair Decrypt':   { type:'text',   label:'Key',    def:'CIPHER' },
  'Playfair Encrypt':   { type:'text',   label:'Key',    def:'CIPHER' },
  'Bifid Decrypt':      { type:'text',   label:'Key',    def:'CIPHER' },
  'Bifid Encrypt':      { type:'text',   label:'Key',    def:'CIPHER' },
  'Columnar Decrypt':    { type:'text',   label:'Key',    def:'ZEBRA' },
  'Columnar Encrypt':    { type:'text',   label:'Key',    def:'ZEBRA' },
  'Caesar Decrypt':        { type:'number', label:'Shift',  def:'3',  min:1, max:25 },
  'Caesar Decrypt (ROT13)':       { type:'number', label:'Shift',  def:'13', min:1, max:25 },
  'Caesar Encrypt':        { type:'number', label:'Shift',  def:'3',  min:1, max:25 },
  'Caesar Encrypt (ROT13)':       { type:'number', label:'Shift',  def:'13', min:1, max:25 },
  'Rail Fence Decrypt':    { type:'number', label:'Rails',  def:'3',  min:2, max:20 },
  'Rail Fence Encrypt':    { type:'number', label:'Rails',  def:'3',  min:2, max:20 },
  'Scytale Decrypt':        { type:'number', label:'Cols',   def:'5',  min:2, max:20 },
  'Scytale Encrypt':        { type:'number', label:'Cols',   def:'5',  min:2, max:20 },
  'Route Cipher Decrypt':   { type:'number', label:'Cols',   def:'5',  min:2, max:20 },
  'Route Cipher Encrypt':   { type:'number', label:'Cols',   def:'5',  min:2, max:20 },
  'Affine Decrypt':       { type:'affine', def:'5,8' },
  'Affine Encrypt':       { type:'affine', def:'5,8' },
  'XOR Single Byte': { type:'text',   label:'Hex byte', def:'41' },
  'XOR Repeating Encrypt':        { type:'text',   label:'Key',    def:'SECRET' },
  'RC4 Decrypt':            { type:'text',   label:'Key',    def:'AB' },
};

// Each step is now {op: string, key: string} so keys persist when you reorder
let recipeSteps = [];

function addRecipeStep() {
  recipeSteps.push({ op:'Base64 Decode', key:'' });
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

// Called when a step's op dropdown changes
function recipeOpChanged(idx, val) {
  recipeSteps[idx].op = val;
  // Reset key to default for the new op
  const cfg = RECIPE_KEY_CONFIG[val];
  recipeSteps[idx].key = cfg ? cfg.def : '';
  renderRecipe();
}

// Called when a step's key input changes
function recipeKeyChanged(idx, val) {
  recipeSteps[idx].key = val;
  runRecipe();
}

// Build the select options string which is shared between steps
function _recipeOpOptions(selected) {
  // Group ops by section header in the dropdown
  const groups = [
    ['── Encodings: Decode ──', ['Base64 Decode','Base64url Decode','Hex Decode','Binary Decode','Octal Decode','Decimal Decode','URL Decode','Morse Decode','Bacon Decode','A1Z26 Decode','Base32 Decode','Base58 Decode','Ascii85 Decode','UUEncode Decode','HTML Entities Decode','Polybius Decode','ADFGVX Decode','Tap Code Decode','NATO Phonetic Decode','Phone Keypad Decode']],
    ['── Encodings: Encode ──', ['Base64 Encode','Hex Encode','Binary Encode','Octal Encode','Decimal Encode','URL Encode','Morse Encode','Bacon Encode','A1Z26 Encode','Base32 Encode','Base58 Encode','Ascii85 Encode','UUEncode Encode','HTML Entities Encode','Polybius Encode','ADFGVX Encode','Tap Code Encode','NATO Phonetic Encode','Phone Keypad Encode']],
    ['── Ciphers: Decrypt ──', ['Caesar Decrypt','Caesar Decrypt (ROT13)','Caesar Crack (best shift)','ROT13','ROT47','Atbash','Vigenère Decrypt','Vigenère Crack (auto-key)','Beaufort Decrypt','Beaufort Crack (auto-key)','Porta Decrypt','Porta Crack (auto-key)','Affine Decrypt','Affine Crack (best key)','Playfair Decrypt','Autokey Decrypt','Bifid Decrypt','Rail Fence Decrypt','Rail Fence Crack (best rails)','Columnar Decrypt','Columnar Crack (best key)','Scytale Decrypt','Route Cipher Decrypt','Substitution Crack (hill-climb)','Enigma Crack (III-II-I)']],
    ['── Ciphers: Encrypt ──', ['Caesar Encrypt','Caesar Encrypt (ROT13)','Vigenère Encrypt','Beaufort Encrypt','Porta Encrypt','Affine Encrypt','Playfair Encrypt','Autokey Encrypt','Bifid Encrypt','Rail Fence Encrypt','Columnar Encrypt','Scytale Encrypt','Route Cipher Encrypt','Reverse']],
    ['── Modern / Byte-level ──', ['XOR Single Byte','XOR Brute (best single-byte)','XOR Repeating Encrypt','RC4 Decrypt','RC4 Crack (1-2 byte key)']],
    ['── Utilities ──', ['To Uppercase','To Lowercase','Remove Whitespace','Remove Non-Alpha','Strip Non-Printable','Unescape Unicode','Unescape Hex','From Char Codes','To Char Codes','PowerShell -Enc Decode']],
  ];
  return groups.map(([label, ops]) =>
    `<optgroup label="${label}">${ops.map(k=>`<option${k===selected?' selected':''}>${H(k)}</option>`).join('')}</optgroup>`
  ).join('');
}

// Build the key input for a step and returns empty string if no key needed
function _recipeKeyInput(idx, op, currentKey) {
  const cfg = RECIPE_KEY_CONFIG[op];
  if (!cfg) return '';
  const val = currentKey || cfg.def;
  if (cfg.type === 'affine') {
    const parts = val.split(',');
    const a = parts[0]||cfg.def.split(',')[0], b = parts[1]||cfg.def.split(',')[1];
    return `<input type="number" min="1" max="25" value="${H(a)}" title="a (must be coprime to 26)" oninput="recipeSteps[${idx}].key=this.value+','+(recipeSteps[${idx}].key.split(',')[1]||'8');runRecipe()" style="width:52px;margin-left:6px" placeholder="a">` +
           `<input type="number" min="0" max="25" value="${H(b)}" title="b" oninput="recipeSteps[${idx}].key=(recipeSteps[${idx}].key.split(',')[0]||'5')+','+this.value;runRecipe()" style="width:52px;margin-left:4px" placeholder="b">`;
  }
  if (cfg.type === 'number') {
    return `<input type="number" min="${cfg.min||1}" max="${cfg.max||999}" value="${H(val)}" title="${cfg.label}" oninput="recipeKeyChanged(${idx},this.value)" style="width:64px;margin-left:6px" placeholder="${cfg.label}">`;
  }
  // text key
  return `<input type="text" value="${H(val)}" title="${cfg.label}: ${op}" oninput="recipeKeyChanged(${idx},this.value)" style="width:90px;margin-left:6px;text-transform:uppercase" placeholder="${cfg.label}">`;
}

function renderRecipe() {
  const el = $('recipeSteps');
  if (!recipeSteps.length) {
    el.innerHTML = '<span class="ldim">No steps added. Click "Add Step" to build a recipe.</span>';
    return;
  }
  el.innerHTML = recipeSteps.map((step, i) => {
    const op = typeof step === 'string' ? step : step.op; // backwards compat
    const key = typeof step === 'string' ? '' : (step.key || '');
    return `<div class="row" style="margin-bottom:6px;align-items:center;flex-wrap:wrap;gap:4px">
      <span style="font-family:var(--mono);font-size:.63rem;color:var(--dim);min-width:24px">${i+1}.</span>
      <select onchange="recipeOpChanged(${i},this.value)" style="flex:1;min-width:160px">${_recipeOpOptions(op)}</select>
      ${_recipeKeyInput(i, op, key)}
      <button class="bs" onclick="moveRecipeStep(${i},-1)" style="padding:4px 8px">↑</button>
      <button class="bs" onclick="moveRecipeStep(${i},1)" style="padding:4px 8px">↓</button>
      <button class="bs" onclick="removeRecipeStep(${i})" style="padding:4px 8px;border-color:rgba(255,92,92,.3);color:var(--red)">×</button>
    </div>`;
  }).join('');
  runRecipe();
}

// Resolve the actual function for a step, injecting the user-supplied key
function _resolveRecipeOp(step) {
  const op = typeof step === 'string' ? step : step.op;
  const rawKey = typeof step === 'string' ? '' : (step.key || '');
  const cfg = RECIPE_KEY_CONFIG[op];

  // No key config: use the static RECIPE_OPS function as-is
  if (!cfg || !rawKey) return RECIPE_OPS[op];

  const key = rawKey.trim().toUpperCase() || cfg.def;

  if (op === 'Caesar Decrypt' || op === 'Caesar Decrypt (ROT13)')
    return t => Caesar.decrypt(t, +key||3);
  if (op === 'Caesar Encrypt' || op === 'Caesar Encrypt (ROT13)')
    return t => Caesar.encrypt(t, +key||3);
  if (op === 'Rail Fence Decrypt')  return t => RailFenceCracker.decrypt(t, +key||3);
  if (op === 'Rail Fence Encrypt')  return t => railEnc(t, +key||3);
  if (op === 'Scytale Decrypt')       return t => Scytale.decrypt(t.replace(/\s/g,''), +key||5);
  if (op === 'Scytale Encrypt')       return t => Scytale.encrypt(t, +key||5);
  if (op === 'Route Cipher Decrypt')  return t => RouteCipher.decrypt(t.replace(/\s/g,''), +key||5);
  if (op === 'Route Cipher Encrypt')  return t => RouteCipher.encrypt(t, +key||5);
  if (op === 'Affine Decrypt') {
    const [a,b] = key.split(',').map(Number); return t => affineDec(t, a||5, b||8);
  }
  if (op === 'Affine Encrypt') {
    const [a,b] = key.split(',').map(Number); return t => affineEnc(t, a||5, b||8);
  }
  if (op === 'Vigenère Decrypt')      return t => Vigenere.decrypt(t, key);
  if (op === 'Vigenère Encrypt')      return t => Vigenere.encrypt(t, key);
  if (op === 'Beaufort Decrypt')      return t => Beaufort.decrypt(t, key);
  if (op === 'Beaufort Encrypt')      return t => Beaufort.encrypt(t, key);
  if (op === 'Porta Decrypt')         return t => Porta.decrypt(t, key);
  if (op === 'Porta Encrypt')         return t => Porta.encrypt(t, key);
  if (op === 'Autokey Decrypt')       return t => VigenereAutokey.decrypt(t, key);
  if (op === 'Autokey Encrypt')       return t => VigenereAutokey.encrypt(t, key);
  if (op === 'Playfair Decrypt')   return t => Playfair.decrypt(t, key);
  if (op === 'Playfair Encrypt')   return t => Playfair.encrypt(t, key);
  if (op === 'Bifid Decrypt')      return t => Bifid.decrypt(t, key);
  if (op === 'Bifid Encrypt')      return t => Bifid.encrypt(t, key);
  if (op === 'Columnar Decrypt')    return t => Columnar.decrypt(t.toUpperCase().replace(/[^A-Z]/g,''), key);
  if (op === 'Columnar Encrypt')    return t => Columnar.encrypt(t.toUpperCase().replace(/[^A-Z]/g,''), key);
  if (op === 'XOR Single Byte') {
    const byte = parseInt(key, 16)||0x41; return t => [...t].map(c=>String.fromCharCode(c.charCodeAt(0)^byte)).join('');
  }
  if (op === 'XOR Repeating Encrypt')        return t => XorCipher.encryptRepeating(t, key);
  if (op === 'RC4 Decrypt')            return t => { try{return RC4.encrypt(t,key);}catch(e){return '[rc4 error]';} };
  return RECIPE_OPS[op];
}

function runRecipe() {
  const input = $('ctfInput').value;
  if (!input || !recipeSteps.length) { $('ctfRecipeOut').innerHTML = ''; return; }
  let val = input;
  const trace = [];
  for (const step of recipeSteps) {
    const op = typeof step === 'string' ? step : step.op;
    const fn = _resolveRecipeOp(step);
    if (fn) {
      val = fn(val);
      trace.push({ op, key: typeof step === 'object' ? (step.key||'') : '', preview: val.substring(0, 120) });
    }
  }
  let h = `<div class="rb"><div class="rl">RECIPE OUTPUT</div><div class="rv">${H(val)}</div></div>`;
  h += `<div class="pipe"><div class="pt">RECIPE TRACE</div>`;
  trace.forEach((s, i) => {
    const keyLabel = s.key ? ` <span style="color:var(--teal);font-size:.6rem">[${H(s.key)}]</span>` : '';
    h += `<div class="ps"><div class="pn">${i+1}</div><div class="pl">${H(s.op)}${keyLabel}</div><div class="pd">${H(s.preview)}</div></div>`;
  });
  h += `</div>`;
  $('ctfRecipeOut').innerHTML = h;
}

// CTF Flag Finder: searches for common flag patterns

const FLAG_PATTERNS = [
  /flag\{[^}]+\}/gi, /ctf\{[^}]+\}/gi, /picoCTF\{[^}]+\}/gi,
  /HTB\{[^}]+\}/gi, /THM\{[^}]+\}/gi, /FLAG\{[^}]+\}/gi,
  /key\{[^}]+\}/gi, /secret\{[^}]+\}/gi,
];

function ctfAutoSolve() {
  let input = $('ctfInput').value.trim();
  if (!input) return;
  const out = $('ctfAutoOut');
  const results = [];

  // First, run any loaded recipe steps
  let recipeProcessed = false;
  if (recipeSteps.length > 0) {
    runRecipe(); // Execute the recipe to show the trace
    let val = input;
    for (const step of recipeSteps) {
      const fn = _resolveRecipeOp(step);
      if (fn) {
        val = fn(val);
      }
    }
    // Use the recipe output as the new input for auto-solve
    if (val !== input) {
      input = val;
      recipeProcessed = true;
      results.push({ method: `Recipe Output (${recipeSteps.length} steps)`, text: input, flags: findFlags(input) });
    }
  }

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

  // Try Beaufort crack (same key-recovery algorithm as Vigenère)
  if (input.length >= 20 && /^[a-zA-Z\s]+$/.test(input)) {
    const beau = crackVigenere(input, 'beaufort');
    if (beau && beau.score > 0.4) {
      const flags = findFlags(beau.text);
      results.push({ method: `Beaufort (key="${beau.key}")`, text: beau.text, flags });
    }
  }

  // Try Vigenère Autokey crack (Friedman key-length estimate, then frequency recovery)
  if (input.length >= 20 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const alpha = input.replace(/[^a-zA-Z]/g, '').toUpperCase();
      const kl = Math.max(1, Math.min(8, Math.round(friedmanKeyLength(alpha))));
      for (const tryKl of [kl, Math.max(1,kl-1), kl+1].filter((v,i,a)=>v>0&&a.indexOf(v)===i)) {
        const key = [];
        for (let pos = 0; pos < tryKl; pos++) {
          const stream = []; for (let i = pos; i < alpha.length; i += tryKl) stream.push(alpha.charCodeAt(i)-65);
          let bestK = 0, bestS = -1;
          for (let s = 0; s < 26; s++) { let sc = 0; for (const ch of stream) { sc += ENGLISH_FREQ[String.fromCharCode((ch-s+26)%26+97)]||0; } if (sc > bestS) { bestS = sc; bestK = s; } }
          key.push(bestK);
        }
        const keyStr = key.map(k => String.fromCharCode(k+65)).join('');
        const pt = VigenereAutokey.decrypt(input, keyStr);
        if (scoreEnglish(pt) > 0.4) {
          const flags = findFlags(pt);
          results.push({ method: `Vigenère Autokey (key="${keyStr}")`, text: pt, flags });
          break;
        }
      }
    } catch(e) {}
  }

  // Try Affine brute-force (312 keys)
  if (input.length >= 8 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const affRes = AffineCracker.crack(input);
      if (affRes[0] && (affRes[0].a !== 1 || affRes[0].b !== 0) && affRes[0].score > 0.4) {
        const flags = findFlags(affRes[0].text);
        results.push({ method: `Affine (a=${affRes[0].a}, b=${affRes[0].b})`, text: affRes[0].text, flags });
      }
    } catch(e) {}
  }

  // Try Scytale brute-force (cols 2-12)
  if (input.length >= 8 && /^[a-zA-Z]+$/.test(input.replace(/\s/g,''))) {
    try {
      const scRes = ScytaleCracker.crack(input);
      if (scRes[0] && scRes[0].score > 0.35) {
        const flags = findFlags(scRes[0].text);
        results.push({ method: `Scytale (cols=${scRes[0].cols})`, text: scRes[0].text, flags });
      }
    } catch(e) {}
  }

  // Try Route Cipher brute-force (cols 2-14, spiral route)
  if (input.length >= 8 && /^[a-zA-Z]+$/.test(input.replace(/\s/g,''))) {
    try {
      const rcRes = RouteCipherCracker.crack(input);
      if (rcRes[0] && rcRes[0].score > 0.35) {
        const flags = findFlags(rcRes[0].text);
        results.push({ method: `Route Cipher (cols=${rcRes[0].cols})`, text: rcRes[0].text, flags });
      }
    } catch(e) {}
  }

  // Try Bifid hill-climb (key-agnostic, needs >= 16 alpha chars)
  if (input.length >= 16 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const bfRes = BifidCracker.crack(input);
      if (bfRes && bfRes.score > 0.35) {
        const flags = findFlags(bfRes.text);
        results.push({ method: `Bifid (key="${bfRes.key.substring(0,8)}")`, text: bfRes.text, flags });
      }
    } catch(e) {}
  }

  // Try Playfair hill-climb (key-agnostic, needs >= 20 alpha chars)
  if (input.length >= 20 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const pfRes = PlayfairCracker.crack(input);
      if (pfRes && pfRes.score > 0.35) {
        const flags = findFlags(pfRes.text);
        results.push({ method: `Playfair (key="${pfRes.key.substring(0,8)}")`, text: pfRes.text, flags });
      }
    } catch(e) {}
  }

  // Try Rail Fence brute-force (rails 2-20)
  if (input.length >= 8 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const rfRes = RailFenceCracker.crack(input.replace(/\s/g,''));
      if (rfRes[0] && rfRes[0].score > 0.4) {
        const flags = findFlags(rfRes[0].text);
        results.push({ method: `Rail Fence (${rfRes[0].rails} rails)`, text: rfRes[0].text, flags });
      }
    } catch(e) {}
  }

  // Try Columnar Transposition (col counts 2-7 with permutation search)
  if (input.length >= 8 && input.length <= 200 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const colRes = ColumnarCracker.crack(input.replace(/\s/g,''));
      if (colRes[0] && colRes[0].score > 0.4) {
        const flags = findFlags(colRes[0].text);
        results.push({ method: `Columnar Transposition (${colRes[0].cols} cols, order ${colRes[0].perm})`, text: colRes[0].text, flags });
      }
    } catch(e) {}
  }

  // Try Porta crack (same Kasiski+Friedman approach as Vigenère)
  if (input.length >= 20 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const porta = crackVigenere(input, 'porta');
      if (porta && porta.score > 0.4) {
        const flags = findFlags(porta.text);
        results.push({ method: `Porta (key="${porta.key}")`, text: porta.text, flags });
      }
    } catch(e) {}
  }

  // Try XOR single-byte brute-force (all 255 keys)
  try {
    const xorRes = XorCipher.crackSingle(input);
    if (xorRes[0] && xorRes[0].score > 0.4) {
      const flags = findFlags(xorRes[0].text);
      results.push({ method: `XOR single-byte (key=0x${xorRes[0].key.toString(16).padStart(2,'0')})`, text: xorRes[0].text, flags });
    }
  } catch(e) {}

  // Try XOR repeating-key (Hamming distance key-length estimation)
  if (input.length > 30) {
    try {
      const xrRes = XorCipher.crackRepeating(input);
      if (xrRes && xrRes.score > 0.4) {
        const flags = findFlags(xrRes.text);
        results.push({ method: `XOR repeating-key (key="${xrRes.key}", len=${xrRes.keyLen})`, text: xrRes.text, flags });
      }
    } catch(e) {}
  }

  // Try RC4 short-key brute-force (1-2 byte keys)
  if (input.length >= 4 && input.length <= 500) {
    try {
      const rcRes = RC4.crackShort(input, 2);
      if (rcRes[0] && rcRes[0].score > 0.4) {
        const flags = findFlags(rcRes[0].text);
        results.push({ method: `RC4 (key=0x${rcRes[0].key})`, text: rcRes[0].text, flags });
      }
    } catch(e) {}
  }

  // Try Substitution cipher hill-climber (needs >= 40 chars to work reliably)
  if (input.length >= 40 && /^[a-zA-Z\s.,!?;:'\-]+$/.test(input)) {
    try {
      const subRes = SubstitutionCracker.crack(input);
      if (subRes && subRes.score > 0.4) {
        const flags = findFlags(subRes.text);
        results.push({ method: `Substitution cipher (hill-climb)`, text: subRes.text, flags });
      }
    } catch(e) {}
  }

  // Try Enigma brute-force (all 17,576 start positions × up to 6 rotor orders)
  if (input.length >= 8 && input.length <= 300 && /^[a-zA-Z\s]+$/.test(input)) {
    try {
      const engRes = EnigmaCracker.crack(input);
      if (engRes && engRes.score > 0.4) {
        const flags = findFlags(engRes.text);
        results.push({ method: `Enigma (rotors ${engRes.rotors}, starts [${engRes.starts.join(',')}])`, text: engRes.text, flags });
      }
    } catch(e) {}
  }

  // Try direct encoding decoders with explicit labeling
  // These complement the RECIPE_OPS loop above — shown separately so they're identified clearly
  const encodingTries = [
    { name: 'Morse Code', fn: () => Encoders.morse.decode(input), guard: () => /^[.\-\s/|]+$/.test(input.trim()) },
    { name: 'Bacon Cipher', fn: () => Encoders.bacon.decode(input), guard: () => /^[ABab\s]+$/.test(input.trim()) && input.trim().length >= 5 },
    { name: 'A1Z26', fn: () => A1Z26.decode(input), guard: () => /^(\d{1,2}\s+)*\d{1,2}$/.test(input.trim()) && input.trim().split(/\s+/).every(n=>{const v=+n;return v>=1&&v<=26;}) },
    { name: 'Polybius Square', fn: () => PolybiusSquare.decode(input), guard: () => { const p=input.match(/\d{2}/g); return p&&p.every(x=>+x[0]>=1&&+x[0]<=5&&+x[1]>=1&&+x[1]<=5); } },
    { name: 'Tap Code', fn: () => TapCode.decode(input), guard: () => /^\d\.\d(\s+\d\.\d)*$/.test(input.trim()) },
    { name: 'NATO Phonetic', fn: () => NATOPhonetic.decode(input), guard: () => { const ws=input.trim().split(/\s+/);const nw=['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa','quebec','romeo','sierra','tango','uniform','victor','whiskey','xray','yankee','zulu'];return ws.length>=3&&ws.filter(w=>nw.includes(w.toLowerCase())).length/ws.length>0.7; } },
    { name: 'Phone Keypad', fn: () => PhoneKeypad.decode(input.replace(/\s/g,'')), guard: () => /^[2-9]+$/.test(input.replace(/\s/g,'')) && input.length >= 4 },
    { name: 'HTML Entities', fn: () => HTMLEntities.decode(input), guard: () => /&#\d+;/.test(input) },
    { name: 'Base32', fn: () => Base32.decode(input.trim()), guard: () => /^[A-Z2-7=\s]+$/i.test(input.trim()) && input.trim().length >= 8 },
    { name: 'Base58', fn: () => Base58.decode(input.trim()), guard: () => /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(input.trim()) && input.trim().length >= 10 },
    { name: 'Ascii85', fn: () => Ascii85.decode(input), guard: () => input.includes('<~') && input.includes('~>') },
    { name: 'UUEncode', fn: () => UUEncode.decode(input), guard: () => input.trimStart().startsWith('begin 6') },
    { name: 'ROT13', fn: () => ROT13_cipher.decrypt(input), guard: () => /^[a-zA-Z\s]+$/.test(input) && scoreEnglish(ROT13_cipher.decrypt(input)) > scoreEnglish(input) + 0.05 },
    { name: 'Reverse', fn: () => ReverseText.encrypt(input), guard: () => scoreEnglish(ReverseText.encrypt(input)) > scoreEnglish(input) + 0.05 },
    { name: 'ADFGVX', fn: () => ADFGVX.decode(input), guard: () => /^[ADFGVX\s]+$/i.test(input.trim()) && input.trim().length >= 4 },
  ];
  for (const { name, fn, guard } of encodingTries) {
    try {
      if (!guard()) continue;
      const decoded = fn();
      if (decoded && decoded !== input && decoded.length > 1) {
        const flags = findFlags(decoded);
        const readable = scoreEnglish(decoded) > 0.15 || flags.length > 0;
        if (readable) results.push({ method: name, text: decoded, flags });
      }
    } catch(e) {}
  }

  // Full decrypt pipeline
  const dec = decodeInput(input);
  if (dec.decoded !== input) {
    const flags = findFlags(dec.decoded);
    results.push({ method: `Auto-pipeline (${dec.method})`, text: dec.decoded, flags });
  }

  // ML Classification: use trained model to identify the type
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
  for (const r of unique.slice(0, 15)) {
    const border = r.flags.length ? 'border-color:rgba(0,255,136,.3)' : '';
    const recipeBtn = _recipeButtonForResult(r.method);
    h += `<div class="rb" style="${border}"><div class="rl" style="display:flex;justify-content:space-between;align-items:center">${H(r.method)}${recipeBtn}</div><div class="rv">${H(r.text.substring(0, 500))}</div></div>`;
  }
  out.innerHTML = h;
}

// Parse a method string from ctfAutoSolve to build an "Add to Recipe" button.
// If we can map the method back to a recipe op + key, show a teal button.
function _recipeButtonForResult(method) {
  let op = null, key = '';

  // Try to match the method string against known patterns
  if (/^Vigenère \(key="(.+)"\)$/.test(method))     { op='Vigenère Decrypt'; key=method.match(/key="(.+)"/)[1]; }
  else if (/^Beaufort \(key="(.+)"\)$/.test(method)) { op='Beaufort Decrypt'; key=method.match(/key="(.+)"/)[1]; }
  else if (/^Porta \(key="(.+)"\)$/.test(method))    { op='Porta Decrypt'; key=method.match(/key="(.+)"/)[1]; }
  else if (/^Vigenère Autokey \(key="(.+)"\)$/.test(method)) { op='Autokey Decrypt'; key=method.match(/key="(.+)"/)[1]; }
  else if (/^Affine \(a=(\d+), b=(\d+)\)$/.test(method)) { const m=method.match(/a=(\d+), b=(\d+)/); op='Affine Decrypt'; key=`${m[1]},${m[2]}`; }
  else if (/^Caesar shift (\d+)$/.test(method))      { op='Caesar Decrypt'; key=method.match(/shift (\d+)/)[1]; }
  else if (/^Rail Fence \((\d+) rails\)$/.test(method)) { op='Rail Fence Decrypt'; key=method.match(/(\d+) rails/)[1]; }
  else if (/^Scytale \(cols=(\d+)\)$/.test(method))  { op='Scytale Decrypt'; key=method.match(/cols=(\d+)/)[1]; }
  else if (/^Route Cipher \(cols=(\d+)\)$/.test(method)) { op='Route Cipher Decrypt'; key=method.match(/cols=(\d+)/)[1]; }
  else if (/^Playfair \(key="(.+)"\)$/.test(method)) { op='Playfair Decrypt'; key=method.match(/key="(.+)"/)[1]; }
  else if (/^Bifid \(key="(.+)"\)$/.test(method))    { op='Bifid Decrypt'; key=method.match(/key="(.+)"/)[1]; }
  else if (/^Columnar /.test(method)) { op='Columnar Decrypt'; const m=method.match(/cols=\d+ cols, order (\S+)/); key=m?m[1]:'ZEBRA'; }
  else if (/^XOR single-byte \(key=(0x[0-9a-fA-F]+)\)$/.test(method)) { op='XOR Single Byte'; key=method.match(/0x([0-9a-fA-F]+)/)[1]; }
  else if (/^ROT13$/.test(method) || method==='ROT13')   { op='ROT13'; }
  else if (/^ROT47$/.test(method) || method==='ROT47')   { op='ROT47'; }
  else if (/^Atbash$/.test(method) || method==='Atbash') { op='Atbash'; }
  else if (/^Reverse$/.test(method) || method==='Reverse'){ op='Reverse'; }
  else if (/^Base64/.test(method))   { op='Base64 Decode'; }
  else if (/^Base32/.test(method))   { op='Base32 Decode'; }
  else if (/^Base58/.test(method))   { op='Base58 Decode'; }
  else if (/^Ascii85/.test(method))  { op='Ascii85 Decode'; }
  else if (/^Morse/.test(method))    { op='Morse Decode'; }
  else if (/^Bacon/.test(method))    { op='Bacon Decode'; }
  else if (/^A1Z26/.test(method))    { op='A1Z26 Decode'; }
  else if (/^Polybius/.test(method)) { op='Polybius Decode'; }
  else if (/^Tap Code/.test(method)) { op='Tap Code Decode'; }
  else if (/^NATO/.test(method))     { op='NATO Phonetic Decode'; }
  else if (/^Phone Keypad/.test(method)) { op='Phone Keypad Decode'; }
  else if (/^UUEncode/.test(method)) { op='UUEncode Decode'; }
  else if (/^HTML Ent/.test(method)) { op='HTML Entities Decode'; }
  else if (/^ADFGVX/.test(method))   { op='ADFGVX Decode'; }
  else if (/^Substitution/.test(method)) { op='Substitution Crack (hill-climb)'; }
  else if (/^Enigma/.test(method))   { op='Enigma Crack (III-II-I)'; }

  if (!op) return '';
  const safeOp = JSON.stringify(op), safeKey = JSON.stringify(key);
  return `<button class="bs" style="font-size:.58rem;padding:2px 7px;border-color:rgba(0,200,150,.35);color:var(--teal);margin-left:8px" onclick="addToRecipe(${safeOp},${safeKey})">+ Recipe</button>`;
}

// Add a step to the recipe with the given op and key pre-filled
function addToRecipe(op, key) {
  recipeSteps.push({ op, key: key||'' });
  renderRecipe();
  // Scroll to the recipe builder section
  const el = $('recipeSteps'); if (el) el.scrollIntoView({ behavior:'smooth', block:'center' });
}

function findFlags(text) {
  const flags = [];
  for (const pat of FLAG_PATTERNS) {
    pat.lastIndex = 0;
    let m; while ((m = pat.exec(text)) !== null) flags.push(m[0]);
  }
  return [...new Set(flags)];
}

// Malware Deobfuscation Engine: detect and reverse obfuscation techniques

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

  // ML Classification: add model insight to findings
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

// Incident Response Tools: extract IOCs and decode commands from logs

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
