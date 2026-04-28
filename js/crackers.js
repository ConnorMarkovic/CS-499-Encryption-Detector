/**
 * CipherLab - Cryptanalysis Module
 * 
 * This module implements automated cryptanalysis techniques for breaking
 * polyalphabetic ciphers. It uses classical methods like Kasiski examination
 * and Friedman testing, combined with intelligent decryption pipelines.
 * 
 * Dependencies: ciphers.js, encoders.js
 */

/**
 * POLYALPHABETIC CIPHER ANALYSIS
 * Implements Kasiski examination and Friedman testing for Vigenère-type ciphers
 */

function computeIC(text){
  const a=[...text.toLowerCase()].filter(c=>c>='a'&&c<='z');const n=a.length;if(n<=1)return 0;
  const f={};for(const c of a)f[c]=(f[c]||0)+1;
  return Object.values(f).reduce((s,v)=>s+v*(v-1),0)/(n*(n-1));
}

function gcd(a,b){a=Math.abs(a);b=Math.abs(b);while(b){[a,b]=[b,a%b];}return a;}

function kasiskiKeyLengths(ct){
  const alpha=ct.toLowerCase().replace(/[^a-z]/g,'');if(alpha.length<20)return[];
  const spacings=[];
  for(let len=3;len<=5;len++){const seen={};
    for(let i=0;i<=alpha.length-len;i++){const gram=alpha.substring(i,i+len);
      if(seen[gram]!==undefined)spacings.push(i-seen[gram]);
      seen[gram]=i;}}
  if(!spacings.length)return[];
  const factors={};for(const sp of spacings){for(let f=2;f<=Math.min(sp,20);f++){if(sp%f===0)factors[f]=(factors[f]||0)+1;}}
  return Object.entries(factors).sort((a,b)=>b[1]-a[1]).slice(0,8).map(e=>+e[0]);
}

function friedmanKeyLength(ct){
  const alpha=ct.toLowerCase().replace(/[^a-z]/g,'');const ic=computeIC(alpha);
  if(ic<=0.0385)return Math.round(alpha.length/10); // near random
  const est=0.0273*alpha.length/((alpha.length-1)*ic-0.0385*alpha.length+0.0273);
  return Math.max(1,Math.min(20,Math.round(est)));
}

function crackVigenere(ct,mode='vigenere'){
  const alpha=ct.replace(/[^a-zA-Z]/g,'');if(alpha.length<20)return null;
  const alphaLower=alpha.toLowerCase();
  const kasiski=kasiskiKeyLengths(ct);const friedman=friedmanKeyLength(ct);
  const candidates=new Set([...kasiski.slice(0,5),friedman]);
  if(candidates.size===0)candidates.add(3);
  let bestScore=-1,bestResult=null;
  for(const kl of candidates){
    if(kl<2||kl>15)continue;
    const key=[];
    for(let pos=0;pos<kl;pos++){
      const stream=[];for(let i=pos;i<alphaLower.length;i+=kl)stream.push(alphaLower.charCodeAt(i)-97);
      let bestShift=0,bestS=-1;
      for(let s=0;s<26;s++){
        let score=0;
        for(const ch of stream){
          let plain;
          if(mode==='beaufort')plain=(s-ch+26)%26;
          else plain=(ch-s+26)%26; // vigenere
          score+=ENGLISH_FREQ[String.fromCharCode(plain+97)]||0;
        }
        if(score>bestS){bestS=score;bestShift=s;}
      }
      key.push(bestShift);
    }
    // Decrypt with found key
    let pt='';let ki=0;
    for(const c of alpha){
      const idx=c.toUpperCase().charCodeAt(0)-65;
      const s=key[ki%key.length];ki++;
      let plain;
      if(mode==='beaufort')plain=(s-idx+26)%26;
      else plain=(idx-s+26)%26;
      pt+=String.fromCharCode(plain+(c<'a'?65:97));
    }
    const sc=scoreEnglish(pt);
    if(sc>bestScore){bestScore=sc;bestResult={key:key.map(k=>String.fromCharCode(k+65)).join(''),text:pt,score:sc,keyLen:kl,mode};}
  }
  return bestResult;
}

/**
 * SMART DECRYPTION PIPELINE
 * Comprehensive decryption system that tries multiple approaches and selects
 * the best result based on English text scoring and ML hints.
 */

function decodeInput(text, mlHint){
  const enc=detectEncoding(text);const steps=[];let decoded=text;

  // Phase 1: Try multi-layer decoding first
  const ml=Encoders.multi.decode(text);
  if(ml.depth>0){decoded=ml.final;ml.layers.forEach((l,i)=>steps.push({l:`Layer ${i+1}: ${l}`,d:i===ml.layers.length-1?ml.final.substring(0,80):'...'}));
  }else{
  // Phase 1b: Decode single encoding layer
  try{
    if(enc==='binary'){decoded=Encoders.binary.decode(text);steps.push({l:'Binary decode',d:decoded});}
    else if(enc==='hex'){decoded=Encoders.hex.decode(text);steps.push({l:'Hex decode',d:decoded});}
    else if(enc==='base64'){decoded=Encoders.base64.decode(text);steps.push({l:'Base64 decode',d:decoded});}
    else if(enc==='decimal'){decoded=Encoders.decimal.decode(text);steps.push({l:'Decimal decode',d:decoded});}
    else if(enc==='octal'){decoded=Encoders.octal.decode(text);steps.push({l:'Octal decode',d:decoded});}
    else if(enc==='polybius'){const d=PolybiusSquare.decode(text);if(d.length>1){decoded=d;steps.push({l:'Polybius decode',d:decoded});}}
    else if(enc==='tap_code'){try{const d=TapCode.decode(text);if(d.length>1){decoded=d;steps.push({l:'Tap code decode',d:decoded});}}catch(e){}}
    else if(enc==='morse'){decoded=Encoders.morse.decode(text);steps.push({l:'Morse decode',d:decoded});}
    else if(enc==='url'){decoded=Encoders.url.decode(text);steps.push({l:'URL decode',d:decoded});}
    else if(enc==='bacon'){decoded=Encoders.bacon.decode(text);steps.push({l:'Bacon decode',d:decoded});}
    else if(enc==='base58'){try{const d=Base58.decode(text.trim());if(d.length>0){decoded=d;steps.push({l:'Base58 decode',d:decoded});}}catch(e){}}
  }catch(e){decoded=text;}

  // Phase 1c: Try additional encoding decoders by pattern detection
  try{
    if(decoded===text){
      // HTML entities: &#123; pattern
      if(/&#\d+;/.test(text)){const d=HTMLEntities.decode(text);if(scoreEnglish(d)>0.2){decoded=d;steps.push({l:'HTML entities decode',d:decoded});}}
      // A1Z26: space-separated numbers 1-26
      if(decoded===text&&/^\s*(\d{1,2}\s+)+\d{1,2}\s*$/.test(text)){const nums=text.trim().split(/\s+/);if(nums.every(n=>{const v=+n;return v>=1&&v<=26;})){const d=A1Z26.decode(text);if(d.length>2){decoded=d;steps.push({l:'A1Z26 decode',d:decoded});}}}
      // Base32: A-Z2-7= only
      if(decoded===text&&/^[A-Z2-7=]+$/i.test(text.trim())&&text.length>=8){try{const d=Base32.decode(text.trim());if(d.length>2&&scoreEnglish(d)>0.15){decoded=d;steps.push({l:'Base32 decode',d:decoded});}}catch(e){}}
      // Polybius: pairs of digits 1-5
      if(decoded===text&&/^[\d\s]+$/.test(text)){const pairs=text.match(/\d{2}/g);if(pairs&&pairs.every(p=>+p[0]>=1&&+p[0]<=5&&+p[1]>=1&&+p[1]<=5)){const d=PolybiusSquare.decode(text);if(d.length>2){decoded=d;steps.push({l:'Polybius decode',d:decoded});}}}
      // ADFGVX: only A,D,F,G,V,X characters — decode maps fractionated pairs back to plaintext chars.
      // Note: ADFGVX output is uppercase with no spaces (the transposition layer is not recoverable
      // without the columnar key), so we accept it even with a modest score — it's better than nothing.
      if(decoded===text&&/^[ADFGVX\s]+$/i.test(text.trim())&&text.trim().length>=4){try{const d=ADFGVX.decode(text);if(d.length>1&&scoreEnglish(d)>scoreEnglish(text)){decoded=d;steps.push({l:'ADFGVX decode',d:decoded});}}catch(e){}}
      // Tap code: dot groups separated by spaces — row dots, space, col dots.
      // Letters separated by double-space; words by ' / '. Minimum ". ." pattern.
      if(decoded===text&&/^[\.\s/]+$/.test(text.trim())&&text.includes('.')){try{const d=TapCode.decode(text);if(d.length>1){decoded=d;steps.push({l:'Tap code decode',d:decoded});}}catch(e){}}
      // NATO phonetic: known NATO words
      if(decoded===text){const words=text.trim().split(/\s+/);const natoWords=['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa','quebec','romeo','sierra','tango','uniform','victor','whiskey','xray','yankee','zulu'];
        if(words.length>=3&&words.filter(w=>natoWords.includes(w.toLowerCase())).length>words.length*0.7){try{const d=NATOPhonetic.decode(text);if(d.length>1){decoded=d;steps.push({l:'NATO phonetic decode',d:decoded});}}catch(e){}}}
      // UUEncode: starts with "begin 644"
      if(decoded===text&&text.trimStart().startsWith('begin 6')){try{const d=UUEncode.decode(text);if(d.length>1&&scoreEnglish(d)>0.1){decoded=d;steps.push({l:'UUEncode decode',d:decoded});}}catch(e){}}
      // Ascii85: <~ ... ~> wrapper
      if(decoded===text&&text.includes('<~')&&text.includes('~>')){try{const d=Ascii85.decode(text);if(d.length>1){decoded=d;steps.push({l:'Ascii85 decode',d:decoded});}}catch(e){}}
      // Phone keypad: space-separated runs of a single repeated digit (e.g. "2 22 222" = ABC)
      // Each token must be all the same digit (2-9 or 0 for space).
      if(decoded===text&&/^[2-90]+(\s+[2-90]+)*$/.test(text.trim())){
        const tokens=text.trim().split(/\s+/);
        if(tokens.length>=2&&tokens.every(tok=>[...tok].every(c=>c===tok[0]))){
          try{const d=PhoneKeypad.decode(text);if(d.length>1){decoded=d;steps.push({l:'Phone keypad decode',d:decoded});}}catch(e){}}}
      // Atbash pre-check — must run BEFORE ROT13/Reverse because the vowel-ratio gate
      // in scoreEnglish() returns 0 for Atbash-encoded English (A/E/I/O/U map to uncommon
      // consonants, dropping the vowel ratio below the 0.15 threshold). When scoreEnglish
      // of the ciphertext is 0, ROT13 and Reverse can fire spuriously from 0 → anything > 0,
      // corrupting 'decoded' before Phase 2 even sees the original text.
      // We detect Atbash by using a raw unigram scorer (no vowel gate) to compare:
      // if the Atbash-transformed input scores substantially better than the raw input, commit it.
      // Atbash pre-check — must run BEFORE ROT13/Reverse.
      // scoreEnglish() uses a vowel-ratio gate that returns 0 for Atbash ciphertext
      // (A/E/I/O/U → Z/V/R/L/F, killing the vowel count). This makes ROT13/Reverse
      // appear to "improve" the score from 0 → anything, corrupting 'decoded' before
      // Phase 2 sees the original text. We pre-empt this by applying Atbash and checking
      // whether the result looks like genuine English (scoreEnglish > 0.18). This threshold
      // is high enough to block Caesar/ROT13 false positives (their Atbash transforms score
      // near 0) while reliably catching real Atbash ciphertext (scores 0.22–0.60+).
      if(decoded===text){const atbCand=Atbash.transform(text);if(scoreEnglish(atbCand)>0.22){decoded=atbCand;steps.push({l:'Atbash',d:decoded});}}
      // ROT13
      if(decoded===text){const r13=ROT13_cipher.decrypt(text);const r13Score=scoreEnglish(r13);if(r13Score>scoreEnglish(text)+0.15&&r13Score>0.20){decoded=r13;steps.push({l:'ROT13',d:decoded});}}
      // Reverse
      if(decoded===text){const rev=ReverseText.encrypt(text);if(scoreEnglish(rev)>scoreEnglish(text)+0.05){decoded=rev;steps.push({l:'Reverse',d:decoded});}}
      // Base58: no 0, O, I, or l — require lowercase or digits to avoid shadowing uppercase-only
      // cipher text like ADFGVX (all six ADFGVX chars happen to be valid base58 characters)
      if(decoded===text&&/^[1-9A-HJ-NP-Za-km-z]+$/.test(text.trim())&&text.trim().length>=8){
        const b58HasLower=/[a-km-z]/.test(text),b58HasDigit=/[1-9]/.test(text);
        if(b58HasLower||b58HasDigit){try{const d=Base58.decode(text.trim());if(d.length>1&&scoreEnglish(d)>0.15){decoded=d;steps.push({l:'Base58 decode',d:decoded});}}catch(e){}}}
    }
  }catch(e){}
  }

  const origScore=scoreEnglish(decoded);
  // Plaintext fast-exit — but veto it if the ML is confident this isn't plaintext.
  // A high scoreEnglish alone isn't enough if the ML sees cipher structure in the features.
  const mlSaysNotPlaintext=mlHint&&!mlHint.lowMargin&&mlHint.confidence>=0.50&&mlHint.cls!=='plaintext';
  if(origScore>0.6&&!mlSaysNotPlaintext)return{decoded,encoding:enc,steps,method:steps.length?steps[steps.length-1].l:'plaintext',runners:[]};
  // Atbash fast-exit: if the Phase 1c Atbash pre-check already decoded the text and the
  // result looks like English (origScore > 0.15), return now. Without this, Phase 2 hill-climbers
  // (Enigma, Affine, Columnar) will run on the already-correct plaintext and "decrypt" it
  // further into gibberish that scores even higher due to the bigram/trigram scorer's
  // tendency to find local optima on any letter sequence.
  const _lastStep=steps.length?steps[steps.length-1].l:'';
  if(_lastStep==='Atbash'&&origScore>0.20)return{decoded,encoding:enc,steps,method:'Atbash',runners:[]};
  // Polybius and TapCode are deterministic decoders — if Phase 1 decoded them, trust it.
  // Without this, Phase 2 hill-climbers (Enigma, Affine) will "improve" already-correct
  // decoded text by running it through a cipher and finding a spurious local optimum.
  // Polybius, TapCode, and Morse are all deterministic decoders — there's no "cracking" 
  // involved, just reversing a known encoding. If Phase 1 decoded them, the result is
  // either correct or garbage. When origScore > 0.10 the decoded text looks sufficiently
  // English-like that we should trust it over Phase 2 hill-climbers.
  // Lower threshold than Atbash (0.20) because these short outputs have fewer chars for
  // the bigram/trigram scorer to work with, pushing scores lower even for correct decodes.
  if((_lastStep==='Polybius decode'||_lastStep==='Tap code decode'||_lastStep==='Morse decode')&&origScore>0.10)
    return{decoded,encoding:enc,steps,method:_lastStep,runners:[]};

  // ADFGVX fast-exit: the decoded result is uppercase-no-spaces (transposition layer isn't recoverable
  // without the key), so scoreEnglish will be low even though it's correct. If the ML is confident
  // this is ADFGVX and Phase1c already decoded it, trust that and skip the cipher crackers — they'd
  // just mangle the already-correct output with a spurious Caesar or Affine shift.
  const lastStep=steps.length?steps[steps.length-1].l:'';
  if(lastStep==='ADFGVX decode'&&mlHint&&mlHint.cls==='adfgvx'&&mlHint.confidence>=0.5){
    return{decoded,encoding:enc,steps,method:'ADFGVX decode',runners:[]};
  }

  // Phase 2: Try all cipher crackers in parallel, collect candidates
  const candidates=[];

  // Caesar brute force
  const cRes=Caesar.crack(decoded);
  if(cRes[0].shift!==0)candidates.push({name:`Caesar shift ${cRes[0].shift}`,text:cRes[0].text,score:cRes[0].score});

  // Atbash — check explicitly before Affine since Affine a=25,b=0 is mathematically
  // identical to Atbash and the Affine cracker might report a=25,b=12 (wrong offset)
  // instead of the canonical a=25,b=0. Atbash gets its own named slot here.
  const atb=Atbash.transform(decoded);
  const atbScore=scoreEnglish(atb);
  candidates.push({name:'Atbash',text:atb,score:atbScore});

  // ROT47
  const r47=ROT47.transform(decoded);candidates.push({name:'ROT47',text:r47,score:scoreEnglish(r47)});

  // Affine brute-force (312 keys) — exclude a=25 since that's Atbash, already handled above.
  // Minimum 20 chars: below this, exhaustive search finds spurious keys by chance.
  if(decoded.replace(/[^a-zA-Z]/g,'').length>=20){
    try{const affRes=AffineCracker.crack(decoded);
      if(affRes[0]&&(affRes[0].a!==1||affRes[0].b!==0)&&affRes[0].a!==25&&affRes[0].score>origScore+0.08)candidates.push({name:`Affine a=${affRes[0].a} b=${affRes[0].b}`,text:affRes[0].text,score:affRes[0].score});}catch(e){}}

  // Scytale brute-force (cols 2-20)
  try{const scRes=ScytaleCracker.crack(decoded);
    if(scRes[0]&&scRes[0].score>origScore+0.05)candidates.push({name:`Scytale cols=${scRes[0].cols}`,text:scRes[0].text,score:scRes[0].score});}catch(e){}

  // Route Cipher brute-force (cols 2-14, spiral route)
  try{const rcRes=RouteCipherCracker.crack(decoded);
    if(rcRes[0]&&rcRes[0].score>origScore+0.05)candidates.push({name:`Route Cipher cols=${rcRes[0].cols}`,text:rcRes[0].text,score:rcRes[0].score});}catch(e){}

  // Playfair hill-climb (needs >= 20 alpha chars, key-based 5x5 grid).
  // Skip when ML is >=70% confident the cipher is Bifid — Playfair and Bifid hill-climbers
  // compete on the same letter-only ciphertext, and Playfair tends to win on raw score
  // even when wrong, because both are unkeyed hill-climbers on the same search space.
  const _mlBifidConf=mlHint&&!mlHint.lowMargin&&mlHint.cls==='bifid'&&mlHint.confidence>=0.70;
  if(!_mlBifidConf&&decoded.length>=20&&/^[a-zA-Z\s]+$/.test(decoded)){
    try{const pfRes=PlayfairCracker.crack(decoded);
      if(pfRes&&pfRes.score>origScore+0.08)candidates.push({name:'Playfair (hill-climb)',text:pfRes.text,score:pfRes.score,key:pfRes.key});}catch(e){}}

  // Bifid hill-climb (needs >= 16 alpha chars, key-based 5x5 grid).
  // When ML is >=70% confident it's Bifid, lower the entry threshold from +0.08 to +0.02.
  if(decoded.length>=16&&/^[a-zA-Z\s]+$/.test(decoded)){
    const _bifidThresh=_mlBifidConf?origScore+0.02:origScore+0.08;
    try{const bfRes=BifidCracker.crack(decoded);
      if(bfRes&&bfRes.score>_bifidThresh){
        // When ML is highly confident it's Bifid, add a 0.15 score boost so Bifid
        // wins ties against Vigenere/Columnar that happen to score slightly higher
        // on the same ciphertext due to the hill-climber finding different local optima.
        const _bfBoost=_mlBifidConf?0.15:0;
        candidates.push({name:'Bifid (hill-climb)',text:bfRes.text,score:bfRes.score+_bfBoost});
      }}catch(e){}}

  // Rail Fence (try rails 2-20)
  try{const rfRes=RailFenceCracker.crack(decoded);
    if(rfRes[0])candidates.push({name:`Rail Fence ${rfRes[0].rails} rails`,text:rfRes[0].text,score:rfRes[0].score});}catch(e){}

  // Columnar transposition (try column counts 2-7 with permutations)
  if(decoded.length>=8&&decoded.length<=200){
    try{const colRes=ColumnarCracker.crack(decoded);
      if(colRes[0])candidates.push({name:`Columnar ${colRes[0].cols} cols (${colRes[0].perm})`,text:colRes[0].text,score:colRes[0].score});}catch(e){}}

  // Vigenère auto-crack
  if(decoded.length>=20){
    const vigRes=crackVigenere(decoded,'vigenere');
    if(vigRes)candidates.push({name:`Vigenère key="${vigRes.key}"`,text:vigRes.text,score:vigRes.score});
    // Beaufort auto-crack
    const beauRes=crackVigenere(decoded,'beaufort');
    if(beauRes)candidates.push({name:`Beaufort key="${beauRes.key}"`,text:beauRes.text,score:beauRes.score});
    // Porta brute-force — tries key lengths 1-8, picks best English score
    try{const portaRes=PortaCracker.crack(decoded);
      if(portaRes&&portaRes.score>origScore+0.05){const portaKeyDisplay=portaRes.key.split('').map(c=>{const idx=c.charCodeAt(0)-65;const row=Math.floor(idx/2);const a=String.fromCharCode(row*2+65);const b=String.fromCharCode(row*2+1+65);return a===c?a+'/'+b:b+'/'+a;}).join('');
      candidates.push({name:`Porta key="${portaRes.key}" (${portaKeyDisplay})`,text:portaRes.text,score:portaRes.score});}}catch(e){}
    // Vigenère Autokey — brute-forces single/double char seeds plus common words
    try{const akRes=AutokeyCracker.crack(decoded);
      if(akRes&&akRes.score>origScore+0.05)candidates.push({name:`Autokey key="${akRes.key}"`,text:akRes.text,score:akRes.score});}catch(e){}
  }

  // XOR single-byte (use scorePrintable for byte-level content)
  const xorRes=XorCipher.crackSingle(decoded);
  if(xorRes[0]){const xScore=Math.max(xorRes[0].score,scorePrintable(xorRes[0].text));
    candidates.push({name:`XOR key=0x${xorRes[0].key.toString(16).padStart(2,'0')}`,text:xorRes[0].text,score:xScore});}

  // XOR repeating-key
  if(decoded.length>30){
    const xrRes=XorCipher.crackRepeating(decoded);
    if(xrRes){const xrScore=Math.max(xrRes.score,scorePrintable(xrRes.text));
      candidates.push({name:`XOR repeating key="${xrRes.key}" (len=${xrRes.keyLen})`,text:xrRes.text,score:xrScore});}}

  // RC4 short key brute-force (1-2 byte keys)
  if(decoded.length>=4&&decoded.length<=500){
    try{const rcRes=RC4.crackShort(decoded,2);
      if(rcRes[0]){const rcScore=Math.max(rcRes[0].score,scorePrintable(rcRes[0].text));
        candidates.push({name:`RC4 key=0x${rcRes[0].key}`,text:rcRes[0].text,score:rcScore});}}catch(e){}}

  // Substitution cipher hill-climber (needs >= 40 chars to be reliable)
  if(decoded.length>=40&&/^[a-zA-Z\s.,!?;:'\-]+$/.test(decoded)){
    try{const subRes=SubstitutionCracker.crack(decoded);
      if(subRes&&subRes.score>origScore+0.08)candidates.push({name:'Substitution (hill-climb)',text:subRes.text,score:subRes.score});}catch(e){}}

  // Enigma brute-force (all 17,576 start positions, 6 rotor orders).
  // Minimum 20 chars: with fewer chars the exhaustive search reliably finds false positives.
  if(decoded.length>=20&&decoded.length<=300&&/^[a-zA-Z\s]+$/.test(decoded)){
    try{const engRes=EnigmaCracker.crack(decoded);
      if(engRes&&engRes.score>origScore+0.08)candidates.push({name:`Enigma ${engRes.rotors} [${engRes.starts.join(',')}]`,text:engRes.text,score:engRes.score});}catch(e){}}

  // Sort candidates by raw English score — no ML boosts applied here.
  // The ML hint is used upstream for fast-exit decisions but doesn't skew
  // the cracker ranking, so the best cryptanalytic result always wins.
  candidates.sort((a,b)=>b.score-a.score);
  const best=candidates[0];
  if(best&&best.score>origScore+0.05){
    const stepEntry={l:best.name,d:best.text.substring(0,100)};
    if(best.key)stepEntry.key=best.key;
    steps.push(stepEntry);
    decoded=best.text;
  }
  // Show runner-up attempts
  const runners=candidates.filter(c=>c!==best&&c.score>0.15).slice(0,5);

  return{decoded,encoding:enc,steps,method:steps.length?steps[steps.length-1].l:'no_cipher',runners};
}
