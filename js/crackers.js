// ═══════════════════════════════════════════════════════════════════════
//  crackers.js — Vigenère/Beaufort auto-cracker + smart decrypt pipeline
//  Dependencies: ciphers.js, encoders.js
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
//  VIGENÈRE / BEAUFORT / PORTA AUTO-CRACKER (Kasiski + Friedman)
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
//  SMART DECRYPT PIPELINE (tries everything, picks best)
// ═══════════════════════════════════════════════════════════════════════

function decodeInput(text){
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
    else if(enc==='morse'){decoded=Encoders.morse.decode(text);steps.push({l:'Morse decode',d:decoded});}
    else if(enc==='url'){decoded=Encoders.url.decode(text);steps.push({l:'URL decode',d:decoded});}
    else if(enc==='bacon'){decoded=Encoders.bacon.decode(text);steps.push({l:'Bacon decode',d:decoded});}
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
      // ADFGVX: only A,D,F,G,V,X characters
      if(decoded===text&&/^[ADFGVX\s]+$/i.test(text.trim())&&text.trim().length>=4){try{const d=ADFGVX.decode(text);if(d.length>1){decoded=d;steps.push({l:'ADFGVX decode',d:decoded});}}catch(e){}}
      // Tap code: N.N pairs
      if(decoded===text&&/^\d\.\d(\s+\d\.\d)*$/.test(text.trim())){try{const d=TapCode.decode(text);if(d.length>1){decoded=d;steps.push({l:'Tap code decode',d:decoded});}}catch(e){}}
      // NATO phonetic: known NATO words
      if(decoded===text){const words=text.trim().split(/\s+/);const natoWords=['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa','quebec','romeo','sierra','tango','uniform','victor','whiskey','xray','yankee','zulu'];
        if(words.length>=3&&words.filter(w=>natoWords.includes(w.toLowerCase())).length>words.length*0.7){try{const d=NATOPhonetic.decode(text);if(d.length>1){decoded=d;steps.push({l:'NATO phonetic decode',d:decoded});}}catch(e){}}}
      // UUEncode: starts with "begin 644"
      if(decoded===text&&text.trimStart().startsWith('begin 6')){try{const d=UUEncode.decode(text);if(d.length>1&&scoreEnglish(d)>0.1){decoded=d;steps.push({l:'UUEncode decode',d:decoded});}}catch(e){}}
      // Ascii85: <~ ... ~> wrapper
      if(decoded===text&&text.includes('<~')&&text.includes('~>')){try{const d=Ascii85.decode(text);if(d.length>1){decoded=d;steps.push({l:'Ascii85 decode',d:decoded});}}catch(e){}}
      // Phone keypad: all digits 2-9
      if(decoded===text&&/^[0-9]+$/.test(text.trim())&&text.length>=5){const digits=text.trim();if([...digits].every(d=>'023456789'.includes(d))){try{const d=PhoneKeypad.decode(digits);if(d.length>2){decoded=d;steps.push({l:'Phone keypad decode',d:decoded});}}catch(e){}}}
      // ROT13
      if(decoded===text){const r13=ROT13_cipher.decrypt(text);if(scoreEnglish(r13)>scoreEnglish(text)+0.05){decoded=r13;steps.push({l:'ROT13',d:decoded});}}
      // Reverse
      if(decoded===text){const rev=ReverseText.encrypt(text);if(scoreEnglish(rev)>scoreEnglish(text)+0.05){decoded=rev;steps.push({l:'Reverse',d:decoded});}}
    }
  }catch(e){}
  }

  const origScore=scoreEnglish(decoded);
  if(origScore>0.6)return{decoded,encoding:enc,steps,method:steps.length?steps[steps.length-1].l:'plaintext'};

  // Phase 2: Try all cipher crackers in parallel, collect candidates
  const candidates=[];

  // Caesar brute force
  const cRes=Caesar.crack(decoded);
  if(cRes[0].shift!==0)candidates.push({name:`Caesar shift ${cRes[0].shift}`,text:cRes[0].text,score:cRes[0].score});

  // Atbash
  const atb=Atbash.transform(decoded);candidates.push({name:'Atbash',text:atb,score:scoreEnglish(atb)});

  // ROT47
  const r47=ROT47.transform(decoded);candidates.push({name:'ROT47',text:r47,score:scoreEnglish(r47)});

  // Affine brute-force (312 keys)
  try{const affRes=AffineCracker.crack(decoded);
    if(affRes[0]&&(affRes[0].a!==1||affRes[0].b!==0))candidates.push({name:`Affine a=${affRes[0].a} b=${affRes[0].b}`,text:affRes[0].text,score:affRes[0].score});}catch(e){}

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

  // Pick the best candidate that beats the original
  candidates.sort((a,b)=>b.score-a.score);
  const best=candidates[0];
  if(best&&best.score>origScore+0.05){
    steps.push({l:best.name,d:best.text.substring(0,100)});
    decoded=best.text;
  }
  // Show runner-up attempts
  const runners=candidates.filter(c=>c!==best&&c.score>0.15).slice(0,5);

  return{decoded,encoding:enc,steps,method:steps.length?steps[steps.length-1].l:'no_cipher',runners};
}
