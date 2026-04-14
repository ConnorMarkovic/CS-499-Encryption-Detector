// ==============================================================================
//  ciphers.js - Cipher implementations for CipherLab
//  Dependencies: none (loads first)
// ==============================================================================

const ENGLISH_FREQ={a:.0817,b:.0149,c:.0278,d:.0425,e:.127,f:.0223,g:.0202,h:.0609,i:.0697,j:.0015,k:.0077,l:.0403,m:.0241,n:.0675,o:.0751,p:.0193,q:.001,r:.0599,s:.0633,t:.0906,u:.0276,v:.0098,w:.0236,x:.0015,y:.0197,z:.0007};

// Common English bigrams with relative frequencies for better scoring
const ENGLISH_BIGRAMS={th:.0356,he:.0307,in:.0243,er:.0205,an:.0199,re:.0185,on:.0176,at:.0149,en:.0145,nd:.0135,ti:.0134,es:.0134,or:.0128,te:.0120,of:.0117,ed:.0117,is:.0113,it:.0112,al:.0109,ar:.0107,st:.0105,to:.0104,nt:.0104,ng:.0095,se:.0093,ha:.0093,as:.0087,ou:.0087,io:.0083,le:.0083,ve:.0083,co:.0079,me:.0079,de:.0076,hi:.0076,ri:.0073,ro:.0073};

function scoreEnglish(text){
  const lc=text.toLowerCase();const alpha=[...lc].filter(c=>c>='a'&&c<='z');const n=alpha.length;
  if(n<3)return 0;
  // Calculate the fraction of text-like characters (alpha + spaces + basic punctuation)
  const textChars=[...text].filter(c=>/[a-zA-Z \.,;:!?'\-]/.test(c)).length;
  const textRatio=textChars/Math.max(text.length,1);
  if(textRatio<0.7)return 0; // Less than 70% text-like indicates non-English content (filters RC4/XOR output)
  const freq={};for(const c of alpha)freq[c]=(freq[c]||0)+1;
  // Unigram chi-squared test (weighted 50%)
  let chi=0;for(let i=0;i<26;i++){const c=String.fromCharCode(97+i);const obs=(freq[c]||0)/n;const exp=ENGLISH_FREQ[c]||.001;chi+=(obs-exp)**2/exp;}
  const uniScore=1/(1+chi);
  // Bigram frequency analysis (weighted 30%)
  if(n<6)return uniScore;
  const biStr=alpha.join('');const biCount={};
  for(let i=0;i<biStr.length-1;i++){const bg=biStr.substring(i,i+2);biCount[bg]=(biCount[bg]||0)+1;}
  const biTotal=biStr.length-1;let biScore=0;
  for(const[bg,expected]of Object.entries(ENGLISH_BIGRAMS)){biScore+=(biCount[bg]||0)/biTotal*expected;}
  biScore=Math.min(1,biScore*120);
  // Word structure analysis (weighted 20%): English typically has spaces forming words of 1-15 characters
  const words=text.trim().split(/\s+/);
  let wordBonus=0;
  if(words.length>1){
    const avgLen=alpha.length/words.length;
    if(avgLen>=2&&avgLen<=12)wordBonus=0.5+0.5*Math.max(0,1-Math.abs(avgLen-4.7)/5);
  }
  return uniScore*0.50+biScore*0.30+wordBonus*0.20;
}

// Score for byte-level content (XOR/RC4 output that may not be pure alphabetic)
function scorePrintable(text){
  const bytes=[...text];const n=bytes.length;if(!n)return 0;
  const printable=bytes.filter(c=>{const code=c.charCodeAt(0);return code>=32&&code<=126;}).length;
  const alphaCount=bytes.filter(c=>/[a-zA-Z]/.test(c)).length;
  const printRatio=printable/n;
  const alphaRatio=alphaCount/n;
  // Must be mostly printable AND mostly alphabetic to be credible
  if(printRatio<0.8||alphaRatio<0.5)return 0;
  const engScore=scoreEnglish(text);
  return engScore;
}

// Caesar cipher implementation
const Caesar={
  shift(text,s){return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const b=c<'a'?65:97;return String.fromCharCode((c.charCodeAt(0)-b+s%26+26)%26+b)}return c}).join('')},
  encrypt(t,s){return this.shift(t,s)},decrypt(t,s){return this.shift(t,-s)},
  crack(ct){const r=[];for(let s=0;s<26;s++){const d=this.shift(ct,-s);r.push({shift:s,text:d,score:scoreEnglish(d)})}r.sort((a,b)=>b.score-a.score);return r}
};

// Vigenère cipher implementation
const Vigenere={
  encrypt(text,key){const k=key.toUpperCase();let ki=0;return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const s=k.charCodeAt(ki%k.length)-65;ki++;const b=c<'a'?65:97;return String.fromCharCode((c.toUpperCase().charCodeAt(0)-65+s)%26+b)}return c}).join('')},
  decrypt(text,key){const k=key.toUpperCase();let ki=0;return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const s=k.charCodeAt(ki%k.length)-65;ki++;const b=c<'a'?65:97;return String.fromCharCode((c.toUpperCase().charCodeAt(0)-65-s+26)%26+b)}return c}).join('')}
};

// Atbash cipher implementation
const Atbash={transform(text){return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const b=c<'a'?65:97;return String.fromCharCode(b+25-(c.charCodeAt(0)-b))}return c}).join('')}};

// Enigma machine simulation (3-rotor Wehrmacht model)
const ROTORS_CFG={I:{w:'EKMFLGDQVZNTOWYHXUSPAIBRCJ',n:16},II:{w:'AJDKSIRUXBLHWTMCQGZNPYFVOE',n:4},III:{w:'BDFHJLCPRTXVZNYEIWGAKMUSQO',n:21},IV:{w:'ESOVPZJAYQUIRHXLNFTGKDCMWB',n:9},V:{w:'VZBRGITYUPSDNHLXAWMJQOFECK',n:25}};
const REFLECTORS={B:'YRUHQSLDPXNGOKMIEBFZCWVJAT',C:'FVPJIAOYEDRZXWGCTKUQSBNMHL'};
function enigmaProcess(text,rotorNames=['III','II','I'],ref='B',starts=[0,0,0]){
  const rotors=rotorNames.map((n,i)=>({w:ROTORS_CFG[n].w,n:ROTORS_CFG[n].n,pos:starts[i]}));
  const refl=REFLECTORS[ref];const clean=text.toUpperCase().replace(/[^A-Z]/g,'');let out='';
  for(const ch of clean){if(rotors[1].pos===rotors[1].n){rotors[1].pos=(rotors[1].pos+1)%26;rotors[2].pos=(rotors[2].pos+1)%26;}
    if(rotors[0].pos===rotors[0].n)rotors[1].pos=(rotors[1].pos+1)%26;rotors[0].pos=(rotors[0].pos+1)%26;
    let c=ch.charCodeAt(0)-65;for(let i=0;i<3;i++){const r=rotors[i];c=(r.w.charCodeAt((c+r.pos)%26)-65-r.pos+26)%26;}
    c=refl.charCodeAt(c)-65;for(let i=2;i>=0;i--){const r=rotors[i];c=(r.w.indexOf(String.fromCharCode((c+r.pos)%26+65))-r.pos+26)%26;}
    out+=String.fromCharCode(c+65);}return out;}

// Substitution cipher helper functions
function genSubKey(rng){const a=[...Array(26)].map((_,i)=>i);for(let i=25;i>0;i--){const j=rng()%(i+1);[a[i],a[j]]=[a[j],a[i]];}return a}
function applySub(text,key){return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const b=c<'a'?65:97;return String.fromCharCode(key[c.toUpperCase().charCodeAt(0)-65]+b)}return c}).join('')}

// Affine cipher implementation
function affineEnc(text,a,b){return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const base=c<'a'?65:97;return String.fromCharCode((a*(c.toUpperCase().charCodeAt(0)-65)+b)%26+base)}return c}).join('')}
// Affine decrypt: apply the modular inverse of 'a' to reverse the encryption
function affineDec(text,a,b){const aInv=modInverse(a,26);return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const base=c<'a'?65:97;return String.fromCharCode(((aInv*((c.toUpperCase().charCodeAt(0)-65-b+26)%26))%26+26)%26+base)}return c}).join('')}

// Rail Fence cipher implementation
function railEnc(text,rails){if(rails<2)return text;const fence=Array.from({length:rails},()=>[]);let r=0,d=1;for(const c of text){fence[r].push(c);if(r===0)d=1;else if(r===rails-1)d=-1;r+=d;}return fence.flat().join('')}

// XOR cipher implementation
const XorCipher={
  encryptSingle(text,key){const b=typeof key==='number'?key:key.charCodeAt(0);return[...text].map(c=>String.fromCharCode(c.charCodeAt(0)^b)).join('')},
  encryptRepeating(text,key){const kb=[...key].map(c=>c.charCodeAt(0));return[...text].map((c,i)=>String.fromCharCode(c.charCodeAt(0)^kb[i%kb.length])).join('')},
  crackSingle(ct){const results=[];for(let k=1;k<256;k++){const pt=[...ct].map(c=>String.fromCharCode(c.charCodeAt(0)^k)).join('');results.push({key:k,text:pt,score:scoreEnglish(pt)});}results.sort((a,b)=>b.score-a.score);return results},
  _hamming(a,b){let d=0;for(let i=0;i<Math.min(a.length,b.length);i++){let x=a.charCodeAt(i)^b.charCodeAt(i);while(x){d+=x&1;x>>=1;}}return d;},
  guessKeyLen(ct,maxLen=20){const scores=[];for(let kl=2;kl<=Math.min(maxLen,Math.floor(ct.length/4));kl++){let total=0,pairs=0;for(let i=0;i+kl*2<=ct.length&&pairs<6;i+=kl){total+=this._hamming(ct.substring(i,i+kl),ct.substring(i+kl,i+kl*2))/kl;pairs++;}if(pairs)scores.push({len:kl,score:total/pairs});}scores.sort((a,b)=>a.score-b.score);return scores.slice(0,5).map(s=>s.len);},
  crackRepeating(ct){const klens=this.guessKeyLen(ct);if(!klens.length)return null;
    let bestScore=-1,bestResult=null;
    for(const kl of klens.slice(0,3)){const key=[];
      for(let pos=0;pos<kl;pos++){const stream=[];for(let i=pos;i<ct.length;i+=kl)stream.push(ct.charCodeAt(i));
        let bestK=0,bestS=-1;for(let k=0;k<256;k++){const dec=stream.map(b=>String.fromCharCode(b^k)).join('');const s=scoreEnglish(dec);if(s>bestS){bestS=s;bestK=k;}}key.push(bestK);}
      const pt=[...ct].map((c,i)=>String.fromCharCode(c.charCodeAt(i)^key[i%key.length])).join('');
      const sc=scoreEnglish(pt);if(sc>bestScore){bestScore=sc;bestResult={key:key.map(k=>String.fromCharCode(k)).join(''),keyBytes:key,text:pt,score:sc,keyLen:kl};}}
    return bestResult;}
};

// RC4 stream cipher implementation
const RC4={
  _ksa(key){const S=Array.from({length:256},(_,i)=>i);let j=0;const kb=[...key].map(c=>c.charCodeAt(0));
    for(let i=0;i<256;i++){j=(j+S[i]+kb[i%kb.length])%256;[S[i],S[j]]=[S[j],S[i]];}return S;},
  _prga(S,len){let i=0,j=0;const out=[];for(let n=0;n<len;n++){i=(i+1)%256;j=(j+S[i])%256;[S[i],S[j]]=[S[j],S[i]];out.push(S[(S[i]+S[j])%256]);}return out;},
  encrypt(text,key){const S=this._ksa(key);const ks=this._prga(S,text.length);return[...text].map((c,i)=>String.fromCharCode(c.charCodeAt(0)^ks[i])).join('');},
  decrypt(ct,key){return this.encrypt(ct,key);},
  crackShort(ct,maxKeyLen=2){const results=[];
    for(let kl=1;kl<=maxKeyLen;kl++){const total=kl===1?256:256*256;
      for(let k=0;k<total;k++){const key=kl===1?String.fromCharCode(k):String.fromCharCode(k>>8,k&0xFF);
        const pt=this.decrypt(ct,key);const sc=scoreEnglish(pt);
        if(sc>0.3)results.push({key:[...key].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(''),text:pt,score:sc});}}
    results.sort((a,b)=>b.score-a.score);return results.slice(0,10);}
};

// Beaufort cipher implementation
const Beaufort={
  transform(text,key){const k=key.toUpperCase();let ki=0;return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const s=k.charCodeAt(ki%k.length)-65;ki++;const b=c<'a'?65:97;return String.fromCharCode((s-(c.toUpperCase().charCodeAt(0)-65)+26)%26+b);}return c;}).join('');},
  encrypt(t,k){return this.transform(t,k);},decrypt(t,k){return this.transform(t,k);}
};

// Porta cipher implementation
const Porta={
  _table:(()=>{const t=[];for(let row=0;row<13;row++){const m={};for(let i=0;i<13;i++){m[i]=(i+row)%13+13;m[(i+row)%13+13]=i;}t.push(m);}return t;})(),
  transform(text,key){const k=key.toUpperCase();let ki=0;return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const row=Math.floor((k.charCodeAt(ki%k.length)-65)/2);ki++;const idx=c.toUpperCase().charCodeAt(0)-65;const b=c<'a'?65:97;const mapped=this._table[row][idx];return String.fromCharCode((mapped!==undefined?mapped:idx)+b);}return c;}).join('');},
  encrypt(t,k){return this.transform(t,k);},decrypt(t,k){return this.transform(t,k);}
};

// Columnar Transposition cipher implementation
const Columnar={
  _order(key){const pairs=[...key.toUpperCase()].map((c,i)=>[c,i]);pairs.sort((a,b)=>a[0]<b[0]?-1:a[0]>b[0]?1:a[1]-b[1]);return pairs.map(p=>p[1]);},
  encrypt(text,key){const ord=this._order(key);const cols=key.length;const padded=text+'X'.repeat((cols-text.length%cols)%cols);
    const grid=[];for(let i=0;i<padded.length;i+=cols)grid.push(padded.substring(i,i+cols));
    let ct='';for(let c=0;c<cols;c++){const srcCol=ord.indexOf(c);for(const row of grid)ct+=row[srcCol];}return ct;},
  decrypt(ct,key){const ord=this._order(key);const cols=key.length;const rows=Math.ceil(ct.length/cols);
    const grid=Array.from({length:rows},()=>Array(cols).fill(''));let pos=0;
    for(let c=0;c<cols;c++){const srcCol=ord.indexOf(c);for(let r=0;r<rows&&pos<ct.length;r++)grid[r][srcCol]=ct[pos++];}
    return grid.map(r=>r.join('')).join('');}
};

// ROT47 cipher implementation
const ROT47={transform(text){return[...text].map(c=>{const code=c.charCodeAt(0);if(code>=33&&code<=126)return String.fromCharCode(33+((code-33+47)%94));return c;}).join('');}};

// Cipher cracking implementations

// Affine cipher brute-force cracker (312 possible keys: 12 valid 'a' values × 26 'b' values)
const AFFINE_VALID_A=[1,3,5,7,9,11,15,17,19,21,23,25];
function modInverse(a,m){for(let x=1;x<m;x++){if((a*x)%m===1)return x;}return 1;}
const AffineCracker={
  crack(ct){const results=[];
    for(const a of AFFINE_VALID_A){const aInv=modInverse(a,26);
      for(let b=0;b<26;b++){
        const pt=[...ct].map(c=>{if(/[a-zA-Z]/.test(c)){const base=c<'a'?65:97;return String.fromCharCode(((aInv*((c.toUpperCase().charCodeAt(0)-65-b+26))%26)+26)%26+base);}return c;}).join('');
        results.push({a,b,aInv,text:pt,score:scoreEnglish(pt)});}}
    results.sort((a,b)=>b.score-a.score);return results;}
};

// Rail Fence cipher brute-force cracker (tries rails 2-20)
const RailFenceCracker={
  decrypt(ct,rails){if(rails<2)return ct;const n=ct.length;
    const offsets=[];let r=0,d=1;for(let i=0;i<n;i++){offsets.push(r);if(r===0)d=1;else if(r===rails-1)d=-1;r+=d;}
    const sorted=offsets.map((r,i)=>({r,i})).sort((a,b)=>a.r-b.r||a.i-b.i);
    const result=new Array(n);sorted.forEach((s,ci)=>result[s.i]=ct[ci]);return result.join('');},
  crack(ct){const results=[];
    for(let rails=2;rails<=Math.min(20,Math.floor(ct.length/2));rails++){
      const pt=this.decrypt(ct,rails);results.push({rails,text:pt,score:scoreEnglish(pt)});}
    results.sort((a,b)=>b.score-a.score);return results;}
};

// Columnar Transposition brute-force cracker (tries column counts 2-8 with permutation search)
const ColumnarCracker={
  _permutations(arr){if(arr.length<=1)return[arr];const result=[];
    for(let i=0;i<arr.length;i++){const rest=[...arr.slice(0,i),...arr.slice(i+1)];
      for(const perm of this._permutations(rest))result.push([arr[i],...perm]);
      if(result.length>5000)return result;}return result;}, // Limit to 5000 permutations to prevent excessive computation
  crack(ct){const results=[];
    for(let cols=2;cols<=Math.min(7,Math.floor(ct.length/2));cols++){
      const rows=Math.ceil(ct.length/cols);
      // Try all column permutations (feasible up to 7! = 5040)
      const colOrder=[...Array(cols).keys()];
      for(const perm of this._permutations(colOrder)){
        // Read columns in perm order
        const grid=Array.from({length:rows},()=>Array(cols).fill(''));let pos=0;
        for(const col of perm){for(let r=0;r<rows&&pos<ct.length;r++){grid[r][col]=ct[pos++];}}
        const pt=grid.map(r=>r.join('')).join('');
        results.push({cols,perm:perm.join(''),text:pt,score:scoreEnglish(pt)});
      }
    }
    results.sort((a,b)=>b.score-a.score);return results.slice(0,10);}
};

// ROT13 cipher implementation
const ROT13_cipher={encrypt(t){return Caesar.encrypt(t,13)},decrypt(t){return Caesar.encrypt(t,13)}};

// A1Z26 cipher implementation
const A1Z26={
  encode(t){return[...t.toUpperCase()].map(c=>{const code=c.charCodeAt(0);if(code>=65&&code<=90)return String(code-64);return c;}).join(' ').replace(/ {2,}/g,' ').trim();},
  decode(t){return t.split(/[\s,]+/).map(n=>{const v=parseInt(n);if(v>=1&&v<=26)return String.fromCharCode(v+64);return n;}).join('');}
};

// Playfair cipher implementation
const Playfair={
  _grid(key){const seen=new Set();const chars=[];for(const c of(key+'ABCDEFGHIKLMNOPQRSTUVWXYZ').toUpperCase()){const ch=c==='J'?'I':c;if(ch>='A'&&ch<='Z'&&!seen.has(ch)){seen.add(ch);chars.push(ch);}}return chars;},
  _pos(grid,c){const idx=grid.indexOf(c==='J'?'I':c);return[Math.floor(idx/5),idx%5];},
  encrypt(text,key){
    const grid=this._grid(key);const clean=text.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    const pairs=[];let i=0;
    while(i<clean.length){const a=clean[i];let b=i+1<clean.length?clean[i+1]:'X';if(a===b){b='X';i++;}else i+=2;pairs.push([a,b]);}
    return pairs.map(([a,b])=>{const[ar,ac]=this._pos(grid,a);const[br,bc]=this._pos(grid,b);
      if(ar===br)return grid[ar*5+(ac+1)%5]+grid[br*5+(bc+1)%5];
      if(ac===bc)return grid[((ar+1)%5)*5+ac]+grid[((br+1)%5)*5+bc];
      return grid[ar*5+bc]+grid[br*5+ac];}).join('');},
  // Decrypt reverses the row/column shift directions
  decrypt(text,key){
    const grid=this._grid(key);const clean=text.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    const pairs=[];for(let i=0;i<clean.length;i+=2)pairs.push([clean[i],clean[i+1]||'X']);
    return pairs.map(([a,b])=>{const[ar,ac]=this._pos(grid,a);const[br,bc]=this._pos(grid,b);
      if(ar===br)return grid[ar*5+(ac+4)%5]+grid[br*5+(bc+4)%5];
      if(ac===bc)return grid[((ar+4)%5)*5+ac]+grid[((br+4)%5)*5+bc];
      return grid[ar*5+bc]+grid[br*5+ac];}).join('');}
};

// Vigenère Autokey cipher implementation
const VigenereAutokey={
  encrypt(text,key){const k=key.toUpperCase();const clean=text.toUpperCase().replace(/[^A-Z]/g,'');let out='',fullKey=k;
    for(let i=0;i<clean.length;i++){const s=fullKey.charCodeAt(i)-65;out+=String.fromCharCode((clean.charCodeAt(i)-65+s)%26+65);fullKey+=clean[i];}return out;},
  // Autokey decrypt recovers the plaintext one char at a time, extending the key as we go
  decrypt(text,key){const k=key.toUpperCase();const clean=text.toUpperCase().replace(/[^A-Z]/g,'');let out='',fullKey=k;
    for(let i=0;i<clean.length;i++){const s=fullKey.charCodeAt(i)-65;const p=String.fromCharCode((clean.charCodeAt(i)-65-s+26)%26+65);out+=p;fullKey+=p;}return out;}
};

// Reverse cipher implementation
const ReverseText={encrypt(t){return[...t].reverse().join('');}};

// Scytale cipher implementation
const Scytale={
  encrypt(text,cols){const clean=text.replace(/[^a-zA-Z]/g,'');const rows=Math.ceil(clean.length/cols);const padded=clean+'X'.repeat(rows*cols-clean.length);
    let out='';for(let c=0;c<cols;c++)for(let r=0;r<rows;r++)out+=padded[r*cols+c];return out;},
  // Read back down the rows to undo the column-wise read
  decrypt(text,cols){const n=text.length;const rows=Math.ceil(n/cols);
    const grid=Array.from({length:rows},()=>Array(cols).fill(''));let pos=0;
    for(let c=0;c<cols;c++)for(let r=0;r<rows;r++){if(pos<n)grid[r][c]=text[pos++];}
    return grid.map(r=>r.join('')).join('').replace(/X+$/,'');}
};

// Route cipher implementation (spiral)
const RouteCipher={
  encrypt(text,cols){const clean=text.replace(/[^a-zA-Z]/g,'');const rows=Math.ceil(clean.length/cols);const padded=clean+'X'.repeat(rows*cols-clean.length);
    const grid=[];for(let i=0;i<rows;i++)grid.push([...padded.substring(i*cols,i*cols+cols)]);
    let out='',top=0,bot=rows-1,left=0,right=cols-1;
    while(top<=bot&&left<=right){for(let i=left;i<=right;i++)out+=grid[top][i];top++;
      for(let i=top;i<=bot;i++)out+=grid[i][right];right--;
      if(top<=bot){for(let i=right;i>=left;i--)out+=grid[bot][i];bot--;}
      if(left<=right){for(let i=bot;i>=top;i--)out+=grid[i][left];left++;}}return out;},
  // Reverse-map the spiral order back to grid positions, then read row by row
  decrypt(text,cols){const n=text.length;const rows=Math.ceil(n/cols);
    const grid=Array.from({length:rows},()=>Array(cols).fill(''));
    const order=[];let top=0,bot=rows-1,left=0,right=cols-1;
    while(top<=bot&&left<=right){
      for(let i=left;i<=right;i++)order.push([top,i]);top++;
      for(let i=top;i<=bot;i++)order.push([i,right]);right--;
      if(top<=bot){for(let i=right;i>=left;i--)order.push([bot,i]);bot--;}
      if(left<=right){for(let i=bot;i>=top;i--)order.push([i,left]);left++;}}
    for(let i=0;i<Math.min(order.length,n);i++){const[r,c]=order[i];grid[r][c]=text[i];}
    return grid.map(r=>r.join('')).join('').replace(/X+$/,'');}
};

// Base32 encoding implementation
const Base32={
  _c:'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
  encode(t){const bytes=[...t].map(c=>c.charCodeAt(0));let bits='';for(const b of bytes)bits+=b.toString(2).padStart(8,'0');
    while(bits.length%5)bits+='0';let out='';for(let i=0;i<bits.length;i+=5)out+=this._c[parseInt(bits.substring(i,i+5),2)];
    while(out.length%8)out+='=';return out;},
  decode(t){const clean=t.replace(/=/g,'');let bits='';for(const c of clean){const v=this._c.indexOf(c.toUpperCase());if(v>=0)bits+=v.toString(2).padStart(5,'0');}
    let out='';for(let i=0;i+8<=bits.length;i+=8)out+=String.fromCharCode(parseInt(bits.substring(i,i+8),2));return out;}
};

// Base58 encoding implementation
const Base58={
  _c:'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
  encode(t){let bytes=[...t].map(c=>c.charCodeAt(0));let num=0n;for(const b of bytes)num=num*256n+BigInt(b);
    let out='';while(num>0n){out=this._c[Number(num%58n)]+out;num=num/58n;}
    for(const b of bytes){if(b===0)out=this._c[0]+out;else break;}return out||this._c[0];},
  // Decode by converting the base-58 number back to bytes
  decode(t){let num=0n;for(const c of t){const idx=this._c.indexOf(c);if(idx<0)continue;num=num*58n+BigInt(idx);}
    const bytes=[];while(num>0n){bytes.unshift(Number(num%256n));num=num/256n;}
    for(const c of t){if(c===this._c[0])bytes.unshift(0);else break;}
    return bytes.map(b=>String.fromCharCode(b)).join('');}
};

// Ascii85 encoding implementation
const Ascii85={
  encode(t){const bytes=[...t].map(c=>c.charCodeAt(0));while(bytes.length%4)bytes.push(0);
    let out='<~';for(let i=0;i<bytes.length;i+=4){
      let val=((bytes[i]<<24)|(bytes[i+1]<<16)|(bytes[i+2]<<8)|bytes[i+3])>>>0;
      if(val===0){out+='z';continue;}const chars=[];for(let j=4;j>=0;j--){chars[j]=String.fromCharCode(val%85+33);val=Math.floor(val/85);}out+=chars.join('');}
    return out+'~>';},
  decode(t){let s=t.replace(/^<~/,'').replace(/~>$/,'');let out=[];
    for(let i=0;i<s.length;){if(s[i]==='z'){out.push(0,0,0,0);i++;continue;}
      let val=0;for(let j=0;j<5;j++){const c=i+j<s.length?s.charCodeAt(i+j)-33:84;val=val*85+c;}
      out.push((val>>>24)&255,(val>>>16)&255,(val>>>8)&255,val&255);i+=5;}
    return out.map(b=>String.fromCharCode(b)).join('');}
};

// UUEncode implementation
const UUEncode={
  encode(t){const bytes=[...t].map(c=>c.charCodeAt(0));let out='begin 644 data\n';
    for(let i=0;i<bytes.length;i+=45){const chunk=bytes.slice(i,i+45);out+=String.fromCharCode(chunk.length+32);
      for(let j=0;j<chunk.length;j+=3){const a=chunk[j]||0,b=chunk[j+1]||0,c=chunk[j+2]||0;
        out+=String.fromCharCode(((a>>2)&63)+32)+String.fromCharCode((((a<<4)|(b>>4))&63)+32)+String.fromCharCode((((b<<2)|(c>>6))&63)+32)+String.fromCharCode((c&63)+32);}out+='\n';}
    return out+'`\nend';},
  decode(t){const lines=t.split('\n').filter(l=>!l.startsWith('begin')&&l!=='end'&&l!=='`');
    let out=[];for(const line of lines){if(!line.length)continue;const len=line.charCodeAt(0)-32;if(len<=0)continue;
      for(let i=1,b=0;b<len;i+=4,b+=3){const c1=(line.charCodeAt(i)||32)-32,c2=(line.charCodeAt(i+1)||32)-32,c3=(line.charCodeAt(i+2)||32)-32,c4=(line.charCodeAt(i+3)||32)-32;
        out.push((c1<<2)|(c2>>4));if(b+1<len)out.push(((c2<<4)|(c3>>2))&255);if(b+2<len)out.push(((c3<<6)|c4)&255);}}
    return out.map(b=>String.fromCharCode(b)).join('');}
};

// HTML Entities encoding implementation
const HTMLEntities={
  encode(t){return[...t].map(c=>'&#'+c.charCodeAt(0)+';').join('');},
  decode(t){return t.replace(/&#(\d+);/g,(_,n)=>String.fromCharCode(+n));}
};

// Bifid cipher implementation
const Bifid={
  _grid(key){const seen=new Set();const chars=[];for(const c of(key+'ABCDEFGHIKLMNOPQRSTUVWXYZ').toUpperCase()){const ch=c==='J'?'I':c;if(ch>='A'&&ch<='Z'&&!seen.has(ch)){seen.add(ch);chars.push(ch);}}return chars;},
  encrypt(text,key){const grid=this._grid(key);const clean=text.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    const rows=[],cols=[];for(const c of clean){const idx=grid.indexOf(c);rows.push(Math.floor(idx/5));cols.push(idx%5);}
    const combined=[...rows,...cols];let out='';for(let i=0;i<combined.length;i+=2)out+=grid[combined[i]*5+combined[i+1]];return out;},
  // Split the combined sequence back into row/col halves and look up each character
  decrypt(text,key){const grid=this._grid(key);const clean=text.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    const combined=[];for(const c of clean){const idx=grid.indexOf(c);combined.push(Math.floor(idx/5),idx%5);}
    const half=combined.length/2;const rows=combined.slice(0,half);const cols=combined.slice(half);
    let out='';for(let i=0;i<rows.length;i++)out+=grid[rows[i]*5+cols[i]];return out;}
};

// Polybius Square implementation
const PolybiusSquare={
  encode(t){const clean=t.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    return[...clean].map(c=>{let idx=c.charCodeAt(0)-65;if(idx>8)idx--;return String(Math.floor(idx/5)+1)+String(idx%5+1);}).join(' ');},
  decode(t){const pairs=t.match(/\d{2}/g)||[];return pairs.map(p=>{const r=+p[0]-1,c=+p[1]-1;let idx=r*5+c;if(idx>=8)idx++;return String.fromCharCode(idx+65);}).join('');}
};

// ADFGVX cipher implementation
const ADFGVX={
  _c:'ADFGVX',_g:'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  encode(t){const clean=t.toUpperCase().replace(/[^A-Z0-9]/g,'');
    return[...clean].map(c=>{const idx=this._g.indexOf(c);if(idx<0)return'';return this._c[Math.floor(idx/6)]+this._c[idx%6];}).join(' ');},
  decode(t){const pairs=t.replace(/\s+/g,'').match(/.{2}/g)||[];
    return pairs.map(p=>{const r=this._c.indexOf(p[0]),c=this._c.indexOf(p[1]);if(r<0||c<0)return'';return this._g[r*6+c]||'';}).join('');}
};

// Tap code implementation
const TapCode={
  encode(t){const clean=t.toUpperCase().replace(/K/g,'C').replace(/[^A-Z]/g,'');
    return[...clean].map(c=>{let idx=c.charCodeAt(0)-65;if(idx>10)idx--;return(Math.floor(idx/5)+1)+'.'+(idx%5+1);}).join(' ');},
  decode(t){const pairs=t.match(/\d\.\d/g)||[];
    return pairs.map(p=>{const r=+p[0]-1,c=+p[2]-1;let idx=r*5+c;if(idx>=10)idx++;return String.fromCharCode(idx+65);}).join('');}
};

// Phone keypad encoding implementation
const PhoneKeypad={
  _m:{A:'2',B:'2',C:'2',D:'3',E:'3',F:'3',G:'4',H:'4',I:'4',J:'5',K:'5',L:'5',M:'6',N:'6',O:'6',P:'7',Q:'7',R:'7',S:'7',T:'8',U:'8',V:'8',W:'9',X:'9',Y:'9',Z:'9',' ':'0'},
  _r:{'2':'ABC','3':'DEF','4':'GHI','5':'JKL','6':'MNO','7':'PQRS','8':'TUV','9':'WXYZ','0':' '},
  encode(t){return[...t.toUpperCase()].map(c=>this._m[c]||'').join('');},
  decode(t){return[...t].map(c=>this._r[c]?this._r[c][0]:c).join('');}
};

// NATO phonetic alphabet implementation
const NATOPhonetic={
  _w:{A:'Alpha',B:'Bravo',C:'Charlie',D:'Delta',E:'Echo',F:'Foxtrot',G:'Golf',H:'Hotel',I:'India',J:'Juliet',K:'Kilo',L:'Lima',M:'Mike',N:'November',O:'Oscar',P:'Papa',Q:'Quebec',R:'Romeo',S:'Sierra',T:'Tango',U:'Uniform',V:'Victor',W:'Whiskey',X:'Xray',Y:'Yankee',Z:'Zulu'},
  _r:null,
  _rev(){if(!this._r){this._r={};for(const k in this._w)this._r[this._w[k].toLowerCase()]=k;}return this._r;},
  encode(t){return[...t.toUpperCase()].map(c=>this._w[c]||c).join(' ').replace(/ {2,}/g,' ').trim();},
  decode(t){const rev=this._rev();return t.split(/\s+/).map(w=>{const l=w.toLowerCase();return rev[l]||w;}).join('');}
};

// Word substitution cipher implementation
const WordSub={
  _pool:['alpha','bravo','charlie','delta','echo','foxtrot','golf','hotel','india','juliet','kilo','lima','mike','november','oscar','papa','quebec','romeo','sierra','tango','uniform','victor','whiskey','xray','yankee','zulu','one','two','three','four','five','six','seven','eight','nine','zero','red','blue','green','black','white','iron','steel','stone','fire','water','earth','wind','star','moon','sun'],
  encrypt(text,seed){let s=seed||Date.now();const rng=()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff;};
    const words=text.toLowerCase().split(/\s+/);const map={};
    return words.map(w=>{const clean=w.replace(/[^a-z]/g,'');if(clean.length<=2)return w;if(!map[clean])map[clean]=this._pool[Math.floor(rng()*this._pool.length)];return map[clean];}).join(' ');}
};

// Hex shuffle cipher implementation
const HexShuffle={
  encrypt(text,seed){const hex=[...text].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
    const pairs=[];for(let i=0;i<hex.length;i+=2)pairs.push(hex.substring(i,i+2));
    let s=seed||42;const rng=()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff;};
    for(let i=pairs.length-1;i>0;i--){const j=Math.floor(rng()*(i+1));[pairs[i],pairs[j]]=[pairs[j],pairs[i]];}
    return pairs.join('');}
};
