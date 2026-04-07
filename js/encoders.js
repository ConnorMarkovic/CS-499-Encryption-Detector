// ═══════════════════════════════════════════════════════════════════════
//  encoders.js — All encoding/decoding implementations
//  Dependencies: none
// ═══════════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════════
//  ENCODING IMPLEMENTATIONS (encoders + decoders)
// ═══════════════════════════════════════════════════════════════════════

const Encoders={
  binary:{encode(t){return[...t].map(c=>c.charCodeAt(0).toString(2).padStart(8,'0')).join(' ')},
    decode(t){return t.replace(/\s+/g,' ').split(' ').map(b=>String.fromCharCode(parseInt(b,2))).join('')}},
  hex:{encode(t){return[...t].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join('')},
    decode(t){const c=t.replace(/\s/g,'');let s='';for(let i=0;i<c.length;i+=2)s+=String.fromCharCode(parseInt(c.substr(i,2),16));return s}},
  base64:{encode(t){return btoa(t)},decode(t){return atob(t.trim())}},
  octal:{encode(t){return[...t].map(c=>c.charCodeAt(0).toString(8).padStart(3,'0')).join('')},
    decode(t){const c=t.replace(/\s/g,'');let s='';for(let i=0;i<c.length;i+=3)s+=String.fromCharCode(parseInt(c.substr(i,3),8));return s}},
  decimal:{encode(t){return[...t].map(c=>c.charCodeAt(0)).join(' ')},
    decode(t){return t.trim().split(/\s+/).map(n=>String.fromCharCode(+n)).join('')}},
  url:{encode(t){return encodeURIComponent(t)},decode(t){return decodeURIComponent(t)}},
  morse:{encode(t){return[...t.toUpperCase()].map(c=>c===' '?' / ':MORSE_MAP[c]||'').filter(Boolean).join(' ')},
    decode(t){return decodeMorse(t)}},
  bacon:{
    _map:{A:'AAAAA',B:'AAAAB',C:'AAABA',D:'AAABB',E:'AABAA',F:'AABAB',G:'AABBA',H:'AABBB',I:'ABAAA',J:'ABAAA',K:'ABAAB',L:'ABABA',M:'ABABB',N:'ABBAA',O:'ABBAB',P:'ABBBA',Q:'ABBBB',R:'BAAAA',S:'BAAAB',T:'BAABA',U:'BAABB',V:'BAABB',W:'BABAA',X:'BABAB',Y:'BABBA',Z:'BABBB'},
    encode(t){return[...t.toUpperCase()].map(c=>this._map[c]||'').join('')},
    decode(t){const rev={};for(const[k,v]of Object.entries(this._map)){if(!rev[v])rev[v]=k;}const clean=t.toUpperCase().replace(/[^AB]/g,'');let s='';for(let i=0;i+5<=clean.length;i+=5)s+=rev[clean.substr(i,5)]||'?';return s}},
  multi:{encode(t){let e=t;const layers=[];const choices=['hex','base64'];
    const n=2+Math.floor(Math.random()*2);
    for(let i=0;i<n;i++){const enc=choices[Math.floor(Math.random()*choices.length)];
      if(enc==='hex')e=[...e].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
      else e=btoa(e);layers.push(enc);}
    return{encoded:e,layers}},
    decode(t){let d=t;const steps=[];for(let depth=0;depth<10;depth++){
      const clean=d.replace(/\s/g,'');
      if(/^[0-9a-fA-F]+$/.test(clean)&&clean.length%2===0&&clean.length>=4){try{const dec=Encoders.hex.decode(clean);if([...dec].every(c=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126)){d=dec;steps.push('hex');continue;}}catch(e){}}
      if(/^[A-Za-z0-9+/=]+$/.test(clean)&&clean.length>=4){try{const dec=atob(clean);if([...dec].every(c=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126)){d=dec;steps.push('base64');continue;}}catch(e){}}
      break;}
    return{final:d,layers:steps,depth:steps.length}}},
};

// ═══════════════════════════════════════════════════════════════════════
//  ENCODING DETECTION + DECODE
// ═══════════════════════════════════════════════════════════════════════

function detectEncoding(text){
  const clean=text.replace(/\s/g,'');
  if(/^[01]+$/.test(clean)&&clean.length>=8)return'binary';
  if(/^[0-7]+$/.test(clean)&&clean.length>=3&&clean.length%3===0)return'octal';
  if(/^(\d{2,3}\s+)*\d{2,3}$/.test(text.trim())){const nums=text.trim().split(/\s+/).map(Number);if(nums.every(n=>n>=32&&n<=126))return'decimal';}
  const upper=clean.toUpperCase();if(/^[AB]+$/.test(upper)&&upper.length>=5&&upper.length%5===0)return'bacon';
  if(/^[0-9a-fA-F]+$/.test(clean)&&clean.length%2===0&&clean.length>=2)return'hex';
  if(/^[A-Za-z0-9+/=]+$/.test(clean)&&clean.length>=4&&(clean.endsWith('=')||clean.length%4===0)){
    // Require at least one of: mixed case, digits, +, /, or = to avoid false positives on uppercase cipher text
    const hasLower=/[a-z]/.test(clean),hasUpper=/[A-Z]/.test(clean),hasDigit=/[0-9]/.test(clean),hasSpecial=/[+/=]/.test(clean);
    if((hasLower&&hasUpper)||hasDigit||hasSpecial)return'base64';
  }
  if(/%[0-9A-Fa-f]{2}/.test(text)&&text.split('%').length>3)return'url';
  if(/^[.\-\s/|]+$/.test(text.trim()))return'morse';
  return'plaintext';
}

const MORSE_MAP={'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--','Z':'--..','0':'-----','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...','8':'---..','9':'----.'};
const MORSE_REV=Object.fromEntries(Object.entries(MORSE_MAP).map(([k,v])=>[v,k]));
function decodeMorse(text){return text.trim().split(/\s{2,}/).map(w=>w.split(/\s+/).map(c=>MORSE_REV[c]||'?').join('')).join(' ')}
