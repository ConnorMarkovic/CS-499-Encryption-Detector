/**
 * CipherLab - Cipher Implementation Module
 * 
 * This module contains implementations of classical and historical ciphers used by the
 * machine learning classifier. Each cipher includes both encryption and decryption
 * methods for testing and demonstration purposes.
 * 
 * Dependencies: None (loaded first)
 */

/**
 * UTILITY FUNCTIONS
 * These helper functions preserve original text formatting (spaces, punctuation)
 * when ciphers process only alphabetic characters.
 */
/**
 * Restores original spacing and punctuation after cipher processing
 * @param {string} originalText - The original input text with spacing
 * @param {string} processedText - The cipher output (alphabetic only)
 * @returns {string} Processed text with original formatting restored
 */
function preserveSpaces(originalText, processedText) {
  if (!originalText || !processedText) return processedText;
  
  const original = [...originalText];
  const processed = [...processedText];
  const result = [];
  
  let processedIndex = 0;
  for (let i = 0; i < original.length; i++) {
    const char = original[i];
    
    // If original character is alphabetic, use next processed character
    if (/[a-zA-Z]/.test(char)) {
      if (processedIndex < processed.length) {
        result.push(processed[processedIndex++]);
      } else {
        // If we run out of processed characters, use original
        result.push(char);
      }
    } else {
      // Preserve spaces, punctuation, numbers as-is
      result.push(char);
    }
  }
  
  // If there are remaining processed characters, append them
  while (processedIndex < processed.length) {
    result.push(processed[processedIndex++]);
  }
  
  return result.join('');
}

// Create a wrapper for ciphers that strip spaces
function withSpacePreservation(cipherFunc) {
  return function(text, ...args) {
    const result = cipherFunc.call(this, text, ...args);
    return preserveSpaces(text, result);
  };
}

const ENGLISH_FREQ={a:.0817,b:.0149,c:.0278,d:.0425,e:.127,f:.0223,g:.0202,h:.0609,i:.0697,j:.0015,k:.0077,l:.0403,m:.0241,n:.0675,o:.0751,p:.0193,q:.001,r:.0599,s:.0633,t:.0906,u:.0276,v:.0098,w:.0236,x:.0015,y:.0197,z:.0007};

// Common English bigrams with relative frequencies for better scoring
const ENGLISH_BIGRAMS={th:.0356,he:.0307,in:.0243,er:.0205,an:.0199,re:.0185,on:.0176,at:.0149,en:.0145,nd:.0135,ti:.0134,es:.0134,or:.0128,te:.0120,of:.0117,ed:.0117,is:.0113,it:.0112,al:.0109,ar:.0107,st:.0105,to:.0104,nt:.0104,ng:.0095,se:.0093,ha:.0093,as:.0087,ou:.0087,io:.0083,le:.0083,ve:.0083,co:.0079,me:.0079,de:.0076,hi:.0076,ri:.0073,ro:.0073};

// ~360 of the most common English words for plaintext verification.
// Used as a dictionary-coverage check in scoreEnglish: real English text
// should have a meaningful fraction of its tokens present here.
// Top 50 English trigrams with relative frequencies.
// Trigrams are far more discriminating than bigrams: real English text hits
// these patterns consistently while cipher output almost never does.
// Multiplier of 400 normalises the raw dot-product score to a 0-1 range.
const ENGLISH_TRIGRAMS={the:0.03508,and:0.02356,ing:0.01920,ion:0.01787,ent:0.01675,ati:0.01487,for:0.01380,her:0.01372,ter:0.01362,hat:0.01312,tha:0.01309,ere:0.01308,con:0.01248,all:0.01195,ate:0.01158,tio:0.01136,ver:0.01127,his:0.01118,res:0.01111,thi:0.01104,est:0.01080,com:0.01013,eve:0.00985,per:0.00978,ons:0.00967,ous:0.00956,tin:0.00950,men:0.00943,whi:0.00940,ith:0.00935,sta:0.00922,nce:0.00917,ont:0.00913,not:0.00907,rea:0.00898,nti:0.00891,int:0.00885,oth:0.00879,ens:0.00876,led:0.00871,our:0.00869,ali:0.00864,ple:0.00859,ore:0.00856,ble:0.00851,pro:0.00847,edt:0.00843,ive:0.00839,hav:0.00836,igh:0.00832};


// English quadgram log-probability table (Olson 2007, Practical Cryptanalysis).
// 268 entries. Scores: correct decrypt ~-7.5, wrong key ~-9.6, random ~-9.8.
// The ~2.1 point gap between wrong-key and correct decryption gives the SA
// hill-climber a strong gradient across the 25! Playfair/Bifid key space.
// Floor -9.7581 represents quadgrams not observed in the reference corpus.
const ENGLISH_QUADGRAMS={
  tion:-3.3836,atio:-3.8256,that:-3.919,ther:-4.0161,with:-4.0464,this:-4.096,ment:-4.1111,
  ions:-4.1252,ting:-4.1331,ents:-4.2379,ight:-4.3036,nter:-4.3666,have:-4.3807,from:-4.3863,
  ance:-4.3877,ough:-4.4158,ness:-4.4288,heir:-4.4794,here:-4.4967,they:-4.5103,ould:-4.5132,
  were:-4.5435,tive:-4.5735,ical:-4.6059,hich:-4.6249,eing:-4.6566,ally:-4.6669,iver:-4.6798,
  each:-4.6861,your:-4.7082,been:-4.7152,come:-4.7515,eral:-4.7622,will:-4.7703,into:-4.7829,
  some:-4.7905,time:-4.8011,what:-4.8042,when:-4.8171,more:-4.8322,than:-4.8442,high:-4.8483,
  make:-4.8684,part:-4.8931,know:-4.9048,form:-4.9249,also:-4.9303,even:-4.9487,most:-4.9655,
  only:-4.9751,much:-4.9935,such:-5.0078,like:-5.0185,good:-5.0332,said:-5.047,onal:-5.0582,
  area:-5.0734,both:-5.093,give:-5.1047,same:-5.1207,thus:-5.1369,year:-5.1536,less:-5.1704,
  rate:-5.1873,ward:-5.2049,woul:-5.2095,ound:-5.2226,ture:-5.2405,real:-5.259,ways:-5.2777,
  work:-5.2966,hand:-5.3162,them:-5.336,last:-5.3561,over:-5.3769,long:-5.3979,take:-5.4193,
  then:-5.4273,just:-5.4415,very:-5.4639,back:-5.4868,ence:-5.5105,nder:-5.5346,worl:-5.5534,
  keep:-5.5591,sion:-5.5847,ster:-5.6107,well:-5.6372,ated:-5.6648,help:-5.693,ered:-5.7218,
  cont:-5.7327,ring:-5.7519,ever:-5.7827,seen:-5.8143,sing:-5.8474,call:-5.8813,ling:-5.9162,
  line:-5.9404,must:-5.9529,want:-5.9626,ient:-5.9626,comp:-5.9626,cons:-5.9626,coun:-5.9626,
  tran:-5.9626,type:-5.9626,user:-5.9626,view:-5.9626,ning:-5.9906,ding:-6.0296,used:-6.0708,
  ttac:-6.0945,writ:-6.0945,pres:-6.0945,comm:-6.0945,sent:-6.1134,home:-6.1205,land:-6.1205,
  king:-6.1205,done:-6.1576,best:-6.2027,case:-6.2046,ware:-6.2465,cent:-6.2465,cond:-6.2465,
  syst:-6.2465,tech:-6.2465,toge:-6.2465,trea:-6.2465,unit:-6.2465,ater:-6.2534,reat:-6.2768,
  name:-6.2768,love:-6.2768,upon:-6.2768,fore:-6.3044,nfor:-6.359,forc:-6.4163,goin:-6.4259,
  wait:-6.4259,conf:-6.4259,cour:-6.4259,oper:-6.4259,tota:-6.4259,univ:-6.4259,grea:-6.4439,
  wing:-6.4622,rest:-6.4622,past:-6.4622,orce:-6.4766,word:-6.5,tack:-6.5392,rein:-6.5418,
  einf:-6.58,enem:-6.6109,rack:-6.6446,eter:-6.6446,visi:-6.6446,walk:-6.6446,warn:-6.6446,
  prep:-6.6446,prov:-6.6446,proc:-6.6446,conv:-6.6446,trad:-6.6446,util:-6.6446,head:-6.667,
  nemy:-6.6847,read:-6.69,game:-6.69,able:-6.69,band:-6.69,down:-6.69,look:-6.69,
  open:-6.69,test:-6.69,fast:-6.69,atta:-6.7136,info:-6.7136,send:-6.7623,thee:-6.7656,
  lead:-6.8136,mine:-6.8136,dear:-6.8136,turn:-6.8136,plan:-6.8136,fall:-6.8136,dent:-6.8136,
  iter:-6.8136,dawn:-6.8959,bein:-6.9249,vita:-6.9249,zero:-6.9249,cros:-6.9249,char:-6.9249,
  clos:-6.9249,topi:-6.9249,viol:-6.9249,fear:-6.9855,hear:-6.9855,near:-6.9855,song:-6.9855,
  town:-6.9855,book:-6.9855,tell:-6.9855,hall:-6.9855,rent:-6.9855,went:-6.9855,prev:-6.9855,
  acks:-7.05,rcem:-7.119,bear:-7.1554,feel:-7.1554,earn:-7.1554,sand:-7.1554,show:-7.1554,
  lack:-7.1554,wall:-7.1554,lent:-7.1554,doin:-7.3157,volu:-7.3157,zone:-7.3157,chil:-7.3157,
  virt:-7.3157,ceme:-7.3602,meet:-7.3602,flow:-7.3602,rock:-7.3602,fill:-7.3602,sell:-7.3602,
  ball:-7.3602,gent:-7.3602,tent:-7.3602,ince:-7.4555,emen:-7.5068,cove:-7.5068,chie:-7.5068,
  coas:-7.5068,endr:-7.5609,ndre:-7.6786,grow:-7.6786,lock:-7.6786,pick:-7.6786,bill:-7.6786,
  vent:-7.6786,bent:-7.6786,eenf:-7.7432,unce:-7.7432,drei:-7.8122,heer:-7.9663,awns:-7.9663,
  reen:-7.9663,deck:-8.0533,kick:-8.0533,hill:-8.0533,bell:-8.0533,nsen:-8.1486,forr:-8.3718,
  satd:-8.3718,wnse:-8.3718,sein:-8.3718,refo:-8.3718,ksat:-8.5053,cksa:-8.6595,refr:-8.6595,
  atda:-8.8418,tdaw:-9.0649
};
const QUADGRAM_FLOOR=-9.7581;

const ENGLISH_WORDS=new Set(['able','about','above','accept','access','according','account','achieve','across','act','action','active','actually','add','address','administration','advance','affect','after','age','ago','agree','ahead','air','all','allow','almost','along','already','also','although','always','am','among','amount','an','and','another','answer','any','apply','approach','are','area','argue','around','ask','at','away','back','base','basic','be','because','become','been','before','being','below','best','between','big','black','blue','board','body','both','bring','build','business','but','by','call','came','can','care','carry','cause','certain','change','check','children','choose','city','civil','class','clear','close','code','collect','come','command','community','compare','complete','concern','condition','consider','continue','control','could','course','create','current','cut','cycle','data','day','deal','decide','define','despite','develop','did','difference','different','direction','discuss','do','does','down','drive','due','during','each','early','economic','effect','either','else','enable','end','enough','ensure','enter','equal','even','ever','every','evidence','example','exist','experience','explain','fall','far','feel','few','final','find','first','follow','force','form','forward','found','four','free','from','full','function','general','give','go','going','good','got','government','great','group','grow','guide','half','hand','happen','hard','help','high','history','hold','how','human','idea','identify','if','image','important','improve','include','increase','individual','influence','information','instead','interest','its','keep','know','large','late','later','law','learn','leave','level','life','likely','list','long','look','low','make','management','market','matter','may','me','mean','meet','mention','method','might','mind','model','most','move','much','must','national','natural','near','necessary','need','network','new','next','not','nothing','now','occur','offer','often','old','on','one','open','or','organization','original','other','our','outcome','page','particular','pattern','people','per','perhaps','plan','point','policy','possible','power','practice','present','prevent','primary','principle','problem','process','produce','program','provide','push','quality','reach','reason','recent','refer','region','relate','require','result','right','role','run','same','say','school','see','set','seven','show','simple','since','situation','skill','social','society','solution','specific','stand','standard','step','structure','study','style','subject','success','suggest','support','system','take','teach','than','that','the','them','theory','think','through','throughout','time','to','together','top','topic','toward','two','type','under','understand','until','use','value','various','very','view','visit','way','well','what','when','where','whether','which','who','why','will','within','without','work','world','write','year','yes','yet','you']);

function scoreEnglish(text){
  const lc=text.toLowerCase();const alpha=[...lc].filter(c=>c>='a'&&c<='z');const n=alpha.length;
  if(n<3)return 0;
  // Gate 1: must be mostly text-like characters
  const textChars=[...text].filter(c=>/[a-zA-Z .,;:!?'\-]/.test(c)).length;
  const textRatio=textChars/Math.max(text.length,1);
  if(textRatio<0.7)return 0;
  // Gate 2: vowel ratio of English is ~38-42% vowels if the text is far outside = not English
  const vowelCount=alpha.filter(c=>'aeiou'.includes(c)).length;
  const vowelRatio=vowelCount/n;
  if(vowelRatio<0.15||vowelRatio>0.70)return 0;
  const freq={};for(const c of alpha)freq[c]=(freq[c]||0)+1;
  // Unigram chi-squared (weighted 25%)
  let chi=0;for(let i=0;i<26;i++){const c=String.fromCharCode(97+i);const obs=(freq[c]||0)/n;const exp=ENGLISH_FREQ[c]||.001;chi+=(obs-exp)**2/exp;}
  const uniScore=1/(1+chi);
  if(n<6)return uniScore;
  const nStr=alpha.join('');
  // Bigram frequency analysis (weighted 20%)
  const biCount={};
  for(let i=0;i<nStr.length-1;i++){const bg=nStr.substring(i,i+2);biCount[bg]=(biCount[bg]||0)+1;}
  const biTotal=nStr.length-1;let biScore=0;
  for(const[bg,exp]of Object.entries(ENGLISH_BIGRAMS)){biScore+=(biCount[bg]||0)/biTotal*exp;}
  biScore=Math.min(1,biScore*120);
  // Trigram frequency analysis (weighted 30%): much more discriminating than bigrams.
  // Real English hits the top 50 trigrams consistently; cipher output almost never does.
  let triScore=0;
  if(n>=8){
    const triCount={};
    for(let i=0;i<nStr.length-2;i++){const tg=nStr.substring(i,i+3);triCount[tg]=(triCount[tg]||0)+1;}
    const triTotal=nStr.length-2;
    for(const[tg,exp]of Object.entries(ENGLISH_TRIGRAMS)){triScore+=(triCount[tg]||0)/triTotal*exp;}
    triScore=Math.min(1,triScore*400);
  }
  // Word structure bonus (weighted 10%)
  const words=text.trim().split(/\s+/).filter(w=>w.length>0);
  let wordBonus=0;
  if(words.length>1){
    const avgLen=n/words.length;
    if(avgLen>=2&&avgLen<=12)wordBonus=0.5+0.5*Math.max(0,1-Math.abs(avgLen-4.7)/5);
  }
  // Dictionary word coverage (weighted 15%) — real English has recognisable tokens.
  // Only applied when 3+ words present; short words excluded from denominator.
  let dictScore=0;
  if(words.length>=3){
    const checkable=words.filter(w=>w.length>2);
    if(checkable.length>0){
      const hits=checkable.filter(w=>ENGLISH_WORDS.has(w.replace(/[^a-z]/g,''))).length;
      dictScore=hits/checkable.length;
    }
  }
  return uniScore*0.25+biScore*0.20+triScore*0.30+wordBonus*0.10+dictScore*0.15;
}

// Log-probability quadgram scorer for hill-climbing (Playfair, Bifid).
// No vowel-ratio or text-ratio gates — those are useful for final validation
// but harm the climb by zeroing partially-correct intermediate candidates.
// Returns a log-probability sum: higher (less negative) = more English-like.
function scoreQuadLog(text){
  const raw=[...text.toLowerCase()].filter(c=>c>='a'&&c<='z');
  if(raw.length<4)return QUADGRAM_FLOOR*raw.length;
  // Strip likely Playfair X-padding before scoring: X inserted between doubled
  // letters (QXQ pattern) corrupts quadgrams that don't exist in English.
  // Removing them improves gradient signal during hill-climbing.
  const stripped=[];
  for(let i=0;i<raw.length;i++){
    if(raw[i]==='x'&&i>0&&i<raw.length-1&&raw[i-1]===raw[i+1])continue;
    stripped.push(raw[i]);
  }
  // Also strip trailing X if total is even (common Playfair padding)
  if(stripped.length>0&&stripped[stripped.length-1]==='x'&&stripped.length%2===0)
    stripped.pop();
  const a=stripped.length>=4?stripped:raw;
  const s=a.join('');let sc=0;
  for(let i=0;i<s.length-3;i++){
    const qg=s[i]+s[i+1]+s[i+2]+s[i+3];
    sc+=ENGLISH_QUADGRAMS[qg]!==undefined?ENGLISH_QUADGRAMS[qg]:QUADGRAM_FLOOR;
  }
  return sc/(s.length-3);
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

/**
 * CIPHER IMPLEMENTATIONS
 * Each cipher object provides encrypt() and decrypt() methods for the specified algorithm.
 * Some also include crack() methods that attempt automated cryptanalysis.
 */

/**
 * Caesar Cipher - Simple shift cipher used by Julius Caesar
 * Each letter is shifted by a fixed number of positions in the alphabet
 */
const Caesar={
  shift(text,s){return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const b=c<'a'?65:97;return String.fromCharCode((c.charCodeAt(0)-b+s%26+26)%26+b)}return c}).join('')},
  encrypt(t,s){return this.shift(t,s)},decrypt(t,s){return this.shift(t,-s)},
  crack(ct){
    const r=[];
    for(let s=0;s<26;s++){
      const d=this.shift(ct,-s);
      // Combined score: scoreEnglish handles long text well; adding a normalized
      // bigram log-probability component fixes short-text cases where unigram
      // frequency alone is too noisy to pick the correct shift.
      const se=scoreEnglish(d);
      const a=[...d.toLowerCase()].filter(c=>c>='a'&&c<='z');
      let bg=0;
      if(a.length>=2){
        for(let i=0;i<a.length-1;i++)bg+=Math.log(ENGLISH_BIGRAMS[a[i]+a[i+1]]||0.00001);
        bg=bg/(a.length-1);
        // Normalize bigram log-prob (~-5 to -12) into a [0,1] boost
        bg=Math.max(0,Math.min(1,(bg+12)/7));
      }
      r.push({shift:s,text:d,score:se+bg*0.5});
    }
    r.sort((a,b)=>b.score-a.score);return r;
  }
};

/**
 * Vigenère Cipher - Polyalphabetic substitution using a repeating keyword
 * More secure than Caesar as the same letter can be encrypted differently
 */
const Vigenere={
  encrypt(text,key){const k=key.toUpperCase();let ki=0;return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const s=k.charCodeAt(ki%k.length)-65;ki++;const b=c<'a'?65:97;return String.fromCharCode((c.toUpperCase().charCodeAt(0)-65+s)%26+b)}return c}).join('')},
  decrypt(text,key){const k=key.toUpperCase();let ki=0;return[...text].map(c=>{if(/[a-zA-Z]/.test(c)){const s=k.charCodeAt(ki%k.length)-65;ki++;const b=c<'a'?65:97;return String.fromCharCode((c.toUpperCase().charCodeAt(0)-65-s+26)%26+b)}return c}).join('')}
};

/**
 * Atbash Cipher - Alphabet reversal cipher from ancient Hebrew
 * A maps to Z, B maps to Y, etc. Self-reversing encryption
 */
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
  crackRepeating(ct){
    // Cap key length at min(8, ct.length/6) — longer keys have fewer than 6 chars
    // per column which makes frequency analysis unreliable and causes overfitting.
    const maxKL=Math.min(8,Math.floor(ct.length/6));
    // Always include key lengths 1-maxKL alongside Kasiski guesses so short common
    // keys aren't missed when Hamming distance analysis is thrown off by short text.
    const kasiski=this.guessKeyLen(ct).filter(k=>k<=maxKL);
    const klens=new Set([...kasiski,...Array.from({length:maxKL},(_,i)=>i+1)]);
    // Space-inclusive character frequency table. Standard scoreEnglish only counts
    // letters, which causes it to over-score wrong keys that happen to turn space
    // bytes into common letters (e.g. 0x20 XOR 0x0e = 0x2e -> '.', but 0x65 -> 'e').
    // Including space at ~0.15 lets the scorer correctly prefer keys that decode
    // space bytes back into actual spaces rather than gibberish.
    const CHAR_FREQ_SPACE={' ':.15,a:.0817,b:.0149,c:.0278,d:.0425,e:.127,f:.0223,g:.0202,h:.0609,i:.0697,j:.0015,k:.0077,l:.0403,m:.0241,n:.0675,o:.0751,p:.0193,q:.001,r:.0599,s:.0633,t:.0906,u:.0276,v:.0098,w:.0236,x:.0015,y:.0197,z:.0007};
    function scoreCol(text){
      const pr=[...text].filter(c=>c.charCodeAt(0)>=32&&c.charCodeAt(0)<=126).length/text.length;
      if(pr<0.85)return 0; // non-printable output means wrong key byte
      let s=0;for(const c of text)s+=CHAR_FREQ_SPACE[c.toLowerCase()]||0;
      return s/text.length;
    }
    const allResults=[];
    for(const kl of klens){
      if(kl<1||kl>ct.length/2)continue;
      const key=[];
      for(let pos=0;pos<kl;pos++){
        const stream=[];for(let i=pos;i<ct.length;i+=kl)stream.push(ct.charCodeAt(i));
        let bestK=0,bestS=-1;
        for(let k=0;k<256;k++){
          const dec=stream.map(b=>String.fromCharCode(b^k)).join('');
          const s=scoreCol(dec);
          if(s>bestS){bestS=s;bestK=k;}
        }
        key.push(bestK);
      }
      const pt=[...ct].map((c,i)=>String.fromCharCode(c.charCodeAt(0)^key[i%key.length])).join('');
      const sc=scoreEnglish(pt);
      allResults.push({key:key.map(k=>String.fromCharCode(k)).join(''),keyBytes:key,text:pt,score:sc,keyLen:kl});
    }
    if(!allResults.length)return null;
    // Sort by score descending, then key length ascending as tiebreaker —
    // when two key lengths give similar scores, prefer the shorter/simpler key
    // (parsimony: a 3-char key repeating is more likely than a unique 6-char key
    // that happens to score the same).
    allResults.sort((a,b)=>b.score-a.score||a.keyLen-b.keyLen);
    return allResults[0].score>-1?allResults[0]:null;}
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

// Columnar Transposition brute-force cracker
// Up to 7 columns: try all permutations (7! = 5040, feasible).
// 8-10 columns: full permutation search is too slow (8! = 40320), so instead
// use a greedy column-ordering heuristic — score each candidate column pair
// and build the order incrementally. Not guaranteed optimal but catches most cases.
const ColumnarCracker={
  _permutations(arr){if(arr.length<=1)return[arr];const result=[];
    for(let i=0;i<arr.length;i++){const rest=[...arr.slice(0,i),...arr.slice(i+1)];
      for(const perm of this._permutations(rest))result.push([arr[i],...perm]);
      if(result.length>6000)return result;}return result;},
  _greedyOrder(grid,cols,rows){
    // Score a full permutation by trigram hit rate — used for cols 8-10
    const scoreOrder=(order)=>{
      let pt='';for(let r=0;r<rows;r++)for(const c of order)if(grid[r]&&grid[r][c])pt+=grid[r][c];
      const a=[...pt.toLowerCase()].filter(c=>c>='a'&&c<='z').join('');let sc=0;
      for(let i=0;i<a.length-2;i++){const tg=a[i]+a[i+1]+a[i+2];sc+=ENGLISH_TRIGRAMS[tg]||0;}
      return sc;
    };
    // Greedy: start with the column pair that scores best, then extend
    const remaining=[...Array(cols).keys()];
    let order=[];
    // Seed with the single best starting column
    let bestStart=0,bestStartScore=-1;
    for(const c of remaining){
      const s=scoreOrder([c]);if(s>bestStartScore){bestStartScore=s;bestStart=c;}
    }
    order.push(bestStart);remaining.splice(remaining.indexOf(bestStart),1);
    while(remaining.length){
      let bestNext=remaining[0],bestNextScore=-1;
      for(const c of remaining){
        const s=scoreOrder([...order,c]);if(s>bestNextScore){bestNextScore=s;bestNext=c;}
      }
      order.push(bestNext);remaining.splice(remaining.indexOf(bestNext),1);
    }
    return order;
  },
  crack(ct){const results=[];
    const maxCols=Math.min(10,Math.floor(ct.length/2));
    for(let cols=2;cols<=maxCols;cols++){
      const rows=Math.ceil(ct.length/cols);
      // Build the grid column by column (standard columnar fill)
      const fullCols=ct.length%cols||cols;
      const shortCols=cols-fullCols;
      const grid=Array.from({length:rows},()=>Array(cols).fill(''));
      let pos=0;
      for(let col=0;col<cols;col++){
        const colLen=col<fullCols?rows:rows-1;
        for(let r=0;r<colLen;r++){if(pos<ct.length)grid[r][col]=ct[pos++];}
      }
      if(cols<=7){
        // Full permutation search
        const colOrder=[...Array(cols).keys()];
        for(const perm of this._permutations(colOrder)){
          const pt=grid.map(r=>perm.map(c=>r[c]||'').join('')).join('');
          results.push({cols,perm:perm.join(''),text:pt,score:scoreEnglish(pt)});
        }
      }else{
        // Greedy heuristic for cols 8-10 — try greedy order plus a few random orders
        const greedyOrder=this._greedyOrder(grid,cols,rows);
        const tryOrder=(perm)=>{
          const pt=grid.map(r=>perm.map(c=>r[c]||'').join('')).join('');
          results.push({cols,perm:perm.join(''),text:pt,score:scoreEnglish(pt)});
        };
        tryOrder(greedyOrder);
        // Also try 200 random permutations to increase coverage
        for(let t=0;t<200;t++){
          const perm=[...Array(cols).keys()];
          for(let i=perm.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[perm[i],perm[j]]=[perm[j],perm[i]];}
          tryOrder(perm);
        }
      }
    }
    results.sort((a,b)=>b.score-a.score);return results.slice(0,10);}
};

// Substitution cipher hill-climber
// Starts from a frequency-sorted seed key, then swaps letter pairs and keeps
// any swap that improves the trigram score. Reliable on texts >= 40 chars.
const SubstitutionCracker={
  // Trigrams are far more discriminating than bigrams for hill-climbing —
  // the score surface is sharper so the climber converges faster and more reliably.
  _scoreTrigrams(text){
    const alpha=[...text.toLowerCase()].filter(c=>c>='a'&&c<='z');
    if(alpha.length<3)return 0;
    const str=alpha.join('');let score=0;
    for(let i=0;i<str.length-2;i++){const tg=str[i]+str[i+1]+str[i+2];score+=ENGLISH_TRIGRAMS[tg]||0.00001;}
    return score/Math.max(str.length-2,1);
  },
  crack(ct,maxIter=8000){
    const alpha=[...ct.toLowerCase()].filter(c=>c>='a'&&c<='z');
    if(alpha.length<20)return null;
    const ctFreq=new Array(26).fill(0);
    for(const c of alpha)ctFreq[c.charCodeAt(0)-97]++;
    const ctRank=[...Array(26).keys()].sort((a,b)=>ctFreq[b]-ctFreq[a]);
    const engRank=[...Object.entries(ENGLISH_FREQ)].sort((a,b)=>b[1]-a[1]).map(([c])=>c.charCodeAt(0)-97);
    // 4 restarts × 2000 iters: first restart uses frequency-seeded key,
    // subsequent restarts shuffle from that seed to escape local optima.
    const RESTARTS=4;const ITERS_PER_RUN=Math.floor(maxIter/RESTARTS);
    const decipher=(k)=>[...ct].map(c=>{if(/[a-zA-Z]/.test(c)){const b=c<'a'?65:97;return String.fromCharCode(k[c.toUpperCase().charCodeAt(0)-65]+b);}return c;}).join('');
    let globalBest=null;let globalBestScore=-Infinity;
    for(let run=0;run<RESTARTS;run++){
      const key=new Array(26);
      for(let i=0;i<26;i++)key[ctRank[i]]=engRank[i];
      // After the first restart, shuffle the seed key to explore different basins
      if(run>0){for(let i=25;i>0;i--){const j=Math.floor(Math.random()*(i+1));[key[i],key[j]]=[key[j],key[i]];}}
      let best=decipher(key);let bestScore=this._scoreTrigrams(best);
      for(let iter=0;iter<ITERS_PER_RUN;iter++){
        const a=Math.floor(Math.random()*26);const b=Math.floor(Math.random()*26);
        if(a===b)continue;
        [key[a],key[b]]=[key[b],key[a]];
        const candidate=decipher(key);const s=this._scoreTrigrams(candidate);
        if(s>bestScore){bestScore=s;best=candidate;}
        else[key[a],key[b]]=[key[b],key[a]];
      }
      if(bestScore>globalBestScore){globalBestScore=bestScore;globalBest=best;}
    }
    return{text:globalBest,score:scoreEnglish(globalBest)};
  }
};

// Enigma brute-forcer
// Tries all 17,576 start positions for the default rotor order (III-II-I, reflector B),
// then falls back to additional rotor orders if no strong result is found.
const EnigmaCracker={
  _orders:[['III','II','I'],['I','II','III'],['II','III','I'],['I','III','II'],['III','I','II'],['II','I','III']],
  crack(ct,crib=null){
    const clean=ct.toUpperCase().replace(/[^A-Z]/g,'');
    if(clean.length<8)return null;
    let bestScore=-1,bestResult=null;
    for(const rotors of this._orders){
      for(let p1=0;p1<26;p1++){
        for(let p2=0;p2<26;p2++){
          for(let p3=0;p3<26;p3++){
            if(crib){
              const cribClean=crib.toUpperCase().replace(/[^A-Z]/g,'');
              let selfEnc=false;
              for(let i=0;i<cribClean.length&&i<clean.length;i++){
                if(clean[i]===cribClean[i]){selfEnc=true;break;}
              }
              if(selfEnc)continue;
            }
            const pt=enigmaProcess(clean,rotors,'B',[p1,p2,p3]);
            const sc=scoreEnglish(pt);
            if(sc>bestScore){bestScore=sc;bestResult={text:preserveSpaces(ct, pt),score:sc,rotors:rotors.join('-'),starts:[p1,p2,p3]};}
          }
        }
      }
      if(bestScore>0.4)break;
    }
    return bestResult&&bestResult.score>0.3?bestResult:null;
  }
};

// ROT13 cipher implementation
const ROT13_cipher={encrypt(t){return Caesar.encrypt(t,13)},decrypt(t){return Caesar.encrypt(t,13)}};

// A1Z26 cipher implementation
const A1Z26={
  encode(t){return[...t.toUpperCase()].map(c=>{const code=c.charCodeAt(0);if(code>=65&&code<=90)return String(code-64);return c;}).join(' ').replace(/ {2,}/g,' ').trim();},
  decode(t){return t.split(/[\s,]+/).map(n=>{const v=parseInt(n);if(v>=1&&v<=26)return String.fromCharCode(v+64);return n;}).join('');}
};

/**
 * Scytale Cipher Cracker
 * Attempts different cylinder diameters to find the original message
 */
// Brute-forces column counts 2–20. Deterministic decrypt for each count.
const ScytaleCracker={
  crack(ct){
    const clean=ct.replace(/[^a-zA-Z]/g,'');
    if(clean.length<6)return[];
    const results=[];
    for(let cols=2;cols<=Math.min(20,Math.floor(clean.length/2));cols++){
      const pt=Scytale.decrypt(clean,cols);
      results.push({cols,text:preserveSpaces(ct, pt),score:scoreEnglish(pt)});
    }
    results.sort((a,b)=>b.score-a.score);
    return results;
  }
};

/**
 * Route Cipher Cracker
 * Tests different spiral reading patterns to decrypt transposition ciphers
 */
// Brute-forces column counts 2–14 using the spiral route (the only route
// the RouteCipher implementation uses). Decrypt is deterministic per count.
const RouteCipherCracker={
  crack(ct){
    const clean=ct.replace(/[^a-zA-Z]/g,'');
    if(clean.length<8)return[];
    const results=[];
    for(let cols=2;cols<=Math.min(14,Math.floor(clean.length/2));cols++){
      try{
        const pt=RouteCipher.decrypt(clean,cols);
        results.push({cols,text:preserveSpaces(ct, pt),score:scoreEnglish(pt)});
      }catch(e){}
    }
    results.sort((a,b)=>b.score-a.score);
    return results;
  }
};

/**
 * Playfair Cipher Cracker
 * Uses simulated annealing to break Playfair ciphers by optimizing digraph frequencies
 */
// Simulated annealing hill-climb over the 5x5 key square.
// Starts from a random key, randomly swaps two cells or two rows or two
// columns, keeps the move if trigram score improves. Temperature schedule
// allows occasional uphill moves early on to escape local maxima.
// Reliable on texts >= 40 characters.
const PlayfairCracker={
  crack(ct,maxIter=9600){
    const clean=ct.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    if(clean.length<20)return null;

    // Decrypt with a given 25-char key square
    const tryDecrypt=(grid)=>{
      const pairs=[];
      for(let i=0;i<clean.length;i+=2)pairs.push([clean[i],clean[i+1]||'X']);
      return pairs.map(([a,b])=>{
        const ai=grid.indexOf(a),bi=grid.indexOf(b);
        const ar=Math.floor(ai/5),ac=ai%5,br=Math.floor(bi/5),bc=bi%5;
        if(ar===br)return grid[ar*5+(ac+4)%5]+grid[br*5+(bc+4)%5];
        if(ac===bc)return grid[((ar+4)%5)*5+ac]+grid[((br+4)%5)*5+bc];
        return grid[ar*5+bc]+grid[br*5+ac];
      }).join('');
    };

    // Use log-probability quadgram scoring instead of raw trigram sum.
    // Quadgrams provide a sharper landscape (456k vs 17k entries) so the
    // climber sees finer differences between candidate keys.
    const score=scoreQuadLog;

    // 8 restarts × 600 iterations = same total work as the old single 5000-iter
    // run but covers far more of the key-square search space. Each restart
    // shuffles a fresh random key so we're unlikely to land in the same
    // local optimum twice.
    const RESTARTS=12;
    const ITERS_PER_RUN=Math.floor(maxIter/RESTARTS);

    let globalBest=null;let globalBestScore=-Infinity;let globalBestKey=null;

    for(let run=0;run<RESTARTS;run++){
      // Fresh random starting key for each restart
      const alpha='ABCDEFGHIKLMNOPQRSTUVWXYZ'.split('');
      for(let i=alpha.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[alpha[i],alpha[j]]=[alpha[j],alpha[i]];}
      let key=[...alpha];
      let keyCt=tryDecrypt(key);let keyScore=score(keyCt);
      let runBestScore=keyScore;let runBest=keyCt;let runBestKey=[...key];

      // Temperature schedule calibrated to the quadgram score range (~3-6 unit spread).
      // Start at 2.0 — exp(-0.5/2)≈0.78, enough early exploration without full randomness.
      // Cool to 0.001 by end of run — exp(-0.5/0.001)≈0, strictly greedy at the end.
      // Previous value of 10.0 was too high: exp(-0.5/10)≈0.95 made early iters near-random.
      let temp=2.0;
      const coolRate=Math.pow(0.001/temp,1/ITERS_PER_RUN);

      for(let iter=0;iter<ITERS_PER_RUN;iter++){
        const newKey=[...key];
        const move=Math.random();
        if(move<0.7){
          // Swap two random cells — most common and fine-grained mutation
          const a=Math.floor(Math.random()*25),b=Math.floor(Math.random()*25);
          [newKey[a],newKey[b]]=[newKey[b],newKey[a]];
        }else if(move<0.85){
          // Swap two rows — coarser, good for early exploration
          const r1=Math.floor(Math.random()*5),r2=Math.floor(Math.random()*5);
          for(let c=0;c<5;c++){[newKey[r1*5+c],newKey[r2*5+c]]=[newKey[r2*5+c],newKey[r1*5+c]];}
        }else{
          // Swap two columns
          const c1=Math.floor(Math.random()*5),c2=Math.floor(Math.random()*5);
          for(let r=0;r<5;r++){[newKey[r*5+c1],newKey[r*5+c2]]=[newKey[r*5+c2],newKey[r*5+c1]];}
        }
        const candidate=tryDecrypt(newKey);const s=score(candidate);
        const delta=s-keyScore;
        // Simulated annealing: always accept improvements; accept worse moves
        // with probability exp(delta/temp). Tracking keyScore separately avoids
        // calling tryDecrypt(key) twice per iteration (was a hidden perf bug).
        if(delta>0||Math.random()<Math.exp(delta/temp)){key=newKey;keyCt=candidate;keyScore=s;}
        if(s>runBestScore){runBestScore=s;runBest=candidate;runBestKey=[...newKey];}
        temp*=coolRate;
      }

      if(runBestScore>globalBestScore){
        globalBestScore=runBestScore;
        globalBest=runBest;
        globalBestKey=runBestKey;
      }
    }
    return{text:preserveSpaces(ct,globalBest),score:scoreEnglish(globalBest),key:globalBestKey.join('')};
  }
};

/**
 * Bifid Cipher Cracker
 * Attempts to break Bifid ciphers using fractionation pattern analysis
 */
// Same simulated annealing approach as PlayfairCracker — hill-climb
// over the 5x5 key square using trigram scoring. Bifid mixes row/col
// coordinates so even small key changes dramatically shift the output,
// making trigrams a more reliable guide than scoreEnglish alone.
// Reliable on texts >= 30 characters.
const BifidCracker={
  crack(ct,maxIter=9600){
    const clean=ct.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    if(clean.length<16)return null;

    // Bifid fractionates coordinates across two halves of the message, so
    // even a one-cell key change produces a radically different output.
    // This makes the score landscape noisier than Playfair — we use the same
    // four improvements (quadgrams, log-prob, restarts, SA) for the same reasons.
    const tryDecrypt=(grid)=>{
      const combined=[];
      for(const c of clean){const idx=grid.indexOf(c);combined.push(Math.floor(idx/5),idx%5);}
      const half=combined.length/2;
      const rows=combined.slice(0,half);const cols=combined.slice(half);
      let out='';for(let i=0;i<rows.length;i++)out+=grid[rows[i]*5+cols[i]];
      return out;
    };

    const score=scoreQuadLog;

    const RESTARTS=12;
    const ITERS_PER_RUN=Math.floor(maxIter/RESTARTS);

    let globalBest=null;let globalBestScore=-Infinity;let globalBestKey=null;

    for(let run=0;run<RESTARTS;run++){
      const alpha='ABCDEFGHIKLMNOPQRSTUVWXYZ'.split('');
      for(let i=alpha.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[alpha[i],alpha[j]]=[alpha[j],alpha[i]];}
      let key=[...alpha];
      let keyCt=tryDecrypt(key);let keyScore=score(keyCt);
      let runBestScore=keyScore;let runBest=keyCt;let runBestKey=[...key];

      // Same calibrated schedule as PlayfairCracker — start=2.0, end=0.001
      let temp=2.0;
      const coolRate=Math.pow(0.001/temp,1/ITERS_PER_RUN);

      for(let iter=0;iter<ITERS_PER_RUN;iter++){
        const newKey=[...key];
        const move=Math.random();
        if(move<0.7){
          const a=Math.floor(Math.random()*25),b=Math.floor(Math.random()*25);
          [newKey[a],newKey[b]]=[newKey[b],newKey[a]];
        }else if(move<0.85){
          const r1=Math.floor(Math.random()*5),r2=Math.floor(Math.random()*5);
          for(let c=0;c<5;c++){[newKey[r1*5+c],newKey[r2*5+c]]=[newKey[r2*5+c],newKey[r1*5+c]];}
        }else{
          const c1=Math.floor(Math.random()*5),c2=Math.floor(Math.random()*5);
          for(let r=0;r<5;r++){[newKey[r*5+c1],newKey[r*5+c2]]=[newKey[r*5+c2],newKey[r*5+c1]];}
        }
        const candidate=tryDecrypt(newKey);const s=score(candidate);
        const delta=s-keyScore;
        if(delta>0||Math.random()<Math.exp(delta/temp)){key=newKey;keyCt=candidate;keyScore=s;}
        if(s>runBestScore){runBestScore=s;runBest=candidate;runBestKey=[...newKey];}
        temp*=coolRate;
      }

      if(runBestScore>globalBestScore){
        globalBestScore=runBestScore;
        globalBest=runBest;
        globalBestKey=runBestKey;
      }
    }
    return{text:preserveSpaces(ct,globalBest),score:scoreEnglish(globalBest),key:globalBestKey.join('')};
  }
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
    const result = pairs.map(([a,b])=>{const[ar,ac]=this._pos(grid,a);const[br,bc]=this._pos(grid,b);
      if(ar===br)return grid[ar*5+(ac+4)%5]+grid[br*5+(bc+4)%5];
      if(ac===bc)return grid[((ar+4)%5)*5+ac]+grid[((br+4)%5)*5+bc];
      return grid[ar*5+bc]+grid[br*5+ac];}).join('');
    return preserveSpaces(text, result);}
};

// Vigenère Autokey cipher implementation
const VigenereAutokey={
  encrypt(text,key){const k=key.toUpperCase();const clean=text.toUpperCase().replace(/[^A-Z]/g,'');let out='',fullKey=k;
    for(let i=0;i<clean.length;i++){const s=fullKey.charCodeAt(i)-65;out+=String.fromCharCode((clean.charCodeAt(i)-65+s)%26+65);fullKey+=clean[i];}return preserveSpaces(text, out);},
  // Autokey decrypt recovers the plaintext one char at a time, extending the key as we go
  decrypt(text,key){const k=key.toUpperCase();const clean=text.toUpperCase().replace(/[^A-Z]/g,'');let out='',fullKey=k;
    for(let i=0;i<clean.length;i++){const s=fullKey.charCodeAt(i)-65;const p=String.fromCharCode((clean.charCodeAt(i)-65-s+26)%26+65);out+=p;fullKey+=p;}return preserveSpaces(text, out);}
};

// Reverse cipher implementation
const ReverseText={encrypt(t){return[...t].reverse().join('');}};

// Scytale cipher implementation
const Scytale={
  encrypt(text,cols){const clean=text.replace(/[^a-zA-Z]/g,'');const rows=Math.ceil(clean.length/cols);const padded=clean+'X'.repeat(rows*cols-clean.length);
    let out='';for(let c=0;c<cols;c++)for(let r=0;r<rows;r++)out+=padded[r*cols+c];return preserveSpaces(text, out);},
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
      if(left<=right){for(let i=bot;i>=top;i--)out+=grid[i][left];left++;}}return preserveSpaces(text, out);},
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
    const combined=[...rows,...cols];let out='';for(let i=0;i<combined.length;i+=2)out+=grid[combined[i]*5+combined[i+1]];return preserveSpaces(text, out);},
  // Split the combined sequence back into row/col halves and look up each character
  decrypt(text,key){const grid=this._grid(key);const clean=text.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    const combined=[];for(const c of clean){const idx=grid.indexOf(c);combined.push(Math.floor(idx/5),idx%5);}
    const half=combined.length/2;const rows=combined.slice(0,half);const cols=combined.slice(half);
    let out='';for(let i=0;i<rows.length;i++)out+=grid[rows[i]*5+cols[i]];return preserveSpaces(text, out);}
};

// Polybius Square implementation
const PolybiusSquare={
  encode(t){const clean=t.toUpperCase().replace(/J/g,'I').replace(/[^A-Z]/g,'');
    return[...clean].map(c=>{let idx=c.charCodeAt(0)-65;if(idx>8)idx--;return String(Math.floor(idx/5)+1)+String(idx%5+1);}).join(' ');},
  decode(t){const pairs=t.match(/\d{2}/g)||[];return pairs.map(p=>{const r=+p[0]-1,c=+p[1]-1;let idx=r*5+c;if(idx>=9)idx++;return String.fromCharCode(idx+65);}).join('');}
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
  // Tap code uses dots to represent row and column in a 5x5 grid.
  // Each letter is encoded as ROW_DOTS SPACE COL_DOTS, words separated by ' / '.
  // K is merged with C (same cell). Example: A = ". .", H = ".. ...", Z = "..... ....."
  encode(t){
    const words=t.toUpperCase().replace(/K/g,'C').split(/\s+/);
    return words.map(w=>{
      return[...w].filter(c=>c>='A'&&c<='Z').map(c=>{
        let idx=c.charCodeAt(0)-65;if(idx>10)idx--; // K removed, shift down
        const row=Math.floor(idx/5)+1,col=idx%5+1;
        return'.'.repeat(row)+' '+'.'.repeat(col);
      }).join('  '); // double space between letters
    }).join(' / '); // slash between words
  },
  // Parse dot groups: single space = row/col separator, double space = letter boundary, / = word boundary
  decode(t){
    return t.split('/').map(wordPart=>{
      return wordPart.trim().split(/  +/).map(letterPart=>{
        const halves=letterPart.trim().split(' ');
        if(halves.length<2)return'';
        const row=halves[0].length,col=halves[1].length;
        if(row<1||row>5||col<1||col>5)return'';
        let idx=(row-1)*5+(col-1);if(idx>=10)idx++; // skip K slot
        return String.fromCharCode(idx+65);
      }).join('');
    }).join(' ');
  }
};

// Phone keypad encoding implementation
const PhoneKeypad={
  // Multi-press encoding: A=2, B=22, C=222, D=3, E=33, F=333, etc.
  // Each group of repeated digits is one letter — the key digit selects
  // the key (2-9), and the press count selects the position on that key.
  _keys:{'2':'ABC','3':'DEF','4':'GHI','5':'JKL','6':'MNO','7':'PQRS','8':'TUV','9':'WXYZ','0':' '},
  encode(t){
    return[...t.toUpperCase()].map(c=>{
      if(c===' ')return'0';
      for(const[digit,letters]of Object.entries(this._keys)){
        const pos=letters.indexOf(c);
        if(pos>=0)return digit.repeat(pos+1);
      }
      return'';
    }).filter(s=>s!=='').join(' ');
  },
  // Each space-separated token is a run of one repeated digit.
  // The digit picks the key; the token length picks the letter on that key.
  decode(t){
    return t.trim().split(/\s+/).map(token=>{
      if(!token)return'';
      const digit=token[0];
      if(![...token].every(c=>c===digit))return'';
      const letters=this._keys[digit];
      if(!letters)return'';
      return letters[(token.length-1)%letters.length];
    }).join('');
  }
};

// NATO phonetic alphabet implementation
const NATOPhonetic={
  _w:{A:'Alpha',B:'Bravo',C:'Charlie',D:'Delta',E:'Echo',F:'Foxtrot',G:'Golf',H:'Hotel',I:'India',J:'Juliet',K:'Kilo',L:'Lima',M:'Mike',N:'November',O:'Oscar',P:'Papa',Q:'Quebec',R:'Romeo',S:'Sierra',T:'Tango',U:'Uniform',V:'Victor',W:'Whiskey',X:'Xray',Y:'Yankee',Z:'Zulu'},
  _r:null,
  _rev(){if(!this._r){this._r={};for(const k in this._w)this._r[this._w[k].toLowerCase()]=k;}return this._r;},
  encode(t){return[...t.toUpperCase()].map(c=>this._w[c]||c).join(' ').replace(/ {2,}/g,' ').trim();},
  decode(t){const rev=this._rev();return t.split(/\s+/).map(w=>{const l=w.toLowerCase();return rev[l]||w;}).join('');}
};

// Hex shuffle cipher implementation
const HexShuffle={
  encrypt(text,seed){const hex=[...text].map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join('');
    const pairs=[];for(let i=0;i<hex.length;i+=2)pairs.push(hex.substring(i,i+2));
    let s=seed||42;const rng=()=>{s=(s*1103515245+12345)&0x7fffffff;return s/0x7fffffff;};
    for(let i=pairs.length-1;i>0;i--){const j=Math.floor(rng()*(i+1));[pairs[i],pairs[j]]=[pairs[j],pairs[i]];}
    return pairs.join('');}
};

/**
 * Porta Cipher Cracker
 * Brute-forces short key lengths (1–8) using the same Kasiski/Friedman
 * approach as the Vigenère cracker, adapted for Porta's 13-row lookup table.
 * For each key length, it picks the row (0–12) for each key position that
 * maximises English letter frequency on the corresponding ciphertext stream,
 * then scores the full decryption with scoreEnglish.
 */
// Porta is a reciprocal cipher — encrypt and decrypt use the same transform.
// The cracker tries key lengths 1–8 and picks whichever gives the best
// English score, falling back to the Kasiski/Friedman estimates when available.
const PortaCracker={
  crack(ct){
    const alpha=ct.replace(/[^a-zA-Z]/g,'');
    if(alpha.length<20)return null;

    const kasiski=kasiskiKeyLengths(ct);
    const friedman=friedmanKeyLength(ct);
    const candidates=new Set([...kasiski.slice(0,5),friedman,1,2,3,4]);
    let bestScore=-1,bestResult=null;

    // Chi-squared scorer — more reliable than scoreEnglish on short column strings
    const chiSqCol=(text)=>{
      const a=[...text.toLowerCase()].filter(c=>c>='a'&&c<='z');
      if(!a.length)return 999;
      const freq=new Array(26).fill(0);
      for(const c of a)freq[c.charCodeAt(0)-97]++;
      const n=a.length;let chi=0;
      for(let i=0;i<26;i++){const e=(ENGLISH_FREQ[String.fromCharCode(i+97)]||0.001)*n;chi+=Math.pow(freq[i]-e,2)/Math.max(e,0.001);}
      return chi;
    };

    for(const kl of candidates){
      if(kl<1||kl>8)continue;
      let keyRows;

      if(kl<=4){
        // Brute-force all 13^kl row combinations (max 13^4=28561).
        // Scoring the full decryption directly avoids the short-column
        // noise problem that makes per-column frequency analysis unreliable.
        const total=Math.pow(13,kl);
        let bestComboScore=-1,bestCombo=null;
        for(let combo=0;combo<total;combo++){
          const rows=[];let c=combo;
          for(let p=0;p<kl;p++){rows.push(c%13);c=Math.floor(c/13);}
          const keyStr=rows.map(r=>String.fromCharCode(r*2+65)).join('');
          const sc=scoreEnglish(Porta.transform(alpha,keyStr));
          if(sc>bestComboScore){bestComboScore=sc;bestCombo=rows;}
        }
        keyRows=bestCombo;
      } else {
        // For kl>4 use chi-squared on each column — more reliable than
        // the old table-inversion scorer for identifying the correct row.
        keyRows=[];
        for(let pos=0;pos<kl;pos++){
          const colChars=[];
          for(let i=pos;i<alpha.length;i+=kl)colChars.push(alpha[i]);
          const col=colChars.join('');
          let bestChi=999,bestRow=0;
          for(let row=0;row<13;row++){
            const kc=String.fromCharCode(row*2+65);
            const chi=chiSqCol(Porta.transform(col,kc));
            if(chi<bestChi){bestChi=chi;bestRow=row;}
          }
          keyRows.push(bestRow);
        }
      }

      // For each position, try both letters in the row pair and pick the one
      // that improves the full-text score — this resolves the A/B ambiguity
      // and ensures the reported key matches the actual encryption key.
      const key=keyRows.map(r=>r*2);
      for(let pos=0;pos<kl;pos++){
        const row=keyRows[pos];
        const tryA=[...key];tryA[pos]=row*2;
        const tryB=[...key];tryB[pos]=row*2+1;
        const sA=scoreEnglish(Porta.transform(alpha,tryA.map(c=>String.fromCharCode(c+65)).join('')));
        const sB=scoreEnglish(Porta.transform(alpha,tryB.map(c=>String.fromCharCode(c+65)).join('')));
        key[pos]=sA>=sB?row*2:row*2+1;
      }

      const keyStr=key.map(c=>String.fromCharCode(c+65)).join('');
      const pt=Porta.transform(alpha,keyStr);
      const sc=scoreEnglish(pt);
      if(sc>bestScore){bestScore=sc;bestResult={key:keyStr,text:preserveSpaces(ct,pt),score:sc,keyLen:kl};}
    }

    return bestResult;
  }
};

/**
 * Vigenère Autokey Cipher Cracker
 * The autokey cipher extends the key with the plaintext itself, so standard
 * Kasiski analysis doesn't work well. Instead this uses a known-plaintext
 * seeding approach: try common short keys (1–6 chars), then at each step
 * the recovered plaintext extends the key, bootstrapping the rest.
 * We try every single-letter key (26 options) plus 2-letter combos and pick
 * the decryption that scores highest on English frequency.
 */
// For longer keys the search space blows up, so we cap at key length 6 and
// supplement with a few common English word seeds to catch obvious cases.
const AutokeyCracker={
  _seeds:['A','E','I','O','T','S','KEY','THE','AND','SECRET','ALPHA','CODE','PASS'],

  // Attempt to decrypt the whole ciphertext given a starting key seed.
  // Once the seed runs out, each recovered plaintext char extends the key.
  _tryKey(ct,seed){
    const alpha=ct.toUpperCase().replace(/[^A-Z]/g,'');
    const k=seed.toUpperCase();
    let out='',fullKey=k;
    for(let i=0;i<alpha.length;i++){
      if(i>=fullKey.length)break; // key hasn't grown far enough yet — shouldn't happen
      const s=fullKey.charCodeAt(i)-65;
      const p=String.fromCharCode((alpha.charCodeAt(i)-65-s+26)%26+65);
      out+=p;
      // Autokey extension: each plaintext letter becomes the next key letter
      fullKey+=p;
    }
    return preserveSpaces(ct,out);
  },

  crack(ct){
    const alpha=ct.replace(/[^a-zA-Z]/g,'');
    if(alpha.length<12)return null;

    let bestScore=-1,bestResult=null;

    // Try all single-letter keys — covers key length 1 exhaustively
    for(let c=0;c<26;c++){
      const seed=String.fromCharCode(c+65);
      const pt=this._tryKey(ct,seed);
      const sc=scoreEnglish(pt);
      if(sc>bestScore){bestScore=sc;bestResult={key:seed,text:pt,score:sc};}
    }

    // Try all two-letter key combos — a bit expensive but still only 676 combos
    for(let a=0;a<26;a++){
      for(let b=0;b<26;b++){
        const seed=String.fromCharCode(a+65)+String.fromCharCode(b+65);
        const pt=this._tryKey(ct,seed);
        const sc=scoreEnglish(pt);
        if(sc>bestScore){bestScore=sc;bestResult={key:seed,text:pt,score:sc};}
      }
    }

    // Try common word seeds — catches passphrases and dictionary keys
    for(const seed of this._seeds){
      const pt=this._tryKey(ct,seed);
      const sc=scoreEnglish(pt);
      if(sc>bestScore){bestScore=sc;bestResult={key:seed,text:pt,score:sc};}
    }

    return bestResult;
  }
};
