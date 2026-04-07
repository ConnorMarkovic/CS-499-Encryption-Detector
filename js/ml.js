// ═══════════════════════════════════════════════════════════════════════
//  ml.js — 128-feature extraction + Decision Forest classifier
//  PERFORMANCE-OPTIMIZED: single-pass feature extraction, sort-based
//  tree splits, typed array internals, no .filter() in hot paths.
//  Dependencies: ciphers.js (ENGLISH_FREQ), encoders.js (detectEncoding)
// ═══════════════════════════════════════════════════════════════════════

const FEATURE_COUNT = 128;

// ═══════════════════════════════════════════════════════════════════════
//  REFERENCE DATA (precomputed for speed)
// ═══════════════════════════════════════════════════════════════════════

const COMMON_BI=['th','he','in','er','an','re','on','at','en','nd','ti','es','or','te','of','ed','is','it','al','ar'];
const COMMON_TRI=['the','and','ing','her','hat','his','tha','ere','for','ent'];
const TOP_QUADS={'tion':1,'ther':1,'that':1,'ment':1,'with':1,'ness':1,'ight':1,'ould':1,'have':1,'hing':1,'here':1,'this':1,'atio':1,'ting':1,'them':1,'ally':1,'from':1,'ough':1,'they':1,'were':1,'ered':1,'ance':1,'been':1,'ring':1,'ling':1,'when':1,'some':1,'ings':1,'able':1,'ents':1,'heir':1,'fore':1,'into':1,'over':1,'ever':1,'each':1,'more':1};
// Precompute common bigram/trigram sets for O(1) lookup
const COMMON_BI_SET=new Set(COMMON_BI);
const COMMON_TRI_SET=new Set(COMMON_TRI);
// English freq as array for fast indexed access
const ENG_FREQ_ARR=new Float64Array(26);
for(let i=0;i<26;i++)ENG_FREQ_ARR[i]=ENGLISH_FREQ[String.fromCharCode(97+i)]||0;

const RANDOM_IC=0.0385;

// ═══════════════════════════════════════════════════════════════════════
//  128-FEATURE EXTRACTION — SINGLE-PASS OPTIMIZED
//  All character iteration happens once; stats accumulated in arrays.
// ═══════════════════════════════════════════════════════════════════════

function extractFeatures(text){
  const F=new Float64Array(FEATURE_COUNT);
  const len=text.length;if(!len)return F;

  // Single pass through the text - collect all stats in one go
  const bytes=new Uint16Array(len);
  const bfreq=new Int32Array(256);
  const alphaArr=new Uint8Array(len); // lowercase alpha codes (0-25), 255 for non-alpha
  let alphaCount=0;
  const letterFreq=new Int32Array(26);
  let upperCount=0,lowerCount=0,digitCount=0,spaceCount=0,punctCount=0;
  let prevCharClass=-1,transitions=0;
  let sepCount=0;
  const sepPositions=[];
  let pctCount=0,plusSlashCount=0,dotDashCount=0,nlCount=0;
  let hexDigitCount=0,symbolCount=0;

  for(let i=0;i<len;i++){
    const code=text.charCodeAt(i);
    bytes[i]=code;
    if(code<256)bfreq[code]++;

    // Classify character
    let cls;
    if(code>=65&&code<=90){cls=0;upperCount++;const lc=code-65;letterFreq[lc]++;alphaArr[alphaCount++]=lc;}
    else if(code>=97&&code<=122){cls=1;lowerCount++;const lc=code-97;letterFreq[lc]++;alphaArr[alphaCount++]=lc;}
    else if(code>=48&&code<=57){cls=2;digitCount++;if(code<=55){}/* octal tracked by charset flags */;if(code<=57&&code>=48)hexDigitCount++;}
    else if(code===32){cls=3;spaceCount++;}
    else{cls=4;}

    // Hex digits (a-f, A-F)
    if((code>=65&&code<=70)||(code>=97&&code<=102))hexDigitCount++;

    // Special char counts
    if(code===37)pctCount++;
    if(code===43||code===47)plusSlashCount++;
    if(code===46||code===45)dotDashCount++;
    if(code===10||code===13)nlCount++;
    if(!((code>=65&&code<=90)||(code>=97&&code<=122)||(code>=48&&code<=57)||code===32))symbolCount++;
    if((code>=33&&code<=47)||(code>=58&&code<=64)||(code>=91&&code<=96)||(code>=123&&code<=126))punctCount++;

    // Separators
    if(code===32||code===47||code===45||code===46)sepPositions.push(i);

    // Transitions
    if(i>0&&cls!==prevCharClass)transitions++;
    prevCharClass=cls;
  }

  const n=alphaCount;

  // A. Frequency distribution features (F0-F8) - how letters are distributed
  if(n>=2){
    let icSum=0;for(let i=0;i<26;i++){const v=letterFreq[i];icSum+=v*(v-1);}
    F[0]=icSum/(n*(n-1));
    let chi=0;for(let i=0;i<26;i++){const obs=letterFreq[i]/n;const exp=ENG_FREQ_ARR[i]||.001;chi+=(obs-exp)**2/exp;}
    F[1]=chi;
    // Correlation
    const obs2=new Float64Array(26);for(let i=0;i<26;i++)obs2[i]=letterFreq[i]/n;
    let mO=0,mE=0;for(let i=0;i<26;i++){mO+=obs2[i];mE+=ENG_FREQ_ARR[i];}mO/=26;mE/=26;
    let num=0,dO=0,dE=0;for(let i=0;i<26;i++){const a=obs2[i]-mO,b=ENG_FREQ_ARR[i]-mE;num+=a*b;dO+=a*a;dE+=b*b;}
    F[2]=(dO&&dE)?num/Math.sqrt(dO*dE):0;
    let ent=0;for(let i=0;i<26;i++){if(letterFreq[i]>0){const p=letterFreq[i]/n;ent-=p*Math.log2(p);}}
    F[3]=ent;
    F[4]=ent/Math.log2(Math.min(26,n));
    let distinct=0;for(let i=0;i<26;i++)if(letterFreq[i]>0)distinct++;
    F[5]=distinct/26;
    let maxF=0,minF=n;for(let i=0;i<26;i++){if(letterFreq[i]>maxF)maxF=letterFreq[i];if(letterFreq[i]>0&&letterFreq[i]<minF)minF=letterFreq[i];}
    F[6]=maxF/n;F[7]=(minF<n)?minF/n:0;
    let fMean=0;for(let i=0;i<26;i++)fMean+=letterFreq[i]/n;fMean/=26;
    let fVar=0;for(let i=0;i<26;i++){const d=letterFreq[i]/n-fMean;fVar+=d*d;}
    F[8]=Math.sqrt(fVar/26);
  }

  // B. N-gram analysis (F9-F22) - looking at letter pairs, triples, etc.
  if(n>=3){
    // Bigrams: encode as (a*26+b) → int key
    const biCounts=new Int32Array(676);
    let biTotal=n-1,commonBiHits=0;
    for(let i=0;i<n-1;i++){const key=alphaArr[i]*26+alphaArr[i+1];biCounts[key]++;}
    let biUnique=0,biHapax=0;
    for(let i=0;i<676;i++){if(biCounts[i]>0){biUnique++;if(biCounts[i]===1)biHapax++;}}
    // Common bigram hits
    for(const bg of COMMON_BI){const key=(bg.charCodeAt(0)-97)*26+(bg.charCodeAt(1)-97);commonBiHits+=biCounts[key];}
    F[9]=biUnique/Math.min(biTotal,676);
    F[10]=commonBiHits/biTotal;

    // Trigrams: encode as (a*676+b*26+c)
    const triMap={};let triTotal=Math.max(n-2,1),commonTriHits=0,triRepeat=0,triUnique=0;
    for(let i=0;i<n-2;i++){const key=alphaArr[i]*676+alphaArr[i+1]*26+alphaArr[i+2];triMap[key]=(triMap[key]||0)+1;}
    for(const k in triMap){triUnique++;if(triMap[k]>1)triRepeat++;}
    for(const tg of COMMON_TRI){const key=(tg.charCodeAt(0)-97)*676+(tg.charCodeAt(1)-97)*26+(tg.charCodeAt(2)-97);commonTriHits+=(triMap[key]||0);}
    F[11]=commonTriHits/triTotal;
    F[12]=triRepeat/Math.max(triUnique,1);

    // Bigram entropy
    let biEnt=0;for(let i=0;i<676;i++){if(biCounts[i]>0){const p=biCounts[i]/biTotal;biEnt-=p*Math.log2(p);}}
    F[13]=biEnt/Math.log2(Math.min(biTotal,676));

    // Trigram entropy
    if(n>=4){let triEnt=0;for(const k in triMap){const p=triMap[k]/triTotal;triEnt-=p*Math.log2(p);}F[14]=triEnt/Math.log2(Math.min(triTotal,17576));}

    // Quadgrams
    if(n>=8){let qHits=0;const qTotal=n-3;
      const alphaStr=text.toLowerCase().replace(/[^a-z]/g,'');
      for(let i=0;i<qTotal;i++){if(TOP_QUADS[alphaStr.substring(i,i+4)])qHits++;}
      F[15]=qHits/qTotal;F[16]=F[15];}// simplified — hit rate is the main signal

    // Longest repeated substring (capped search)
    if(n>=6&&n<=3000){let maxRep=0;const maxCk=Math.min(20,Math.floor(n/2));
      const alphaStr=text.toLowerCase().replace(/[^a-z]/g,'');
      for(let sl=3;sl<=maxCk;sl++){const seen=new Set();let found=false;
        for(let i=0;i<=n-sl;i++){const sub=alphaStr.substring(i,i+sl);if(seen.has(sub)){maxRep=sl;found=true;break;}seen.add(sub);}
        if(!found)break;}F[17]=maxRep/n;}

    F[18]=biUnique/biTotal;
    F[19]=biHapax/Math.max(biUnique,1);

    // Bigram skewness
    let biMean=biTotal/676,biM2=0,biM3=0;
    for(let i=0;i<676;i++){const d=biCounts[i]-biMean;biM2+=d*d;biM3+=d*d*d;}
    biM2/=676;biM3/=676;const biStd=Math.sqrt(biM2);
    F[20]=biStd>0?biM3/(biStd*biStd*biStd):0;

    // Consonant cluster
    let maxCon=0,curCon=0;const vowels=new Uint8Array([1,0,0,0,1,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0]);
    for(let i=0;i<n;i++){if(!vowels[alphaArr[i]]){curCon++;if(curCon>maxCon)maxCon=curCon;}else curCon=0;}
    F[21]=maxCon/n;

    // V-C transitions
    if(n>1){let vcT=0;for(let i=1;i<n;i++){if(vowels[alphaArr[i-1]]!==vowels[alphaArr[i]])vcT++;}F[22]=vcT/(n-1);}
  }

  // C. Index of Coincidence at different key lengths (F23-F36) - for polyalphabetic detection
  if(n>=10){
    for(let kl=2;kl<=11;kl++){
      const sf=new Int32Array(kl*26);const sn=new Int32Array(kl);
      for(let i=0;i<n;i++){const s=i%kl;sf[s*26+alphaArr[i]]++;sn[s]++;}
      let avgIc=0,valid=0;
      for(let s=0;s<kl;s++){const sLen=sn[s];if(sLen<2)continue;
        let ic=0;for(let c=0;c<26;c++){const v=sf[s*26+c];ic+=v*(v-1);}
        avgIc+=ic/(sLen*(sLen-1));valid++;}
      F[21+kl]=valid?avgIc/valid:0;
    }
    F[33]=0;for(let kl=2;kl<=11;kl++)if(F[21+kl]>F[33])F[33]=F[21+kl];
    let bestKL=2;for(let kl=3;kl<=11;kl++)if(F[21+kl]>F[21+bestKL])bestKL=kl;
    F[34]=bestKL/11;
    let icM=0;for(let kl=2;kl<=11;kl++)icM+=F[21+kl];icM/=10;
    let icV=0;for(let kl=2;kl<=11;kl++){const d=F[21+kl]-icM;icV+=d*d;}
    F[35]=Math.sqrt(icV/10);
    const ic=F[0];if(ic>RANDOM_IC&&n>1){const est=0.0273*n/((n-1)*ic-RANDOM_IC*n+0.0273);F[36]=Math.max(1,Math.min(20,Math.round(est)))/20;}else F[36]=1;
  }

  // D. Autocorrelation (F37-F46) - patterns repeating at different offsets
  if(n>=8){
    let acMax=0,acMaxIdx=0,acSum=0;
    for(let off=1;off<=8;off++){let m=0;const denom=n-off;
      if(denom>0){for(let i=0;i<denom;i++)if(alphaArr[i]===alphaArr[i+off])m++;
      const ac=m/denom;F[36+off]=ac;acSum+=ac;if(ac>acMax){acMax=ac;acMaxIdx=off;}}}
    const acMean=acSum/8;F[45]=acMean>0?acMax/acMean:1;F[46]=acMaxIdx/8;
  }

  // E. Structural shape (F47-F60) - case, spaces, word lengths, etc.
  if(n>=2){let vc=0;const vowels=new Uint8Array([1,0,0,0,1,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0,1,0,0,0,0,0]);
    for(let i=0;i<n;i++)if(vowels[alphaArr[i]])vc++;F[47]=vc/n;}
  F[48]=spaceCount>0?1:0;
  const totalAlpha=upperCount+lowerCount;
  F[49]=totalAlpha?upperCount/totalAlpha:0;
  F[50]=Math.log2(n+1);
  if(n>=2){
    F[51]=Math.abs(letterFreq[4]/n-ENG_FREQ_ARR[4]); // e
    F[52]=Math.abs(letterFreq[19]/n-ENG_FREQ_ARR[19]); // t
    F[53]=Math.abs(letterFreq[0]/n-ENG_FREQ_ARR[0]); // a
    F[54]=Math.abs(letterFreq[14]/n-ENG_FREQ_ARR[14]); // o
    let devSum=0;for(let i=0;i<26;i++)devSum+=Math.abs(letterFreq[i]/n-ENG_FREQ_ARR[i]);F[55]=devSum;
    // Kurtosis
    let fM=0;for(let i=0;i<26;i++)fM+=letterFreq[i]/n;fM/=26;
    let m2=0,m4=0;for(let i=0;i<26;i++){const d=letterFreq[i]/n-fM;m2+=d*d;m4+=d*d*d*d;}m2/=26;m4/=26;
    F[56]=m2>0?m4/(m2*m2)-3:0;
  }
  F[57]=transitions/Math.max(len-1,1);
  // Separator regularity
  if(sepPositions.length>=2){
    let gSum=0;const gN=sepPositions.length-1;
    for(let i=1;i<sepPositions.length;i++)gSum+=sepPositions[i]-sepPositions[i-1];
    const gM=gSum/gN;let gVar=0;
    for(let i=1;i<sepPositions.length;i++){const d=(sepPositions[i]-sepPositions[i-1])-gM;gVar+=d*d;}
    F[58]=1/(1+Math.sqrt(gVar/gN)/Math.max(gM,1));
  }
  // Word stats
  if(spaceCount>0){const words=text.split(/\s+/);const wc=words.length;if(wc>0){
    let wSum=0;for(let i=0;i<wc;i++)wSum+=words[i].length;const wM=wSum/wc;F[59]=wM/20;
    if(wc>1){let wVar=0;for(let i=0;i<wc;i++){const d=words[i].length-wM;wVar+=d*d;}F[60]=Math.sqrt(wVar/wc)/10;}}}

  // F. Byte-level features (F61-F80) - looking at raw bytes
  let bent=0,distinctB=0;
  for(let i=0;i<256;i++){if(bfreq[i]>0){distinctB++;const p=bfreq[i]/len;bent-=p*Math.log2(p);}}
  F[61]=bent;
  let printable=0,control=0,highByte=0;
  for(let i=0;i<32;i++)control+=bfreq[i];
  for(let i=32;i<=126;i++)printable+=bfreq[i];
  for(let i=128;i<256;i++)highByte+=bfreq[i];
  F[62]=printable/len;F[63]=control/len;F[64]=highByte/len;F[65]=bfreq[0]/len;
  const bMean=len/256;let bVar=0;for(let i=0;i<256;i++){const d=bfreq[i]-bMean;bVar+=d*d;}
  F[66]=Math.sqrt(bVar/256)/len;F[67]=distinctB/256;
  F[68]=spaceCount/len;F[69]=digitCount/len;F[70]=punctCount/len;

  // Byte bigram entropy
  if(len>=4){const bbC=new Map();for(let i=0;i<len-1;i++){const k=(bytes[i]<<8)|bytes[i+1];bbC.set(k,(bbC.get(k)||0)+1);}
    let bbE=0;const bbT=len-1;for(const v of bbC.values()){const p=v/bbT;bbE-=p*Math.log2(p);}
    F[71]=bbE/Math.log2(Math.min(bbT,65536));}

  // Byte deltas
  if(len>=2){let dSum=0,dSqSum=0;for(let i=0;i<len-1;i++){const d=Math.abs(bytes[i+1]-bytes[i]);dSum+=d;dSqSum+=d*d;}
    const dM=dSum/(len-1);F[72]=Math.sqrt(dSqSum/(len-1)-dM*dM)/128;F[73]=dM/128;}

  // Run-length
  if(len>=4){let runs=1;for(let i=1;i<len;i++)if(bytes[i]!==bytes[i-1])runs++;F[74]=runs/len;}

  // Byte chi²
  {const bExp=len/256;let bChi=0;for(let i=0;i<256;i++){const d=bfreq[i]-bExp;bChi+=d*d/Math.max(bExp,.001);}F[75]=bChi/len;}

  // Byte skewness & kurtosis
  {let m2=0,m3=0,m4=0;for(let i=0;i<256;i++){const d=bfreq[i]-bMean;const d2=d*d;m2+=d2;m3+=d2*d;m4+=d2*d2;}
    m2/=256;m3/=256;m4/=256;const bs=Math.sqrt(m2);
    F[76]=bs>0?m3/(bs*bs*bs):0;F[77]=m2>0?m4/(m2*m2)-3:0;}

  F[78]=upperCount/len;F[79]=lowerCount/len;
  F[80]=Math.min(upperCount,lowerCount)/Math.max(upperCount,lowerCount,1);

  // G. Positional and regional features (F81-F99) - entropy in different parts
  F[81]=bytes[0]/255;F[82]=bytes[len-1]/255;
  let trailEq=0;for(let i=len-1;i>=0&&bytes[i]===61;i--)trailEq++;
  F[83]=Math.min(trailEq,3)/3;
  F[84]=(bytes[0]===37)?1:0;F[85]=(bytes[0]>=48&&bytes[0]<=57)?1:0;

  // Quarter entropies
  if(n>=16){const qLen=n>>2;
    for(let q=0;q<4;q++){const qf=new Int32Array(26);const start=q*qLen;
      for(let i=start;i<start+qLen;i++)qf[alphaArr[i]]++;
      let qe=0;for(let c=0;c<26;c++){if(qf[c]>0){const p=qf[c]/qLen;qe-=p*Math.log2(p);}}F[86+q]=qe;}
    const qes=[F[86],F[87],F[88],F[89]];let qM=0;for(let i=0;i<4;i++)qM+=qes[i];qM/=4;
    let qV=0;for(let i=0;i<4;i++){const d=qes[i]-qM;qV+=d*d;}F[90]=Math.sqrt(qV/4);
    F[91]=Math.max(qes[0],qes[1],qes[2],qes[3])-Math.min(qes[0],qes[1],qes[2],qes[3]);}

  // Half byte entropies
  if(len>=8){const half=len>>1;
    const bf1=new Int32Array(256),bf2=new Int32Array(256);
    for(let i=0;i<half;i++)bf1[bytes[i]]++;for(let i=half;i<len;i++)bf2[bytes[i]]++;
    let be1=0,be2=0;
    for(let i=0;i<256;i++){if(bf1[i]>0){const p=bf1[i]/half;be1-=p*Math.log2(p);}if(bf2[i]>0){const p=bf2[i]/(len-half);be2-=p*Math.log2(p);}}
    F[92]=be1;F[93]=be2;F[94]=be1-be2;}

  if(len>=2){let mono=0;for(let i=0;i<len-1;i++)if(bytes[i+1]>=bytes[i])mono++;F[95]=mono/(len-1);}
  if(len>=2){let maxR=1,curR=1;for(let i=1;i<len;i++){if(bytes[i]===bytes[i-1]){curR++;if(curR>maxR)maxR=curR;}else curR=1;}F[96]=maxR/len;}

  // Byte range, median, IQR — use bfreq histogram instead of sorting
  {let bMin=255,bMax=0;for(let i=0;i<256;i++){if(bfreq[i]>0){if(i<bMin)bMin=i;if(i>bMax)bMax=i;}}
    F[97]=(bMax-bMin)/255;
    // Median and IQR from cumulative histogram
    let cum=0;const q1Pos=Math.floor(len*0.25),medPos=Math.floor(len*0.5),q3Pos=Math.floor(len*0.75);
    let q1=0,med=0,q3=0;
    for(let i=0;i<256;i++){cum+=bfreq[i];if(cum>=q1Pos&&!q1)q1=i;if(cum>=medPos&&!med)med=i;if(cum>=q3Pos&&!q3){q3=i;break;}}
    F[98]=med/255;F[99]=(q3-q1)/255;}

  // H. Pattern, charset, and metadata features (F100-F127)
  // Length mod flags — compute on stripped length
  const strippedLen=len-spaceCount;const clen=strippedLen||1;
  F[100]=(clen%2===0)?1:0;F[101]=(clen%3===0)?1:0;F[102]=(clen%4===0)?1:0;
  F[103]=(clen%5===0)?1:0;F[104]=(clen%8===0)?1:0;F[105]=(clen%6===0)?1:0;

  // Charset flags — derived from counts (no regex!)
  const nonAlphaDigitSpace=symbolCount;
  F[106]=(totalAlpha===len-spaceCount&&totalAlpha>0)?1:0; // alpha-only
  F[107]=(hexDigitCount===len-spaceCount&&len>0)?1:0; // hex-compat
  F[108]=(digitCount===len-spaceCount&&digitCount>0&&bfreq[50]===0&&bfreq[51]===0&&bfreq[52]===0&&bfreq[53]===0&&bfreq[54]===0&&bfreq[55]===0&&bfreq[56]===0&&bfreq[57]===0)?1:0;
  // ↑ binary: only 0 (48) and 1 (49)
  // Simpler binary check:
  if(F[108]===0){let binOk=true;for(let i=0;i<len;i++){const c=bytes[i];if(c!==48&&c!==49&&c!==32){binOk=false;break;}}if(binOk&&len>0)F[108]=1;}
  F[109]=(nonAlphaDigitSpace<=pctCount+plusSlashCount+trailEq&&totalAlpha+digitCount+plusSlashCount+trailEq+spaceCount>=len)?1:0;
  // Bacon: only A/B (65,66,97,98)
  {let baconOk=true;for(let i=0;i<len;i++){const c=bytes[i];if(c!==65&&c!==66&&c!==97&&c!==98&&c!==32){baconOk=false;break;}}F[110]=baconOk&&len>0?1:0;}
  // Octal: only 0-7
  {let octOk=true;for(let i=0;i<len;i++){const c=bytes[i];if(!((c>=48&&c<=55)||c===32)){octOk=false;break;}}F[111]=octOk&&len>0?1:0;}

  // Encoding pre-check
  try{const ENC_MAP={plaintext:0,binary:1,octal:2,decimal:3,hex:4,base64:5,url:6,morse:7,bacon:8};
    const det=detectEncoding(text);F[112]=(ENC_MAP[det]!==undefined)?ENC_MAP[det]/8:0;}catch(e){F[112]=0;}

  F[113]=1-1/(1+len/100);
  F[114]=Math.log2(len+1);
  F[115]=n/len;
  F[116]=digitCount/len;
  F[117]=symbolCount/len;
  F[118]=pctCount/len;
  F[119]=plusSlashCount/len;
  F[120]=dotDashCount/len;
  F[121]=nlCount/len;
  F[122]=hexDigitCount/len;

  // Even-odd byte diff
  if(len>=4){let eS=0,oS=0;const eN=(len+1)>>1,oN=len>>1;
    for(let i=0;i<len;i++){if(i&1)oS+=bytes[i];else eS+=bytes[i];}
    F[123]=Math.abs(eS/eN-oS/Math.max(oN,1))/128;}

  // Repeating pattern
  if(clen>=6&&clen<=1000){let bestP=0;
    for(let p=1;p<=Math.min(10,clen>>1);p++){let m=0;for(let i=p;i<len;i++){if(bytes[i]===bytes[i%p])m++;}
      if(m/(len-p)>0.95){bestP=p;break;}}F[124]=bestP>0?1/bestP:0;}

  // Unique word ratio
  if(spaceCount>0){const words=text.split(/\s+/);if(words.length>1){const uniq=new Set(words);F[125]=uniq.size/words.length;}}

  // Printable-only flag
  {let allPrint=true;for(let i=0;i<len;i++){const c=bytes[i];if(!((c>=32&&c<=126)||c===10||c===13)){allPrint=false;break;}}F[126]=allPrint?1:0;}

  // Bits per char
  if(distinctB>1)F[127]=bent/Math.log2(distinctB);

  return F;
}


// ═══════════════════════════════════════════════════════════════════════
//  DECISION FOREST — SORT-BASED SPLITS (no .filter() in hot path)
//  Instead of filtering data for each threshold, we sort once per
//  feature and scan left-to-right, updating class counts incrementally.
//  This is O(n log n) per feature instead of O(n × thresholds).
// ═══════════════════════════════════════════════════════════════════════

function _gini(counts,total){
  if(!total)return 0;let sum=0;for(const k in counts){const p=counts[k]/total;sum+=p*p;}return 1-sum;
}

function bestSplitSorted(data,nFeatures,rng){
  const N=data.length;
  const allFeats=data[0].x.length;

  // Select random feature subset
  const featIndices=new Uint8Array(nFeatures);
  if(nFeatures>=allFeats){for(let i=0;i<allFeats;i++)featIndices[i]=i;}
  else{const pool=new Uint8Array(allFeats);for(let i=0;i<allFeats;i++)pool[i]=i;
    for(let i=0;i<nFeatures;i++){const j=i+Math.floor(rng()*(allFeats-i));const tmp=pool[i];pool[i]=pool[j];pool[j]=tmp;featIndices[i]=pool[i];}}

  // Total class counts
  const totalCounts={};for(let i=0;i<N;i++)totalCounts[data[i].y]=(totalCounts[data[i].y]||0)+1;

  let bestFeat=-1,bestVal=0,bestGini=Infinity,bestSplitIdx=-1;

  // Reusable index array
  const indices=new Uint32Array(N);

  for(let fi=0;fi<nFeatures;fi++){
    const feat=featIndices[fi];

    // Sort indices by feature value
    for(let i=0;i<N;i++)indices[i]=i;
    indices.sort((a,b)=>data[a].x[feat]-data[b].x[feat]);

    // Scan left-to-right, incrementally updating left/right class counts
    const leftCounts={};let leftN=0;
    const rightCounts={};for(const k in totalCounts)rightCounts[k]=totalCounts[k];
    let rightN=N;

    for(let i=0;i<N-1;i++){
      const cls=data[indices[i]].y;
      leftCounts[cls]=(leftCounts[cls]||0)+1;leftN++;
      rightCounts[cls]--;rightN--;

      // Only evaluate split if values differ (skip ties)
      if(data[indices[i]].x[feat]===data[indices[i+1]].x[feat])continue;

      const gLeft=_gini(leftCounts,leftN);
      const gRight=_gini(rightCounts,rightN);
      const gini=(leftN*gLeft+rightN*gRight)/N;

      if(gini<bestGini){
        bestGini=gini;bestFeat=feat;
        bestVal=(data[indices[i]].x[feat]+data[indices[i+1]].x[feat])/2;
        bestSplitIdx=i;
      }
    }
  }

  if(bestFeat===-1)return{feat:-1,val:0,left:null,right:null};

  // Partition data using the best split
  const left=[],right=[];
  for(let i=0;i<N;i++){
    if(data[i].x[bestFeat]<bestVal)left.push(data[i]);else right.push(data[i]);
  }
  return{feat:bestFeat,val:bestVal,left,right,gini:bestGini};
}

function buildTree(data,maxDepth,minSize,nFeatures,rng,depth){
  if(!data.length)return{leaf:true,cls:'unknown',dist:{}};
  const classes=new Set();for(let i=0;i<data.length;i++)classes.add(data[i].y);
  // Leaf stores full probability distribution
  if(classes.size===1)return{leaf:true,cls:data[0].y,dist:{[data[0].y]:1},n:data.length};
  if(depth>=maxDepth||data.length<=minSize){
    const counts={};for(let i=0;i<data.length;i++)counts[data[i].y]=(counts[data[i].y]||0)+1;
    let best='',bestV=0;const dist={};
    for(const k in counts){if(counts[k]>bestV){bestV=counts[k];best=k;}dist[k]=counts[k]/data.length;}
    return{leaf:true,cls:best,confidence:bestV/data.length,dist:dist,n:data.length};
  }
  // Use all features at depth 0 only, random subset deeper
  const featCount=(depth===0)?data[0].x.length:nFeatures;
  const split=bestSplitSorted(data,featCount,rng);
  if(split.feat===-1||!split.left||!split.left.length||!split.right||!split.right.length){
    const counts={};for(let i=0;i<data.length;i++)counts[data[i].y]=(counts[data[i].y]||0)+1;
    let best='',bestV=0;const dist={};
    for(const k in counts){if(counts[k]>bestV){bestV=counts[k];best=k;}dist[k]=counts[k]/data.length;}
    return{leaf:true,cls:best,dist:dist,n:data.length};
  }
  return{leaf:false,feat:split.feat,val:split.val,
    left:buildTree(split.left,maxDepth,minSize,nFeatures,rng,depth+1),
    right:buildTree(split.right,maxDepth,minSize,nFeatures,rng,depth+1)};
}

// Returns just the class label (backward compatible, used by evaluateTrees)
function treePredict(tree,x){if(tree.leaf)return tree.cls;return x[tree.feat]<tree.val?treePredict(tree.left,x):treePredict(tree.right,x);}

// Returns full probability distribution from the leaf
function treePredictDist(tree,x){if(tree.leaf)return tree.dist||{[tree.cls]:1};return x[tree.feat]<tree.val?treePredictDist(tree.left,x):treePredictDist(tree.right,x);}

function treeFeatureImportance(tree,imp,depth){
  if(tree.leaf)return;imp[tree.feat]=(imp[tree.feat]||0)+1/(1+depth);
  treeFeatureImportance(tree.left,imp,depth+1);treeFeatureImportance(tree.right,imp,depth+1);
}

class DecisionForest{
  constructor(){this.trees=[];this.trained=false;this.total=0;this.classes=[];this.importances={};this.oobAccuracy=0;}
  train(X,Y,nTrees=20,maxDepth=14,minSize=3){
    const data=X.map((x,i)=>({x,y:Y[i]}));
    this.classes=[...new Set(Y)];
    const nFeatures=Math.max(4,Math.floor(Math.sqrt(X[0].length)));
    this.trees=[];
    let seed=Date.now()%100000;const rng=()=>{seed=(seed*1103515245+12345)&0x7fffffff;return seed/0x7fffffff;};
    const oobVotes=new Array(data.length);for(let i=0;i<data.length;i++)oobVotes[i]={};
    const oobUsed=new Uint8Array(data.length);
    for(let t=0;t<nTrees;t++){
      const inBag=new Uint8Array(data.length);
      const sample=new Array(data.length);
      for(let i=0;i<data.length;i++){const idx=Math.floor(rng()*data.length);sample[i]=data[idx];inBag[idx]=1;}
      const tree=buildTree(sample,maxDepth,minSize,nFeatures,rng,0);
      this.trees.push(tree);
      for(let i=0;i<data.length;i++){if(!inBag[i]){const pred=treePredict(tree,data[i].x);oobVotes[i][pred]=(oobVotes[i][pred]||0)+1;oobUsed[i]=1;}}
    }
    let oobC=0,oobT=0;
    for(let i=0;i<data.length;i++){if(!oobUsed[i])continue;const votes=oobVotes[i];
      let best='',bestV=0;for(const k in votes)if(votes[k]>bestV){bestV=votes[k];best=k;}
      if(best===data[i].y)oobC++;oobT++;}
    this.oobAccuracy=oobT?oobC/oobT:0;
    this.importances={};for(const tree of this.trees)treeFeatureImportance(tree,this.importances,0);
    const maxImp=Math.max(...Object.values(this.importances),1);
    for(const k in this.importances)this.importances[k]/=maxImp;
    this.trained=true;this.total=X.length;
  }
  predict(features){
    if(!this.trained)return{cls:'unknown',probs:{},confidence:0};
    // Average leaf probability distributions across all trees
    const avgDist={};
    for(const tree of this.trees){
      const dist=treePredictDist(tree,features);
      for(const k in dist)avgDist[k]=(avgDist[k]||0)+dist[k];
    }
    const total=this.trees.length;const probs={};let bestCls='unknown',bestV=0;
    for(const k in avgDist){probs[k]=avgDist[k]/total;if(avgDist[k]>bestV){bestV=avgDist[k];bestCls=k;}}
    return{cls:bestCls,probs,confidence:bestV/total};
  }
  save(){return JSON.stringify({trees:this.trees,trained:this.trained,total:this.total,classes:this.classes,importances:this.importances,oobAccuracy:this.oobAccuracy,fc:FEATURE_COUNT});}
  load(json){const d=JSON.parse(json);if(d.fc&&d.fc!==FEATURE_COUNT)return false;this.trees=d.trees;this.trained=d.trained;this.total=d.total;this.classes=d.classes||[];this.importances=d.importances||{};this.oobAccuracy=d.oobAccuracy||0;return true;}

  // Evaluate each individual tree's accuracy on a test set
  // Returns array of {index, accuracy} sorted worst-first
  evaluateTrees(testX, testY){
    const scores=[];
    for(let t=0;t<this.trees.length;t++){
      let correct=0;
      for(let i=0;i<testX.length;i++){
        if(treePredict(this.trees[t],testX[i])===testY[i])correct++;
      }
      scores.push({index:t, accuracy:testX.length?correct/testX.length:0});
    }
    scores.sort((a,b)=>a.accuracy-b.accuracy); // worst first
    return scores;
  }

  // Diversity-aware federated merge
  // Instead of picking challenger trees by raw accuracy, pick trees that CORRECT
  // mistakes the current champion makes. A tree with 70% accuracy that fixes 15
  // of the champion's errors is more valuable than an 85% tree that fixes 2.
  mergeFrom(challenger, testX, testY, mergeTrees=5, maxTrees=30){
    if(!challenger.trained||!challenger.trees.length)return{merged:false,reason:'challenger not trained'};
    if(!testX.length)return{merged:false,reason:'no test data'};

    // First: find which test samples the CURRENT champion gets wrong
    const champErrors=new Set();
    for(let i=0;i<testX.length;i++){
      if(treePredict(this.trees[0],testX[i])!==testY[i]){} // single tree check isn't enough
      const pred=this.predict(testX[i]);
      if(pred.cls!==testY[i])champErrors.add(i);
    }

    // Score each challenger tree by how many champion errors it corrects
    const challScores=[];
    for(let t=0;t<challenger.trees.length;t++){
      let corrections=0,totalCorrect=0;
      for(let i=0;i<testX.length;i++){
        const pred=treePredict(challenger.trees[t],testX[i]);
        if(pred===testY[i]){totalCorrect++;if(champErrors.has(i))corrections++;}
      }
      challScores.push({index:t, corrections, accuracy:testX.length?totalCorrect/testX.length:0});
    }
    // Sort by corrections first, then accuracy as tiebreaker
    challScores.sort((a,b)=>b.corrections-a.corrections||(b.accuracy-a.accuracy));

    // Score champion trees — find the worst ones
    const champScores=this.evaluateTrees(testX,testY);
    // champScores is already sorted worst-first

    // Take top mergeTrees challenger trees by correction count
    const challBest=challScores.slice(0,mergeTrees);
    const champWorst=champScores.slice(0,mergeTrees);

    // Only merge trees that are STRICTLY BETTER than what they'd replace
    const toAdd=[];const toRemove=[];
    for(let i=0;i<mergeTrees;i++){
      if(i<challBest.length&&i<champWorst.length){
        // Only replace if challenger tree has higher accuracy than the champion tree it would replace
        if(challBest[i].accuracy>champWorst[i].accuracy){
          toAdd.push({tree:challenger.trees[challBest[i].index],corrections:challBest[i].corrections,accuracy:challBest[i].accuracy});
          toRemove.push(champWorst[i].index);
        }
      }
    }

    if(!toAdd.length)return{merged:false,reason:'no challenger trees better than champion trees',champErrors:champErrors.size,challBestCorr:challBest[0]?.corrections||0};

    // Save current state for rollback
    const savedTrees=[...this.trees];
    const savedOob=this.oobAccuracy;

    // Measure champion accuracy BEFORE merge
    let beforeCorrect=0;
    for(let i=0;i<testX.length;i++){if(this.predict(testX[i]).cls===testY[i])beforeCorrect++;}
    const beforeAcc=testX.length?beforeCorrect/testX.length:0;

    // Remove worst champion trees
    const removeSet=new Set(toRemove);
    this.trees=this.trees.filter((_,i)=>!removeSet.has(i));

    // Add best challenger trees
    for(const item of toAdd)this.trees.push(item.tree);

    // Cap at maxTrees
    while(this.trees.length>maxTrees)this.trees.shift();

    // Re-evaluate accuracy AFTER merge
    let afterCorrect=0;
    for(let i=0;i<testX.length;i++){if(this.predict(testX[i]).cls===testY[i])afterCorrect++;}
    const afterAcc=testX.length?afterCorrect/testX.length:0;

    // ROLLBACK if merge made things worse
    if(afterAcc<beforeAcc){
      this.trees=savedTrees;
      this.oobAccuracy=savedOob;
      return{merged:false,reason:'merge would reduce accuracy ('+((beforeAcc*100).toFixed(1))+'% -> '+((afterAcc*100).toFixed(1))+'%)',champErrors:champErrors.size};
    }

    // Merge classes
    const cls=new Set(this.classes);for(const c of challenger.classes)cls.add(c);this.classes=[...cls];

    // Recalculate importances
    this.importances={};for(const tree of this.trees)treeFeatureImportance(tree,this.importances,0);
    const maxImp=Math.max(...Object.values(this.importances),1);
    for(const k in this.importances)this.importances[k]/=maxImp;

    this.oobAccuracy=afterAcc;
    this.total+=challenger.total;

    const totalCorr=toAdd.reduce((s,t)=>s+t.corrections,0);
    return{merged:true,added:toAdd.length,removed:toRemove.length,totalTrees:this.trees.length,newAcc:afterAcc,beforeAcc:beforeAcc,corrections:totalCorr,champErrors:champErrors.size};
  }
}

let mlModel=new DecisionForest();
