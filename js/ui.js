// ═══════════════════════════════════════════════════════════════════════
//  ui.js — Corpus, Training Engine, all UI handlers
//  Dependencies: ciphers.js, encoders.js, ml.js, kb.js, crackers.js
// ═══════════════════════════════════════════════════════════════════════

const $=id=>document.getElementById(id);
const $$=id=>document.getElementById(id);
const H=s=>s?String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'):'';

function go(id,btn){
  document.querySelectorAll('.pg').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('on'));
  $('pg-'+id).classList.add('on');btn.classList.add('on');
  syncAllStats();
  if(id==='kb')renderKB();if(id==='ml')renderML();
}

// ═══════════════════════════════════════════════════════════════════════
// Procedural text generator - creates unique plaintext samples
//  300+ nouns, 200+ adjectives, 120+ verbs, 80+ adverbs, 60+ prepositions
//  40 sentence templates, random names/places/numbers for infinite variety
//  Combinatorial space: trillions of possible sentences
// ═══════════════════════════════════════════════════════════════════════

const _NOUNS=[
  // Computing & security
  'system','network','server','cipher','algorithm','protocol','message','database','password','firewall','signal','module','packet','token','session','device','buffer','kernel','vector','matrix','cluster','payload','header','socket','gateway','archive','sensor','router','filter','handler','parser','driver','thread','process','channel','registry','sandbox','container','pipeline','function','variable','array','table','index','query','schema','record','cache','stack','queue','node','edge','branch','block','chain','frame','layer','stream','cursor','pointer','instance','template','interface','pattern','command','strategy',
  // Nature & physical world
  'river','mountain','forest','ocean','valley','desert','island','canyon','glacier','volcano','meadow','cliff','waterfall','shore','prairie','marsh','cavern','ridge','plateau','storm','thunder','lightning','rainbow','sunset','horizon','breeze','current','tide','wave','stone','crystal','diamond','ember','flame','shadow','echo','frost','mist','dawn','twilight',
  // People & society
  'captain','soldier','merchant','scholar','traveler','guardian','hunter','builder','healer','messenger','inventor','explorer','navigator','commander','engineer','artist','musician','philosopher','detective','apprentice','champion','volunteer','pioneer','architect','librarian','professor','student','teacher','pilot','surgeon',
  // Objects & things
  'bridge','tower','castle','fortress','temple','library','garden','market','harbor','lighthouse','compass','telescope','lantern','anchor','shield','sword','crown','banner','scroll','mirror','clock','engine','hammer','anvil','wheel','lever','spring','basket','candle','torch','bell','drum','flag','coin','key','lock','gate','door','window','wall','fence','path','road','trail','ladder',
  // Abstract concepts
  'freedom','justice','courage','wisdom','honor','truth','balance','harmony','chaos','order','silence','mystery','knowledge','power','strength','fortune','destiny','legacy','progress','victory','challenge','journey','promise','secret','legend','memory','reason','purpose','vision','spirit','energy','motion','rhythm','pattern','signal','measure','limit','threshold','boundary','origin'
];
const _ADJS=[
  // Technical
  'secure','encrypted','hidden','volatile','persistent','dynamic','static','parallel','distributed','recursive','virtual','portable','modular','scalable','robust','adaptive','reactive','autonomous','redundant','critical','fragile','stable','quantum','symmetric','asymmetric','compressed','encoded','verified','trusted','isolated','connected','hardened','vulnerable','lightweight','complex','nested','linear','random','sequential','logical','physical','temporal','spatial','global','local','public','private','internal','external','primary','secondary','active','passive',
  // Descriptive
  'ancient','modern','classical','bright','dark','narrow','wide','tall','short','deep','shallow','sharp','smooth','rough','heavy','light','swift','slow','loud','quiet','warm','cold','frozen','burning','golden','silver','iron','wooden','crystal','hollow','solid','broken','whole','empty','full','open','closed','vast','tiny','enormous','miniature',
  // Quality
  'brilliant','clever','careful','reckless','patient','restless','fearless','cautious','bold','gentle','fierce','calm','wild','strange','familiar','mysterious','obvious','subtle','elegant','crude','precise','vague','certain','doubtful','reliable','unstable','powerful','weak','mighty','humble','proud','loyal','defiant','silent','noisy','peaceful','violent','graceful','clumsy','cunning',
  // Colors & sensory
  'crimson','azure','emerald','obsidian','ivory','amber','violet','scarlet','cobalt','copper','bronze','sapphire','jade','coral','onyx','pearl','turquoise','mahogany','slate','charcoal','dusty','gleaming','glowing','shimmering','sparkling','flickering','pulsing','fading','vivid','pale','muted','translucent'
];
const _VERBS=[
  // Technical
  'encrypts','decrypts','processes','analyzes','monitors','detects','prevents','validates','transmits','receives','compiles','executes','generates','transforms','parses','scans','filters','routes','caches','queries','hashes','verifies','authenticates','authorizes','synchronizes','compresses','encodes','decodes','intercepts','bypasses','deploys','configures','initializes','terminates','recovers','restores','archives','optimizes',
  // Physical
  'carries','crosses','follows','reaches','climbs','descends','circles','surrounds','breaks','builds','destroys','creates','opens','closes','locks','unlocks','lifts','drops','pushes','pulls','throws','catches','holds','releases','gathers','scatters','strikes','blocks','dodges','chases','flees','hides','reveals','covers','exposes',
  // Mental & social
  'discovers','remembers','forgets','understands','believes','doubts','decides','chooses','refuses','accepts','demands','offers','promises','warns','teaches','learns','studies','solves','questions','answers','explains','describes','imagines','considers','evaluates','judges','measures','compares','combines','separates','connects','divides','arranges','organizes','inspects','examines','investigates','challenges','conquers','defends','protects','guards','watches','observes','notices','recognizes','identifies','locates','searches','finds','loses','wins','fails','succeeds','attempts','achieves','abandons','continues','begins','finishes','completes'
];
const _ADVS=[
  'quickly','silently','efficiently','securely','repeatedly','automatically','continuously','periodically','randomly','sequentially','concurrently','atomically','gracefully','forcefully','temporarily','permanently','partially','completely','incrementally','dramatically','substantially','reliably','consistently','occasionally','frequently','rarely','always','never','sometimes','internally','externally','locally','remotely','carefully','carelessly','boldly','cautiously','steadily','suddenly','gradually','instantly','eventually','immediately','deliberately','accidentally','naturally','artificially','precisely','roughly','approximately','exactly','merely','entirely','barely','hardly','mostly','largely','mainly','purely','simply','deeply','highly','strongly','weakly','firmly','loosely','tightly','broadly','narrowly','openly','secretly','directly','indirectly','formally','casually','desperately','calmly','furiously','patiently','reluctantly','eagerly','willingly'
];
const _PREPS=[
  'through','across','behind','beyond','within','without','beneath','between','against','toward','around','along','above','below','inside','outside','under','over','before','after','during','until','since','despite','regarding','concerning','involving','including','excluding','following','preceding','surrounding','underlying','supporting','protecting','among','amid','alongside','opposite','near','past','beside','throughout','upon','onto','into','from','towards','aboard','atop'
];
const _NAMES=['alice','robert','chen','maria','james','sarah','dmitri','elena','marcus','priya','thomas','fatima','kenji','sofia','oliver','nadia','carlos','ingrid','hassan','maya','felix','diana','oscar','petra','rafael','clara','boris','leona','samuel','yuki'];
const _PLACES=['london','tokyo','berlin','cairo','mumbai','sydney','toronto','oslo','dublin','prague','vienna','lisbon','nairobi','santiago','bangkok','moscow','havana','athens','seoul','lima','zurich','ankara','warsaw','bogota','manila','hanoi','riyadh','stockholm','bucharest','helsinki'];
const _TIMES=['yesterday','today','tomorrow','last night','this morning','at midnight','before sunrise','after sunset','at noon','during the storm','in the evening','at dusk','before dawn','in the afternoon','moments ago','hours later','days before','weeks after','long ago','recently'];

// 40 sentence templates with varied grammatical structures
const _TEMPLATES=[
  // Simple declarative
  ()=>`the ${ra()} ${rn()} ${rv()} the ${ra()} ${rn()} ${rp()} the ${rn()}`,
  ()=>`a ${ra()} ${rn()} ${rv()} the ${rn()} and the ${rn()} ${rad()}`,
  ()=>`the ${rn()} ${rv()} every ${ra()} ${rn()} ${rp()} the ${ra()} ${rn()}`,
  // Complex declarative
  ()=>`${ra()} ${rn()} and ${ra()} ${rn()} ${rv()} the ${rn()} ${rp()} ${rn()} ${rad()}`,
  ()=>`the ${ra()} ${rn()} ${rp()} the ${rn()} ${rv()} ${rad()} and ${rv()} the ${rn()}`,
  ()=>`the ${rn()} ${rn()} ${rv()} ${rad()} while the ${ra()} ${rn()} ${rv()} the ${rn()}`,
  ()=>`the ${rn()} ${rv()} the ${rn()} ${rp()} the ${rn()} and ${rv()} the ${ra()} ${rn()} ${rad()}`,
  // Conditional & temporal
  ()=>`when the ${rn()} ${rv()} the ${ra()} ${rn()} must ${rv2()} ${rad()}`,
  ()=>`after the ${rn()} ${rv()} the ${rn()} ${rv()} ${rad()} ${rp()} ${rn()}`,
  ()=>`before the ${ra()} ${rn()} can ${rv2()} the ${rn()} needs to ${rv2()} first`,
  ()=>`if the ${rn()} ${rv()} ${rad()} then the ${ra()} ${rn()} will ${rv2()} the ${rn()}`,
  ()=>`until the ${ra()} ${rn()} ${rv()} the ${rn()} the ${rn()} cannot ${rv2()}`,
  // Quantified
  ()=>`every ${rn()} ${rv()} ${ra()} ${rn()} but the ${rn()} ${rv()} ${rad()}`,
  ()=>`no ${ra()} ${rn()} can ${rv2()} the ${rn()} ${rp()} a ${ra()} ${rn()}`,
  ()=>`several ${ra()} ${rn()} ${rv()} the ${rn()} ${rp()} the ${ra()} ${rn()}`,
  ()=>`each ${ra()} ${rn()} ${rv()} another ${ra()} ${rn()} ${rp()} their ${rn()}`,
  ()=>`most ${ra()} ${rn()} ${rv()} ${rad()} but some ${rv()} the ${rn()} ${rp()} ${rn()}`,
  ()=>`only the ${ra()} ${rn()} ${rv()} the ${rn()} ${rn()} ${rad()} ${rp()} the ${rn()}`,
  ()=>`both the ${rn()} and the ${rn()} ${rv()} the ${ra()} ${rn()} ${rad()}`,
  // Possessive & relational
  ()=>`our ${ra()} ${rn()} ${rv()} their ${ra()} ${rn()} ${rp()} the ${rn()} ${rn()}`,
  ()=>`this ${ra()} ${rn()} ${rv()} ${ra()} ${rn()} that ${rv()} ${rad()}`,
  ()=>`${rname()} said the ${ra()} ${rn()} ${rv()} the ${rn()} ${rad()}`,
  // Named entities
  ()=>`${rname()} and ${rname()} ${rv2()} the ${ra()} ${rn()} ${rp()} ${rplace()}`,
  ()=>`the ${rn()} ${rp()} ${rplace()} ${rv()} ${rad()} ${rp()} the ${ra()} ${rn()}`,
  ()=>`${rname()} ${rv2()} the ${ra()} ${rn()} ${rp()} the ${rn()} in ${rplace()} ${rad()}`,
  ()=>`in ${rplace()} the ${ra()} ${rn()} ${rv()} the ${rn()} that ${rname()} ${rv2()}`,
  // Temporal
  ()=>`${rtime()} the ${ra()} ${rn()} ${rv2()} the ${rn()} ${rp()} the ${ra()} ${rn()}`,
  ()=>`the ${rn()} ${rv2()} ${rad()} ${rtime()} while the ${rn()} ${rv2()} ${rp()} ${rplace()}`,
  // Numerical
  ()=>`${rnum()} ${ra()} ${rn()} ${rv()} the ${rn()} ${rp()} ${rnum()} ${ra()} ${rn()}`,
  ()=>`the ${rn()} ${rv()} exactly ${rnum()} ${ra()} ${rn()} ${rad()} ${rp()} the ${rn()}`,
  ()=>`after ${rnum()} ${rn()} ${rv2()} the ${ra()} ${rn()} finally ${rv2()} ${rad()}`,
  // Passive voice
  ()=>`the ${ra()} ${rn()} was ${rv2()}ed ${rp()} the ${rn()} by ${rname()} ${rtime()}`,
  ()=>`the ${rn()} had been ${rv2()}ed ${rad()} ${rp()} the ${ra()} ${rn()} for ${rnum()} days`,
  // Questions (as statements)
  ()=>`whether the ${rn()} ${rv()} the ${ra()} ${rn()} ${rp()} the ${rn()} remains unclear`,
  ()=>`how the ${ra()} ${rn()} ${rv()} the ${rn()} ${rad()} is still a ${rn()} to ${rname()}`,
  // Compound sentences
  ()=>`the ${rn()} ${rv()} ${rad()} and the ${ra()} ${rn()} ${rv()} the ${rn()} but the ${rn()} ${rv()} ${rp()} ${rn()}`,
  ()=>`although the ${ra()} ${rn()} ${rv()} ${rad()} the ${rn()} still ${rv()} the ${ra()} ${rn()} ${rp()} ${rplace()}`,
  ()=>`${rname()} ${rv2()} that the ${ra()} ${rn()} ${rv()} the ${rn()} while the ${rn()} ${rv()} ${rad()} ${rp()} ${rn()}`,
  // Lists
  ()=>`the ${rn()} the ${rn()} and the ${rn()} all ${rv2()} the ${ra()} ${rn()} ${rp()} ${rplace()} ${rad()}`,
  ()=>`${rname()} ${rv2()} ${rnum()} ${rn()} ${rnum()} ${rn()} and ${rnum()} ${ra()} ${rn()} ${rp()} the ${rn()}`,
];

function rn(){return _NOUNS[Math.floor(Math.random()*_NOUNS.length)];}
function ra(){return _ADJS[Math.floor(Math.random()*_ADJS.length)];}
function rv(){return _VERBS[Math.floor(Math.random()*_VERBS.length)];}
function rv2(){return _VERBS[Math.floor(Math.random()*_VERBS.length)].replace(/s$/,'');}
function rad(){return _ADVS[Math.floor(Math.random()*_ADVS.length)];}
function rp(){return _PREPS[Math.floor(Math.random()*_PREPS.length)];}
function rname(){return _NAMES[Math.floor(Math.random()*_NAMES.length)];}
function rplace(){return _PLACES[Math.floor(Math.random()*_PLACES.length)];}
function rtime(){return _TIMES[Math.floor(Math.random()*_TIMES.length)];}
function rnum(){return String(2+Math.floor(Math.random()*98));}
function rndChoice(arr){return arr[Math.floor(Math.random()*arr.length)];}

function generateText(short=false){
  const tmpl=_TEMPLATES[Math.floor(Math.random()*_TEMPLATES.length)];
  let text=tmpl();
  if(short)text=text.split(' ').slice(0,3+Math.floor(Math.random()*4)).join(' ');
  return text;
}

// Key pools for ciphers (also randomized per sample)
const VIG_KEYS=['KEY','SECRET','CIPHER','ALPHA','BRAVO','DELTA','ENIGMA','CRYPTO','SECURE','HIDDEN','PHOENIX','STORM','QUANTUM','NEBULA','FALCON'];
const AFFINE_A=[1,3,5,7,9,11,15,17,19,21,23,25];
const COL_KEYS=['ZEBRA','CASTLE','STORM','PYTHON','MATRIX','FALCON','CRYPTO','HIDDEN'];


// ═══════════════════════════════════════════════════════════════════════
//  TRAINING ENGINE — Web Worker (4A) for non-blocking training
//  The worker embeds ciphers.js + encoders.js + ml.js + corpus/genSample
//  Main thread handles: IndexedDB storage, UI updates, KB/confusion writes
//  Worker handles: sample generation, feature extraction, forest training, eval
// ═══════════════════════════════════════════════════════════════════════

let trainRunning=false,trainAbort=false,trainWorker=null;
function rndChoice(arr){return arr[Math.floor(Math.random()*arr.length)]}

function genSample(type,short=false){
  let text=generateText(short);
  switch(type){
    case'plaintext':return text;
    case'caesar':return Caesar.encrypt(text,1+Math.floor(Math.random()*25));
    case'vigenere':return Vigenere.encrypt(text,rndChoice(VIG_KEYS));
    case'substitution':return applySub(text,genSubKey(()=>Math.floor(Math.random()*1e9)));
    case'atbash':return Atbash.transform(text);
    case'affine':return affineEnc(text,rndChoice(AFFINE_A),Math.floor(Math.random()*26));
    case'rail_fence':return railEnc(text,2+Math.floor(Math.random()*5));
    case'enigma':return enigmaProcess(text,['III','II','I'],'B',[Math.floor(Math.random()*26),Math.floor(Math.random()*26),Math.floor(Math.random()*26)]);
    case'xor_single':return XorCipher.encryptSingle(text,1+Math.floor(Math.random()*254));
    case'xor_repeating':return XorCipher.encryptRepeating(text,rndChoice(VIG_KEYS));
    case'rc4':return RC4.encrypt(text,String.fromCharCode(Math.floor(Math.random()*256),Math.floor(Math.random()*256)));
    case'beaufort':return Beaufort.encrypt(text,rndChoice(VIG_KEYS));
    case'porta':return Porta.encrypt(text,rndChoice(VIG_KEYS));
    case'columnar':return Columnar.encrypt(text.toUpperCase().replace(/[^A-Z]/g,''),rndChoice(COL_KEYS));
    case'rot47':return ROT47.transform(text);
    case'binary':return Encoders.binary.encode(text);
    case'hex':return Encoders.hex.encode(text);
    case'base64':return Encoders.base64.encode(text);
    case'morse':return Encoders.morse.encode(text);
    case'octal':return Encoders.octal.encode(text);
    case'decimal':return Encoders.decimal.encode(text);
    case'url':return Encoders.url.encode(text);
    case'bacon':return Encoders.bacon.encode(text);
    case'multi_layer':return Encoders.multi.encode(text).encoded;
    // ── 20 NEW TYPES ──
    case'rot13':return ROT13_cipher.encrypt(text);
    case'a1z26':return A1Z26.encode(text);
    case'playfair':return Playfair.encrypt(text,rndChoice(VIG_KEYS));
    case'vigenere_autokey':return VigenereAutokey.encrypt(text,rndChoice(VIG_KEYS));
    case'reverse':return ReverseText.encrypt(text);
    case'scytale':return Scytale.encrypt(text,3+Math.floor(Math.random()*6));
    case'route_cipher':return RouteCipher.encrypt(text,3+Math.floor(Math.random()*6));
    case'base32':return Base32.encode(text);
    case'base58':return Base58.encode(text);
    case'ascii85':return Ascii85.encode(text);
    case'uuencode':return UUEncode.encode(text);
    case'html_entities':return HTMLEntities.encode(text);
    case'bifid':return Bifid.encrypt(text,rndChoice(VIG_KEYS));
    case'polybius':return PolybiusSquare.encode(text);
    case'adfgvx':return ADFGVX.encode(text);
    case'tap_code':return TapCode.encode(text);
    case'phone_keypad':return PhoneKeypad.encode(text);
    case'nato_phonetic':return NATOPhonetic.encode(text);
    case'word_sub':return WordSub.encrypt(text,Math.floor(Math.random()*1e9));
    case'hex_shuffle':return HexShuffle.encrypt(text,Math.floor(Math.random()*1e9));
    default:return text;
  }
}

// Build a Web Worker from inline code (4A)
function createTrainWorker(){
  // Collect all the source code the worker needs
  const scripts=document.querySelectorAll('script[src]');
  // For inline single-file builds, we grab script tag contents
  const allScripts=document.querySelectorAll('script:not([src])');
  let ciphersCode='',encodersCode='',mlCode='';
  const scriptTags=[...document.querySelectorAll('script')];
  for(const s of scriptTags){
    const txt=s.textContent||'';
    if(!ciphersCode&&txt.includes('const ENGLISH_FREQ=')&&txt.includes('Caesar=')&&!txt.includes('createTrainWorker'))ciphersCode=txt;
    else if(!encodersCode&&txt.includes('const Encoders=')&&txt.includes('detectEncoding')&&!txt.includes('createTrainWorker'))encodersCode=txt;
    else if(!mlCode&&txt.includes('const FEATURE_COUNT')&&txt.includes('extractFeatures')&&!txt.includes('createTrainWorker'))mlCode=txt;
  }

  // If we couldn't find inline scripts (multi-file mode), we can't make a worker
  if(!ciphersCode||!encodersCode||!mlCode){
    console.warn('[Worker] Could not find inline script code — falling back to main-thread training');
    return null;
  }

  const workerCode=`
// ═══ Web Worker: Training Pipeline ═══
${ciphersCode}
${encodersCode}
${mlCode}

const CORPUS_COMPAT=[]; // kept for compatibility — not used
const VIG_KEYS=${JSON.stringify(VIG_KEYS)};
const AFFINE_A=${JSON.stringify(AFFINE_A)};
const COL_KEYS=${JSON.stringify(COL_KEYS)};
const _NOUNS=${JSON.stringify(_NOUNS)};
const _ADJS=${JSON.stringify(_ADJS)};
const _VERBS=${JSON.stringify(_VERBS)};
const _ADVS=${JSON.stringify(_ADVS)};
const _PREPS=${JSON.stringify(_PREPS)};
const _NAMES=${JSON.stringify(_NAMES)};
const _PLACES=${JSON.stringify(_PLACES)};
const _TIMES=${JSON.stringify(_TIMES)};
${rn.toString()}
${ra.toString()}
${rv.toString()}
${rv2.toString()}
${rad.toString()}
${rp.toString()}
${rname.toString()}
${rplace.toString()}
${rtime.toString()}
${rnum.toString()}
function rndChoice(arr){return arr[Math.floor(Math.random()*arr.length)]}
const _TEMPLATES=${JSON.stringify(_TEMPLATES.map(f=>f.toString()))}.map(s=>eval('('+s+')'));
${generateText.toString()}
${genSample.toString()}

let model=new DecisionForest();
let abort=false;

self.onmessage=function(e){
  const msg=e.data;
  if(msg.cmd==='stop'){abort=true;return;}
  if(msg.cmd==='train'){
    abort=false;
    const{storedX,storedY,sampPerType,maxIter,continuous,existingModel}=msg;
    // Misclassified samples from previous sessions — include in every iteration
    const missX=storedX.map(a=>new Float64Array(a));
    const missY=[...storedY];
    if(existingModel){try{model.load(existingModel);}catch(e){}}
    const types=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','word_sub','hex_shuffle'];
    let confusedTypes=new Set(); // tracks which types the model struggles with

    for(let iter=1;iter<=maxIter&&!abort;iter++){
      self.postMessage({type:'log',msg:'── Iteration '+iter+(continuous?' (continuous)':'/'+maxIter)+' ──'});
      self.postMessage({type:'progress',iter:iter,phase:'generating'});

      // Phase 1: Generate fresh samples for ALL types
      const freshX=[],freshY=[],freshTexts=[];
      for(const type of types){
        // Confused types get 2x samples to help the model learn them
        const count=confusedTypes.has(type)?sampPerType*2:sampPerType;
        for(let i=0;i<count;i++){
          try{
            const isShort=i>=count*0.8;
            const ct=genSample(type,isShort);
            if(ct&&ct.length>=8){const f=extractFeatures(ct);if(!f.some(isNaN)){freshX.push(f);freshY.push(type);freshTexts.push(ct);}}
          }catch(e){}
        }
        if(abort)break;
      }
      if(abort)break;
      self.postMessage({type:'log',msg:'[data] Generated '+freshX.length+' fresh samples'+(confusedTypes.size?' ('+confusedTypes.size+' confused types boosted 2x)':'')+(missX.length?' + '+missX.length+' misclassified reinforcement':'')});

      // Phase 2: Train on fresh samples + misclassified reinforcement
      self.postMessage({type:'progress',iter:iter,phase:'training'});
      const trainX=[...freshX,...missX];const trainY=[...freshY,...missY];
      model.train(trainX,trainY,20,10,3);
      self.postMessage({type:'log',msg:'[ml] Trained on '+trainX.length+' samples (20 trees, depth 10), OOB: '+(model.oobAccuracy*100).toFixed(1)+'%'});
      self.postMessage({type:'model',json:model.save()});

      // Send fresh samples back for storage
      self.postMessage({type:'samples',X:freshX.map(f=>Array.from(f)),Y:freshY,texts:freshTexts,iter:iter});

      // Phase 3: Evaluate on the ACTUAL training samples (not random)
      self.postMessage({type:'progress',iter:iter,phase:'evaluating'});
      let correct=0,total=0;const byType={};const confusion=[];
      const testSamples=[];
      for(let i=0;i<freshX.length;i++){
        try{
          const f=freshX[i];const type=freshY[i];
          const pred=model.predict(f);
          total++;
          if(!byType[type])byType[type]={t:0,c:0};byType[type].t++;
          const ok=pred.cls===type;if(ok){correct++;byType[type].c++;}
          confusion.push({actual:type,predicted:pred.cls,confidence:pred.confidence,ok:ok,ic:f[0],ent:f[3]});
          testSamples.push({features:Array.from(f),actual:type});
        }catch(e){}
      }
      const acc=total?correct/total:0;
      
      // Update confused types for next iteration — types below 80% get boosted
      confusedTypes=new Set();
      for(const type in byType){
        if(byType[type].t>=3){
          const typeAcc=byType[type].c/byType[type].t;
          if(typeAcc<0.8)confusedTypes.add(type);
        }
      }
      
      self.postMessage({type:'eval',acc:acc,total:total,correct:correct,byType:byType,confusion:confusion,oob:model.oobAccuracy,iter:iter,testSamples:testSamples,challengerJson:model.save()});
    }
    self.postMessage({type:'done',aborted:abort});
  }
};
self.postMessage({type:'ready'});
`;

  try{
    const blob=new Blob([workerCode],{type:'application/javascript'});
    const url=URL.createObjectURL(blob);
    const w=new Worker(url);
    URL.revokeObjectURL(url); // worker keeps its reference
    return w;
  }catch(e){
    console.warn('[Worker] Failed to create:',e.message);
    return null;
  }
}

async function startTrain(){
  if(trainRunning)return;trainRunning=true;trainAbort=false;
  $('bStart').style.display='none';$('bStop').style.display='';
  $('tDot').innerHTML='<span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--accent);box-shadow:0 0 6px rgba(0,255,136,.5);margin-right:5px" class="pulse"></span>';
  const continuous=$('tContinuous')&&$('tContinuous').checked;
  const maxIter=continuous?999999:(+($('tIter').value)||3);
  const baseSampPerType=+($('tSamp').value)||25;
  // Confusion-adaptive: hard types get more samples, easy types get fewer
  const confMatrix=ConfusionTracker.matrix;
  const confusedTypes=new Set();
  for(const actual in confMatrix){let total=0,errors=0;for(const pred in confMatrix[actual]){total+=confMatrix[actual][pred];if(pred!==actual)errors+=confMatrix[actual][pred];}if(total>10&&errors/total>0.05)confusedTypes.add(actual);}
  const sampPerType=baseSampPerType; // base rate — worker uses this
  const types=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','word_sub','hex_shuffle'];
  const log=[];
  function addLog(msg,ok=true){log.push({msg,ok});if(log.length>500)log.splice(0,log.length-500);
    $('tLog').innerHTML=log.map(l=>`<div class="${l.ok?'lok':'lfail'}">${H(l.msg)}</div>`).join('');$('tLog').scrollTop=$('tLog').scrollHeight;}

  if(continuous)addLog('═══ CONTINUOUS MODE — will run until you click STOP ═══');

  // Load previously misclassified samples for training reinforcement
  addLog('[store] Loading misclassified samples from previous sessions...');
  const missData=await SampleDB.loadMisclassified(200);
  if(missData.count>0)addLog(`[store] Loaded ${missData.count} previously misclassified samples (up to 200/type)`);
  else addLog('[store] No misclassified samples stored yet');

  // Try Web Worker (4A)
  const worker=createTrainWorker();
  if(worker){
    addLog('Training in Web Worker — UI stays responsive');
    trainWorker=worker;

    // Send training data to worker — include misclassified samples
    worker.postMessage({
      cmd:'train',
      storedX:missData.X.map(f=>Array.from(f)),
      storedY:missData.Y,
      sampPerType:sampPerType,
      maxIter:maxIter,
      continuous:continuous,
      existingModel:mlModel.trained?mlModel.save():null
    });

    // Handle messages from worker
    worker.onmessage=async function(e){
      const msg=e.data;
      if(msg.type==='log')addLog(msg.msg,msg.ok!==false);
      else if(msg.type==='progress'){
        $('tsS').textContent=continuous?'RUNNING ∞ [Worker]':'RUNNING [Worker]';$('tsS').style.color='var(--accent)';
        $('tsI').textContent=msg.iter;
        if(!continuous)$('tBar').style.width=((msg.iter-1)/maxIter*100)+'%';
        else $('tBar').style.width=((msg.iter%20)/20*100)+'%';
      }
      else if(msg.type==='model'){
        // Don't accept yet — wait for eval to compare against champion
        // Store challenger JSON temporarily
        trainWorker._pendingModel=msg.json;
      }
      else if(msg.type==='samples'){
        // Save fresh samples to IndexedDB and update centroids
        const X=msg.X.map(a=>new Float64Array(a));
        await DataStore.saveWithTexts(X,msg.Y,msg.texts,{iteration:msg.iter});
        // 3A: Update centroids
        const byType={};for(let i=0;i<X.length;i++){if(!byType[msg.Y[i]])byType[msg.Y[i]]=[];byType[msg.Y[i]].push(X[i]);}
        for(const type in byType)CentroidStore.updateBatch(type,byType[type]);
        CentroidStore.save();
      }
      else if(msg.type==='eval'){
        const challengerAcc=msg.acc;

        // ── FEDERATED MODEL MERGING ────────────────────────
        // Instead of replacing the champion entirely, merge the best
        // challenger trees into the champion, replacing its worst trees.
        // Every training session contributes — no learning is ever lost.

        // Build test arrays for tree evaluation
        const testX=msg.testSamples.map(ts=>new Float64Array(ts.features));
        const testY=msg.testSamples.map(ts=>ts.actual);

        if(!mlModel.trained){
          // No champion yet — accept challenger as first model
          if(msg.challengerJson){mlModel.load(msg.challengerJson);ModelStore.save(mlModel);}
          addLog(`[champion] ▲ First model accepted: ${(challengerAcc*100).toFixed(1)}% (${mlModel.trees.length} trees)`);
        }else{
          // Evaluate champion on same test data
          let championCorrect=0;
          for(let i=0;i<testX.length;i++){if(mlModel.predict(testX[i]).cls===testY[i])championCorrect++;}
          const championAcc=testX.length>0?championCorrect/testX.length:0;

          // Load challenger as a temporary forest for merging
          const challenger=new DecisionForest();
          if(msg.challengerJson)challenger.load(msg.challengerJson);
          else if(trainWorker._pendingModel)challenger.load(trainWorker._pendingModel);

          // Merge best 5 challenger trees into champion, replacing worst 5
          const result=mlModel.mergeFrom(challenger,testX,testY,5,30);

          if(result.merged){
            ModelStore.save(mlModel);
            addLog(`[merge] ▲ Merged ${result.added} trees into champion (replaced ${result.removed} worst) — ${mlModel.trees.length} total trees`);
            addLog(`[merge] Champion: ${(championAcc*100).toFixed(1)}% → ${(result.newAcc*100).toFixed(1)}% | Challenger: ${(challengerAcc*100).toFixed(1)}%`);
          }else{
            addLog(`[merge] ▬ No merge: ${result.reason} (champion ${(championAcc*100).toFixed(1)}% already optimal)`,false);
          }
        }
        trainWorker._pendingModel=null;

        const finalAcc=mlModel.trained?(function(){let c=0;for(let i=0;i<testX.length;i++)if(mlModel.predict(testX[i]).cls===testY[i])c++;return testX.length?c/testX.length:0;})():challengerAcc;
        AccuracyHistory.record(finalAcc,msg.total,msg.iter);
        addLog(`[eval] Active model: ${(finalAcc*100).toFixed(1)}% (${mlModel.trees.length} trees, ${msg.correct}/${msg.total} challenger eval)`);
        addLog(`[eval] OOB estimate: ${(msg.oob*100).toFixed(1)}%`);

        // Record confusion + calibration using batch methods (save once at end)
        // Also collect misclassified samples for future training reinforcement
        const misclassified=[];
        for(const c of msg.confusion){
          ConfusionTracker.recordBatch(c.actual,c.predicted);
          CalibrationTracker.recordBatch(c.confidence,c.ok);
          if(!c.ok){
            // Find the feature vector for this misclassified sample
            const ts=msg.testSamples.find(s=>s.actual===c.actual&&msg.confusion.indexOf(c)>=0);
            if(ts)misclassified.push({features:new Float64Array(ts.features),actual:c.actual,predicted:c.predicted});
          }
          if(KB[c.actual]){KB[c.actual].stats.tested++;if(c.ok)KB[c.actual].stats.cracked++;
            KB[c.actual].icObs.push(+c.ic.toFixed(5));KB[c.actual].entObs.push(+c.ent.toFixed(4));
            if(KB[c.actual].icObs.length>200)KB[c.actual].icObs=KB[c.actual].icObs.slice(-200);
            if(KB[c.actual].entObs.length>200)KB[c.actual].entObs=KB[c.actual].entObs.slice(-200);}
        }
        ConfusionTracker.save();CalibrationTracker.save();
        // Save misclassified samples to IndexedDB + UnsolvedStore
        if(misclassified.length>0){
          const toSave=misclassified.slice(0,500);
          SampleDB.saveMisclassifiedBatch(toSave).then(()=>{
            addLog(`[store] Saved ${toSave.length} misclassified samples for future training`);
          });
          // Add to unsolved store (persistent JSON, up to 100K)
          UnsolvedStore.addUnsolved(toSave);
          const uStats=UnsolvedStore.getStats();
          addLog(`[unsolved] Added ${toSave.length} unsolved samples (${uStats.unsolved.toLocaleString()} unsolved, ${uStats.solved.toLocaleString()} solved total)`);
        }
        // Test unsolved samples against the current champion — mark solved if model now gets them right
        if(mlModel.trained){
          const solveResult=UnsolvedStore.testAndSolve(mlModel);
          if(solveResult.solved>0){
            addLog(`[unsolved] ★ SOLVED ${solveResult.solved}/${solveResult.tested} previously unsolved samples! (${solveResult.remaining.toLocaleString()} remaining)`);
            // Log which types got solved
            const solvedTypes={};
            for(const s of solveResult.solvedSamples){solvedTypes[s.actual]=(solvedTypes[s.actual]||0)+1;}
            const solvedList=Object.entries(solvedTypes).sort((a,b)=>b[1]-a[1]).slice(0,5);
            if(solvedList.length)addLog(`[unsolved] Solved types: ${solvedList.map(([t,n])=>t+':'+n).join(', ')}`);
          }
          UnsolvedStore.save();
        }
        // Per-type display
        const typeEntries=Object.entries(msg.byType).sort((a,b)=>(b[1].c/b[1].t)-(a[1].c/a[1].t));
        for(const[t,d]of typeEntries)addLog(`  ${t}: ${d.c}/${d.t} (${(d.c/d.t*100).toFixed(0)}%)`);
        $('tsA').textContent=(finalAcc*100).toFixed(1)+'%';syncAllStats();
        $('tTypeSection').style.display='';
        $('tTypeAcc').innerHTML=typeEntries.map(([t,d])=>{const pct=d.t?(d.c/d.t*100):0;const color=pct>80?'var(--accent)':pct>50?'var(--orange)':'var(--red)';
          return`<div class="bar-r"><div class="bar-l">${t}</div><div class="bar-t"><div class="bar-f" style="width:${pct.toFixed(0)}%;background:${color}"></div></div><div class="bar-p">${pct.toFixed(0)}%</div></div>`;}).join('');
        // Confusion pairs
        const confPairs=ConfusionTracker.getConfusedPairs(3);
        if(confPairs.length){addLog('[confusion] Top misclassifications:');confPairs.slice(0,5).forEach(p=>addLog(`  ${p.actual} → ${p.predicted}: ${p.count}× (${(p.rate*100).toFixed(0)}%)`,false));}
        // KB discovery
        for(const type of types){if(KB[type]&&KB[type].icObs.length>=5){
          const ics=KB[type].icObs;const icMean=ics.reduce((a,b)=>a+b,0)/ics.length;const icStd=Math.sqrt(ics.reduce((a,v)=>a+(v-icMean)**2,0)/ics.length);
          KB[type].icMean=+icMean.toFixed(5);KB[type].icStd=+icStd.toFixed(5);KB[type].icRange=[+Math.min(...ics).toFixed(5),+Math.max(...ics).toFixed(5)];
          if(KB[type].entObs.length>=5){const ents=KB[type].entObs;KB[type].entMean=+(ents.reduce((a,b)=>a+b,0)/ents.length).toFixed(4);}
          const st=KB[type].stats;const rate=st.tested?(st.cracked/st.tested):0;
          KB[type].insights=`${(rate*100).toFixed(1)}% accuracy (${st.tested} tests). IC=${icMean.toFixed(4)}±${icStd.toFixed(4)}.`;
          if(!KB[type].discoveries)KB[type].discoveries=[];
          KB[type].discoveries.push(`Iter ${msg.iter}: IC=${icMean.toFixed(4)}, acc=${(rate*100).toFixed(1)}%, OOB=${(msg.oob*100).toFixed(1)}%`);
          if(KB[type].discoveries.length>20)KB[type].discoveries=KB[type].discoveries.slice(-20);
        }}
        saveKB();
      }
      else if(msg.type==='done'){
        const finalIter=+($('tsI').textContent)||0;
        $('tBar').style.width='100%';$('tsS').textContent=msg.aborted?'STOPPED':'DONE';$('tsS').style.color=msg.aborted?'var(--orange)':'var(--teal)';
        DataStore.getStats().then(dsStats=>{
          addLog(`═══ Training ${msg.aborted?'stopped':'complete'} after ${finalIter} iterations! ═══`);
          addLog(`[db] ${dsStats.total.toLocaleString()} total samples stored`);
        });
        syncAllStats();$('bStart').style.display='';$('bStop').style.display='none';$('tDot').innerHTML='';
        trainRunning=false;trainWorker=null;worker.terminate();
      }
    };
    worker.onerror=function(e){
      addLog('[Worker ERROR] '+e.message,false);
      $('bStart').style.display='';$('bStop').style.display='none';$('tDot').innerHTML='';
      trainRunning=false;trainWorker=null;
    };
  } else {
    // ── FALLBACK: Main-thread training ──
    addLog('[fallback] Training on main thread (Worker unavailable)');
    const fallbackMiss=await SampleDB.loadMisclassified(200);
    if(fallbackMiss.count>0)addLog(`[store] Loaded ${fallbackMiss.count} misclassified samples for reinforcement`);
    let confusedTypes=new Set();
    for(let iter=1;iter<=maxIter&&!trainAbort;iter++){
      $('tsS').textContent=continuous?'RUNNING ∞':'RUNNING';$('tsS').style.color='var(--accent)';$('tsI').textContent=iter;
      if(!continuous)$('tBar').style.width=((iter-1)/maxIter*100)+'%';
      else $('tBar').style.width=((iter%20)/20*100)+'%';
      addLog(`── Iteration ${iter}${continuous?' (continuous)':'/'+maxIter} ──`);
      const freshX=[],freshY=[],freshTexts=[];
      for(const type of types){
        const count=confusedTypes.has(type)?sampPerType*2:sampPerType;
        for(let i=0;i<count;i++){try{const isShort=i>=count*0.8;const ct=genSample(type,isShort);if(ct&&ct.length>=8){const f=extractFeatures(ct);if(!f.some(isNaN)){freshX.push(f);freshY.push(type);freshTexts.push(ct);}}}catch(e){}}
        await new Promise(r=>setTimeout(r,0));if(trainAbort)break;
      }
      addLog(`[data] Generated ${freshX.length} fresh samples${confusedTypes.size?' ('+confusedTypes.size+' confused types boosted 2x)':''}${fallbackMiss.count?' + '+fallbackMiss.count+' misclassified reinforcement':''}`);
      const trainX=[...freshX,...fallbackMiss.X];const trainY=[...freshY,...fallbackMiss.Y];
      addLog(`[ml] Training challenger (${trainX.length} samples, ${FEATURE_COUNT} features)...`);
      await new Promise(r=>setTimeout(r,10));
      const challenger=new DecisionForest();
      // trainAsync yields between trees so the main thread doesn't freeze
      await challenger.trainAsync(trainX,trainY,20,10,3,(done,total)=>{
        if(!continuous)$('tBar').style.width=(((iter-1)/maxIter)+(done/total/maxIter))*100+'%';
      });
      addLog(`[ml] Trained on ${trainX.length} samples (20 trees, depth 10), OOB: ${(challenger.oobAccuracy*100).toFixed(1)}%`);
      await DataStore.saveWithTexts(freshX,freshY,freshTexts,{iteration:iter});
      const cbt={};for(let i=0;i<freshX.length;i++){if(!cbt[freshY[i]])cbt[freshY[i]]=[];cbt[freshY[i]].push(freshX[i]);}
      for(const t in cbt)CentroidStore.updateBatch(t,cbt[t]);CentroidStore.save();
      // Evaluate on actual training samples
      const testX=freshX,testY=freshY;
      let challCorrect=0;for(let i=0;i<testX.length;i++){if(challenger.predict(testX[i]).cls===testY[i])challCorrect++;}
      const challAcc=testX.length?challCorrect/testX.length:0;
      // Federated merge
      if(!mlModel.trained){
        mlModel=challenger;ModelStore.save(mlModel);
        addLog(`[champion] ▲ First model: ${(challAcc*100).toFixed(1)}%`);
      }else{
        let champCorrect=0;for(let i=0;i<testX.length;i++){if(mlModel.predict(testX[i]).cls===testY[i])champCorrect++;}
        const champAcc=testX.length?champCorrect/testX.length:0;
        const result=mlModel.mergeFrom(challenger,testX,testY,5,30);
        if(result.merged){ModelStore.save(mlModel);addLog(`[merge] ▲ Merged ${result.added} trees — ${champAcc.toFixed(3)}→${result.newAcc.toFixed(3)} (${mlModel.trees.length} trees)`);}
        else addLog(`[merge] ▬ No merge: ${result.reason}`,false);
      }
      // Record confusion/calibration (batched — save once) + collect misclassified
      const byType={};const misclassified=[];
      for(let i=0;i<testX.length;i++){const pred=mlModel.predict(testX[i]);const ok=pred.cls===testY[i];
        if(!byType[testY[i]])byType[testY[i]]={c:0,t:0};byType[testY[i]].t++;if(ok)byType[testY[i]].c++;
        if(!ok)misclassified.push({features:testX[i],actual:testY[i],predicted:pred.cls});
        ConfusionTracker.recordBatch(testY[i],pred.cls);CalibrationTracker.recordBatch(pred.confidence,ok);if(KB[testY[i]]){KB[testY[i]].stats.tested++;if(ok)KB[testY[i]].stats.cracked++;KB[testY[i]].icObs.push(+testX[i][0].toFixed(5));KB[testY[i]].entObs.push(+testX[i][3].toFixed(4));if(KB[testY[i]].icObs.length>200)KB[testY[i]].icObs=KB[testY[i]].icObs.slice(-200);if(KB[testY[i]].entObs.length>200)KB[testY[i]].entObs=KB[testY[i]].entObs.slice(-200);}}
      ConfusionTracker.save();CalibrationTracker.save();
      if(misclassified.length>0){
        const toSave=misclassified.slice(0,500);
        SampleDB.saveMisclassifiedBatch(toSave).then(()=>addLog(`[store] Saved ${toSave.length} misclassified samples`));
        UnsolvedStore.addUnsolved(toSave);
        addLog(`[unsolved] Added ${toSave.length} unsolved (${UnsolvedStore.getUnsolvedCount().toLocaleString()} total unsolved)`);
      }
      // Test unsolved against current model
      if(mlModel.trained){
        const solveResult=UnsolvedStore.testAndSolve(mlModel);
        if(solveResult.solved>0)addLog(`[unsolved] ★ SOLVED ${solveResult.solved}/${solveResult.tested} previously unsolved! (${solveResult.remaining.toLocaleString()} remaining)`);
        UnsolvedStore.save();
      }
      let fCorrect=0;for(let i=0;i<testX.length;i++)if(mlModel.predict(testX[i]).cls===testY[i])fCorrect++;
      const finalAcc=testX.length?fCorrect/testX.length:0;
      // Update confused types for next iteration
      confusedTypes=new Set();
      for(const type in byType){if(byType[type].t>=3&&byType[type].c/byType[type].t<0.8)confusedTypes.add(type);}
      addLog(`[eval] Active: ${(finalAcc*100).toFixed(1)}% (${mlModel.trees.length} trees)`);
      AccuracyHistory.record(finalAcc,freshX.length,iter);
      $('tsA').textContent=(finalAcc*100).toFixed(1)+'%';syncAllStats();
      $('tTypeSection').style.display='';$('tTypeAcc').innerHTML=Object.entries(byType).sort((a,b)=>(b[1].c/b[1].t)-(a[1].c/a[1].t)).map(([t,d])=>{const pct=d.t?(d.c/d.t*100):0;return`<div class="bar-r"><div class="bar-l">${t}</div><div class="bar-t"><div class="bar-f" style="width:${pct.toFixed(0)}%;background:${pct>80?'var(--accent)':pct>50?'var(--orange)':'var(--red)'}"></div></div><div class="bar-p">${pct.toFixed(0)}%</div></div>`;}).join('');
      saveKB();await new Promise(r=>setTimeout(r,0));
    }
    $('tBar').style.width='100%';$('tsS').textContent=trainAbort?'STOPPED':'DONE';$('tsS').style.color=trainAbort?'var(--orange)':'var(--teal)';
    DataStore.getStats().then(ds=>addLog(`═══ Done! ${ds.total.toLocaleString()} samples stored ═══`));
    syncAllStats();$('bStart').style.display='';$('bStop').style.display='none';$('tDot').innerHTML='';trainRunning=false;
  }
}

function stopTrain(){
  trainAbort=true;
  if(trainWorker){trainWorker.postMessage({cmd:'stop'});}
}

// ═══════════════════════════════════════════════════════════════════════
//  UI HANDLERS
// ═══════════════════════════════════════════════════════════════════════

// Decrypt
function copyText(text){navigator.clipboard?navigator.clipboard.writeText(text):prompt('Copy:',text);}
function doDec(){
  const text=$('dIn').value.trim();if(!text)return;const o=$('dOut');
  const dec=decodeInput(text);
  let mlResult=null;
  if($('dML').checked&&mlModel.trained){const f=extractFeatures(text);mlResult=mlModel.predict(f);}
  const feats=extractFeatures(text);

  let h='';
  if(dec.decoded!==text||dec.steps.length){
    h+=`<div class="rb"><div class="rl">DECODED OUTPUT <button class="bs" style="float:right;font-size:.55rem;padding:3px 10px" onclick="copyText(this.closest('.rb').querySelector('.rv').textContent)">COPY</button></div><div class="rv">${H(dec.decoded)}</div></div>`;
  }
  h+=`<div class="rb blu"><div class="rl">DETECTION</div><div style="font-family:var(--mono);font-size:.75rem;color:var(--text);line-height:2">`;
  h+=`Encoding: <b style="color:var(--bright)">${dec.encoding}</b> &nbsp; Method: <b style="color:var(--bright)">${dec.method}</b><br>`;
  if(mlResult){
    const calConf=CalibrationTracker.getCalibratedConfidence(mlResult.confidence);
    h+=`ML: <b style="color:var(--accent)">${mlResult.cls}</b> (${(mlResult.confidence*100).toFixed(1)}%`;
    if(Math.abs(calConf-mlResult.confidence)>0.05)h+=` → calibrated: ${(calConf*100).toFixed(0)}%`;
    h+=`) <span class="badge">random_forest_20t</span><br>`;
    const sorted=Object.entries(mlResult.probs).sort((a,b)=>b[1]-a[1]).slice(0,5);
    h+='Probs: '+sorted.map(([k,v])=>`${k}:${(v*100).toFixed(1)}%`).join(' ')+`<br>`;
    // 3A: Show centroid ranking
    const centroidRank=CentroidStore.rank(feats);
    if(centroidRank.length>=2)h+=`Centroid: <span style="color:var(--teal)">${centroidRank[0].type}</span> (d=${centroidRank[0].distance.toFixed(2)}) · ${centroidRank[1].type} (d=${centroidRank[1].distance.toFixed(2)})<br>`;
    // 5A: Correction UI
    const escapedText=text.replace(/\\/g,'\\\\').replace(/'/g,"\\'").replace(/\n/g,'\\n');
    h+=`</div></div>`;
    h+=`<div class="rb" style="border-color:rgba(255,159,67,.2)"><div class="rl" style="color:var(--orange)">WRONG PREDICTION? CORRECT IT</div>`;
    h+=`<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:6px">`;
    h+=`<span style="font-family:var(--mono);font-size:.65rem;color:var(--dim)">Actual type:</span>`;
    h+=`<select id="corrType" style="padding:4px 8px;background:var(--bg2);color:var(--bright);border:1px solid var(--brd);border-radius:6px;font-family:var(--mono);font-size:.7rem">`;
    h+=`<option value="">— select —</option>`;
    for(const t of ALL_TYPES)h+=`<option value="${t}"${t===mlResult.cls?' selected':''}>${t}</option>`;
    h+=`</select>`;
    h+=`<button class="bs" onclick="correctPrediction('${escapedText}')">SAVE CORRECTION</button>`;
    h+=`</div><div id="corrStatus" style="margin-top:6px;font-family:var(--mono);font-size:.65rem"></div></div>`;
  } else {
  h+=`</div></div>`;
  }
  h+=`<div class="rb blu"><div class="rl">STATISTICS</div><div style="font-family:var(--mono);font-size:.75rem;color:var(--text);line-height:2">`;
  h+=`IC:${feats[0].toFixed(4)} Chi²:${feats[1].toFixed(2)} Entropy:${feats[3].toFixed(3)} FreqCorr:${feats[2].toFixed(3)} ByteEnt:${feats[61].toFixed(3)}<br></div></div>`;
  if(dec.steps.length){h+=`<div class="pipe"><div class="pt">PIPELINE</div>`;dec.steps.forEach((s,i)=>h+=`<div class="ps"><div class="pn">${i+1}</div><div class="pl">${H(s.l)}</div><div class="pd">${H(s.d)}</div></div>`);h+=`</div>`;}
  if(dec.runners&&dec.runners.length){h+=`<div class="pipe"><div class="pt">RUNNER-UP ATTEMPTS (${dec.runners.length})</div>`;dec.runners.forEach(r=>h+=`<div class="ps"><div class="pn">~</div><div class="pl">${H(r.name)}</div><div class="pd">score: ${r.score.toFixed(3)}</div></div>`);h+=`</div>`;}
  h+=`<div class="pipe"><div class="pt">EXTRACTED METADATA (${FEATURE_COUNT} features)</div><div class="fg" id="decFG">`;
  const fnames=['ic','chi²','freqCorr','entropy','normEnt','distinct','maxFreq','minFreq','freqStd','bigramDiv','commonBi','commonTri','repTri'];
  for(let i=0;i<13;i++)h+=renderFI(fnames[i],feats[i],'decFG');
  h+=renderFI('byteEnt',feats[61],'decFG');
  h+=renderFI('printable',feats[62],'decFG');
  h+=renderFI('highByte',feats[64],'decFG');
  // Key new features
  h+=`</div><div class="fg" id="decFG2" style="margin-top:8px"><div style="font-family:var(--mono);font-size:.6rem;color:var(--accent);margin-bottom:6px;letter-spacing:.08em">▸ NEW CONTEXTUAL FEATURES</div>`;
  const newFeatMap=[
    ['charClassTrans',57],['sepRegularity',58],['bigramEnt',13],['trigramEnt',14],
    ['quadHitRate',15],['longestRepeat',17],['acPeakRatio',45],['maxIC',33],['bestKL',34],
    ['isAlpha',106],['isHex',107],['isBinary',108],['isBase64',109],['isBacon',110],
    ['encPreCheck',112],['rawLenSig',113],
    ['byteBigramEnt',71],['byteDeltaStd',72],['rlCompRatio',74],['byteChiNorm',75],
    ['mixedCase',80],['trailingEq',83],['qEntStd',90],['byteMedian',98],['byteIQR',99],
    ['bitsPerChar',127]
  ];
  for(const[name,idx]of newFeatMap)h+=renderFI(name,feats[idx],'decFG2');
  h+=`</div><p style="font-family:var(--mono);font-size:.58rem;color:var(--dim);margin-top:10px">Click any feature for explanation · ${FEATURE_COUNT} total features extracted</p></div>`;
  o.innerHTML=h;
}

// Encrypt
let curC='caesar';let xorMode='single';
function selC(c,btn){curC=c;
  document.querySelectorAll('#cBtns .bs, #eBtns .bs').forEach(b=>b.classList.remove('on'));btn.classList.add('on');
  const m={
    caesar:'<div class="lbl" style="margin-top:12px">SHIFT</div><input type="number" id="cS" value="3" min="1" max="25" style="width:100px">',
    vigenere:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="vK" value="SECRET" style="width:200px">',
    atbash:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Self-inverse. No key needed.</p>',
    beaufort:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="bK" value="SECRET" style="width:200px"><p style="margin-top:6px;font-size:.7rem;color:var(--dim)">Self-inverse.</p>',
    porta:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="pK" value="SECRET" style="width:200px">',
    columnar:'<div class="lbl" style="margin-top:12px">KEYWORD</div><input type="text" id="clK" value="ZEBRA" style="width:200px">',
    rot47:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Self-inverse. All printable ASCII rotated by 47.</p>',
    xor:'<div class="lbl" style="margin-top:12px">MODE</div><div class="row"><button class="bs on" id="xm1" onclick="xorMode=\'single\';this.classList.add(\'on\');$$(\'xm2\').classList.remove(\'on\');$$(\'xkDiv\').innerHTML=\'<div class=lbl>KEY BYTE (0-255)</div><input type=number id=xK value=42 min=0 max=255 style=width:100px>\'">SINGLE BYTE</button><button class="bs" id="xm2" onclick="xorMode=\'repeat\';this.classList.add(\'on\');$$(\'xm1\').classList.remove(\'on\');$$(\'xkDiv\').innerHTML=\'<div class=lbl>KEY STRING</div><input type=text id=xRK value=SECRET style=width:200px>\'">REPEATING KEY</button></div><div id="xkDiv"><div class="lbl">KEY BYTE (0-255)</div><input type="number" id="xK" value="42" min="0" max="255" style="width:100px"></div>',
    rc4:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="rcK" value="AB" style="width:200px"><p style="margin-top:6px;font-size:.7rem;color:var(--dim)">Short keys are brute-forceable.</p>',
    enigma:'<div class="lbl" style="margin-top:12px">START POSITIONS (0-25)</div><div class="row"><input type="number" id="eP1" value="0" min="0" max="25" style="width:60px"><input type="number" id="eP2" value="0" min="0" max="25" style="width:60px"><input type="number" id="eP3" value="0" min="0" max="25" style="width:60px"></div>',
    binary:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Converts each character to its 8-bit binary representation.</p>',
    hex:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Converts each character to 2-digit hexadecimal.</p>',
    base64:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Standard Base64 encoding (RFC 4648).</p>',
    morse:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">International Morse Code. Letters only (A-Z, 0-9).</p>',
    octal:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Converts each character to a 3-digit octal number.</p>',
    decimal:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Converts each character to its decimal ASCII code.</p>',
    url:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Percent-encodes special characters (%20 for space, etc.).</p>',
    bacon:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Francis Bacon\'s 5-bit binary cipher (1605). Letters become sequences of A and B.</p>',
    multi_layer:'<div class="lbl" style="margin-top:12px">LAYERS</div><p style="font-size:.72rem;color:var(--dim)">Applies 2-3 random encoding layers (hex + base64). Each run produces a different result.</p>',
    rot13:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Caesar shift-13. Self-inverse. The internet\'s favorite "encryption."</p>',
    affine:'<div class="lbl" style="margin-top:12px">a (coprime to 26)</div><input type="number" id="afA" value="5" min="1" max="25" style="width:80px"><div class="lbl">b (0-25)</div><input type="number" id="afB" value="8" min="0" max="25" style="width:80px">',
    rail_fence:'<div class="lbl" style="margin-top:12px">RAILS</div><input type="number" id="rfR" value="3" min="2" max="20" style="width:80px">',
    playfair:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="pfK" value="CIPHER" style="width:200px">',
    vigenere_autokey:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="akK" value="SECRET" style="width:200px">',
    reverse:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Reverses the text character by character. Self-inverse.</p>',
    scytale:'<div class="lbl" style="margin-top:12px">DIAMETER (columns)</div><input type="number" id="scD" value="5" min="2" max="20" style="width:80px">',
    route_cipher:'<div class="lbl" style="margin-top:12px">COLUMNS</div><input type="number" id="rtC" value="5" min="2" max="20" style="width:80px">',
    bifid:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="biK" value="CIPHER" style="width:200px">',
    substitution:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Random alphabet permutation. 26! possible keys.</p>',
    word_sub:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Replaces content words with random NATO/military terms.</p>',
    hex_shuffle:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Hex-encodes then shuffles byte pairs randomly.</p>',
    base32:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">RFC 4648. Uses A-Z, 2-7, and = padding. Case-insensitive.</p>',
    base58:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Bitcoin alphabet. No 0/O/I/l to avoid visual confusion.</p>',
    ascii85:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Base85 encoding in &lt;~ ~&gt; wrapper. Higher density than Base64.</p>',
    a1z26:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">A=1, B=2, ..., Z=26. Space-separated numbers.</p>',
    html_entities:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Each character as &amp;#CODE; numeric entity.</p>',
    polybius:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">5×5 grid: each letter becomes a two-digit coordinate (11-55).</p>',
    adfgvx:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">6×6 grid using only letters A, D, F, G, V, X.</p>',
    tap_code:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Prison cipher. Each letter as row.column (1.1 to 5.5).</p>',
    phone_keypad:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">ABC=2, DEF=3, GHI=4... Lossy (one-way).</p>',
    nato_phonetic:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Alpha Bravo Charlie... NATO/ICAO phonetic alphabet.</p>',
    uuencode:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Legacy Unix encoding with begin/end markers.</p>',
  };$('cOpts').innerHTML=m[c]||'';}

function doEnc(){
  const t=$('eIn').value.trim();if(!t)return;const o=$('eOut');let ct;
  try{const v=id=>{const e=$(id);return e?e.value:''};
    if(curC==='caesar')ct=Caesar.encrypt(t,+(v('cS'))||3);
    else if(curC==='vigenere')ct=Vigenere.encrypt(t,v('vK')||'KEY');
    else if(curC==='atbash')ct=Atbash.transform(t);
    else if(curC==='beaufort')ct=Beaufort.encrypt(t,v('bK')||'KEY');
    else if(curC==='porta')ct=Porta.encrypt(t,v('pK')||'KEY');
    else if(curC==='columnar')ct=Columnar.encrypt(t.toUpperCase().replace(/[^A-Z]/g,''),v('clK')||'ZEBRA');
    else if(curC==='rot47')ct=ROT47.transform(t);
    else if(curC==='xor'){if(xorMode==='single')ct=btoa(XorCipher.encryptSingle(t,+(v('xK'))||42));else ct=btoa(XorCipher.encryptRepeating(t,v('xRK')||'SECRET'));}
    else if(curC==='rc4')ct=btoa(RC4.encrypt(t,v('rcK')||'AB'));
    else if(curC==='enigma')ct=enigmaProcess(t,['III','II','I'],'B',[+(v('eP1'))||0,+(v('eP2'))||0,+(v('eP3'))||0]);
    else if(curC==='binary')ct=Encoders.binary.encode(t);
    else if(curC==='hex')ct=Encoders.hex.encode(t);
    else if(curC==='base64')ct=Encoders.base64.encode(t);
    else if(curC==='morse')ct=Encoders.morse.encode(t);
    else if(curC==='octal')ct=Encoders.octal.encode(t);
    else if(curC==='decimal')ct=Encoders.decimal.encode(t);
    else if(curC==='url')ct=Encoders.url.encode(t);
    else if(curC==='bacon')ct=Encoders.bacon.encode(t);
    else if(curC==='multi_layer'){const r=Encoders.multi.encode(t);ct=r.encoded+'\n\n[Layers: '+r.layers.join(' → ')+']';}
    // ── New types ──
    else if(curC==='rot13')ct=ROT13_cipher.encrypt(t);
    else if(curC==='affine')ct=affineEnc(t,+(v('afA'))||5,+(v('afB'))||8);
    else if(curC==='rail_fence')ct=railEnc(t,+(v('rfR'))||3);
    else if(curC==='playfair')ct=Playfair.encrypt(t,v('pfK')||'CIPHER');
    else if(curC==='vigenere_autokey')ct=VigenereAutokey.encrypt(t,v('akK')||'SECRET');
    else if(curC==='reverse')ct=ReverseText.encrypt(t);
    else if(curC==='scytale')ct=Scytale.encrypt(t,+(v('scD'))||5);
    else if(curC==='route_cipher')ct=RouteCipher.encrypt(t,+(v('rtC'))||5);
    else if(curC==='bifid')ct=Bifid.encrypt(t,v('biK')||'CIPHER');
    else if(curC==='substitution')ct=applySub(t,genSubKey(()=>Math.floor(Math.random()*1e9)));
    else if(curC==='word_sub')ct=WordSub.encrypt(t,Math.floor(Math.random()*1e9));
    else if(curC==='hex_shuffle')ct=HexShuffle.encrypt(t,Math.floor(Math.random()*1e9));
    else if(curC==='base32')ct=Base32.encode(t);
    else if(curC==='base58')ct=Base58.encode(t);
    else if(curC==='ascii85')ct=Ascii85.encode(t);
    else if(curC==='a1z26')ct=A1Z26.encode(t);
    else if(curC==='html_entities')ct=HTMLEntities.encode(t);
    else if(curC==='polybius')ct=PolybiusSquare.encode(t);
    else if(curC==='adfgvx')ct=ADFGVX.encode(t);
    else if(curC==='tap_code')ct=TapCode.encode(t);
    else if(curC==='phone_keypad')ct=PhoneKeypad.encode(t);
    else if(curC==='nato_phonetic')ct=NATOPhonetic.encode(t);
    else if(curC==='uuencode')ct=UUEncode.encode(t);
    // Show result with "Send to Decrypt" button
    // 5B: Silently capture this encrypt output for training
    const captureType=curC;const captureCt=ct.split('\n')[0]; // strip multi-layer annotation
    if(captureType!=='multi_layer')captureEncrypt(captureCt,captureType);
    else{const rawCt=captureCt;captureEncrypt(rawCt,'multi_layer');}
    o.innerHTML=`<div class="rb"><div class="rl">CIPHERTEXT</div><div class="rv">${H(ct)}</div><button class="bs" style="margin-top:12px" onclick="$('dIn').value='${H(ct).replace(/'/g,"\\'")}';go('dec',document.querySelectorAll('.nb')[0])">SEND TO DECRYPT →</button></div>`;
  }catch(e){o.innerHTML=`<div class="rb err"><div class="rl">ERROR</div><div class="rv">${H(e.message)}</div></div>`}}

// Knowledge Base
function renderKB(){
  loadKB();const entries=Object.entries(KB);
  $('kbG').innerHTML=entries.map(([k,e])=>{
    const rate=e.stats?.tested?((e.stats.cracked/e.stats.tested)*100).toFixed(0)+'%':'—';
    return`<div class="kc" onclick="showKB('${k}')"><div class="kn">${H(e.name)}</div><div class="kcat">${H((e.cat||'').replace(/_/g,' '))}</div><div class="kst">Eval tests: ${e.stats?.tested||0} &nbsp; Classified: ${rate} &nbsp; IC: ${e.icMean||'—'}</div></div>`}).join('');
  syncAllStats();
}
function showKB(key){
  const e=KB[key];if(!e)return;const d=$('kbDet');
  let h=`<div class="kd"><h3>${H(e.name)}</h3><span class="badge">${H((e.cat||'').replace(/_/g,' '))}</span>`;
  const secs=[['DESCRIPTION',e.desc],['HOW TO ENCRYPT',e.enc],['HOW TO DECRYPT / CRACK',e.dec],
    ['KNOWN WEAKNESSES',Array.isArray(e.weakness)?e.weakness.join(' • '):e.weakness],
    ['HISTORICAL CONTEXT',e.hist],['LEARNED INSIGHTS',e.insights]];
  for(const[t,b]of secs)if(b)h+=`<div class="ks"><div class="kst2">${t}</div><div class="ksb">${H(b)}</div></div>`;
  if(e.stats?.tested>0){const r=((e.stats.cracked/e.stats.tested)*100).toFixed(1);
    h+=`<div class="ks"><div class="kst2">EMPIRICAL STATS</div><div class="g3" style="margin-top:8px">`;
    h+=`<div class="sc"><div class="sn" style="font-size:1.2rem">${e.stats.tested}</div><div class="sl">EVAL TESTS</div></div>`;
    h+=`<div class="sc bl"><div class="sn" style="font-size:1.2rem">${r}%</div><div class="sl">CLASSIFICATION RATE</div></div>`;
    h+=`<div class="sc or"><div class="sn" style="font-size:1.2rem">${e.entMean||'—'}</div><div class="sl">AVG ENTROPY</div></div>`;
    h+=`</div></div>`;}
  if(e.icMean){h+=`<div class="ks"><div class="kst2">OBSERVED STATISTICS</div><div class="fg" id="kbStatFG">`;
    if(e.icMean)h+=renderFI('ic',e.icMean,'kbStatFG');
    if(e.icRange)h+=`<div class="fi" onclick="toggleFITip(this,'icRange',0,'kbStatFG')"><span class="fname">IC Range</span><span class="fval">[${e.icRange.join(', ')}]</span></div>`;
    if(e.icStd)h+=`<div class="fi" onclick="toggleFITip(this,'freqStd',${e.icStd},'kbStatFG')"><span class="fname">IC Std</span><span class="fval">${e.icStd}</span></div>`;
    if(e.entMean)h+=renderFI('entropy',e.entMean,'kbStatFG');
    h+=`</div><p style="font-family:var(--mono);font-size:.58rem;color:var(--dim);margin-top:6px">Click any stat for explanation</p></div>`;}
  if(e.discoveries?.length){h+=`<div class="ks"><div class="kst2">DISCOVERY LOG</div><div style="font-family:var(--mono);font-size:.68rem;color:var(--dim);line-height:1.8">`;
    e.discoveries.slice(-10).forEach(d=>h+=d+'<br>');h+=`</div></div>`;}
  h+=`<button class="bs" style="margin-top:16px" onclick="$('kbDet').innerHTML=''">CLOSE</button></div>`;
  d.innerHTML=h;d.scrollIntoView({behavior:'smooth',block:'start'});
}

// ML Model page
function renderML(){
  syncAllStats();
  // OOB accuracy
  if(mlModel.trained&&mlModel.oobAccuracy){
    if($('mlOOB'))$('mlOOB').textContent=(mlModel.oobAccuracy*100).toFixed(1)+'%';
  }
  // Feature importances
  if(mlModel.trained&&Object.keys(mlModel.importances).length){
    const FNAMES=['ic','chi²','freqCorr','entropy','normEnt','distinct','maxFreq','minFreq','freqStd',
      'bigramDiv','commonBi','commonTri','repTri','bigramEnt','trigramEnt','quadHitRate','quadScore','longestRepeat','uniqueBiRatio','hapaxBiRatio','bigramSkew','maxConCluster','vcTransRate',
      'ic_kl2','ic_kl3','ic_kl4','ic_kl5','ic_kl6','ic_kl7','ic_kl8','ic_kl9','ic_kl10','ic_kl11','maxIC','bestKL','icVariance','friedmanKL',
      'ac1','ac2','ac3','ac4','ac5','ac6','ac7','ac8','acPeakRatio','acArgmax',
      'vowels','spaces','upper','logLen','dev_e','dev_t','dev_a','dev_o','devSum','freqKurtosis','charClassTrans','sepRegularity','wordLenMean','wordLenStd',
      'byteEnt','printable','control','highByte','nulls','byteStd','distinctByte','spaceRatio','digitRatio','punctRatio','byteBigramEnt','byteDeltaStd','byteDeltaMean','rlCompRatio','byteChiNorm','byteSkew','byteKurtosis','upperByte','lowerByte','mixedCase',
      'firstByte','lastByte','trailingEq','firstIsPct','firstIsDigit','qEnt1','qEnt2','qEnt3','qEnt4','qEntStd','qEntRange','halfByteEnt1','halfByteEnt2','halfByteEntDiff','byteMono','maxRunRatio','byteRange','byteMedian','byteIQR',
      'lenMod2','lenMod3','lenMod4','lenMod5','lenMod8','lenMod6','isAlpha','isHex','isBinary','isBase64','isBacon','isOctal','encPreCheck','rawLenSig','logRawLen','alphaRatio','digitTotal','symbolDensity','pctCharRatio','plusSlashRatio','dotDashRatio','newlineRatio','hexDigitRatio','evenOddDiff','repeatPeriod','uniqueWordRatio','isPrintableOnly','bitsPerChar'];
    // New features F62-F94
    FNAMES.push();
    const sorted=Object.entries(mlModel.importances).sort((a,b)=>b[1]-a[1]).slice(0,15);
    $('mlImp').innerHTML=sorted.map(([k,v])=>{
      const name=FNAMES[+k]||`feat_${k}`;const pct=(v*100).toFixed(0);
      const color=v>.6?'var(--accent)':v>.3?'var(--blue)':'var(--dim)';
      return`<div class="bar-r"><div class="bar-l">${name}</div><div class="bar-t"><div class="bar-f" style="width:${pct}%;background:${color}"></div></div><div class="bar-p">${(v*100).toFixed(1)}%</div></div>`;
    }).join('');
  }
  // Accuracy history
  const history=AccuracyHistory.load();
  if(history.length&&$('mlHistory')){
    $('mlHistory').innerHTML=history.slice(-15).map((h,i)=>{
      const pct=(h.accuracy*100).toFixed(1);const color=h.accuracy>.8?'var(--accent)':h.accuracy>.5?'var(--orange)':'var(--red)';
      const date=new Date(h.timestamp).toLocaleDateString();
      return`<div class="bar-r"><div class="bar-l" style="min-width:130px">${date} #${h.iteration}</div><div class="bar-t"><div class="bar-f" style="width:${pct}%;background:${color}"></div></div><div class="bar-p">${pct}%</div></div>`;
    }).join('');
  }
  // Top confusion pairs
  const confPairs=ConfusionTracker.getConfusedPairs(2);
  if(confPairs.length&&$('mlConfusion')){
    $('mlConfusion').innerHTML=confPairs.slice(0,10).map(p=>{
      const pct=(p.rate*100).toFixed(0);const color=p.rate>.3?'var(--red)':p.rate>.15?'var(--orange)':'var(--dim)';
      return`<div class="bar-r"><div class="bar-l" style="min-width:160px">${p.actual} → ${p.predicted}</div><div class="bar-t"><div class="bar-f" style="width:${pct}%;background:${color}"></div></div><div class="bar-p">${p.count}× (${pct}%)</div></div>`;
    }).join('');
  }
  // Calibration
  const cal=CalibrationTracker.getCalibration();
  if(cal.length&&$('mlCalibration')){
    $('mlCalibration').innerHTML=cal.filter(c=>c.total>=3).map(c=>{
      const expected=(c.confidence*100).toFixed(0);const actual=(c.accuracy*100).toFixed(0);
      const gap=Math.abs(c.accuracy-c.confidence);
      const color=gap<.1?'var(--accent)':gap<.2?'var(--orange)':'var(--red)';
      return`<div class="bar-r"><div class="bar-l" style="min-width:80px">${expected}% conf</div><div class="bar-t"><div class="bar-f" style="width:${actual}%;background:${color}"></div></div><div class="bar-p">${actual}% actual (n=${c.total})</div></div>`;
    }).join('');
  }
  // DataStore stats (async)
  DataStore.getStats().then(dsStats=>{
    if($('mlStore'))$('mlStore').textContent=dsStats.total.toLocaleString();
  });
  DataStore.getUserCount().then(n=>{
    if($('mlUserSamples'))$('mlUserSamples').textContent=n.toLocaleString();
  });
  // 3A: Centroid profiles
  const profiles=CentroidStore.getAllProfiles();
  if(Object.keys(profiles).length&&$('mlCentroids')){
    const entries=Object.entries(profiles).filter(([,p])=>p&&p.count>=10).sort((a,b)=>b[1].count-a[1].count);
    $('mlCentroids').innerHTML=entries.map(([type,p])=>{
      const topFeats=[];for(let i=0;i<FEATURE_COUNT;i++){if(p.std[i]>0.001)topFeats.push({i,mean:p.mean[i],std:p.std[i]});}
      topFeats.sort((a,b)=>a.std-b.std); // lowest std = most consistent feature for this type
      const stable=topFeats.slice(0,3).map(f=>`F${f.i}=${f.mean.toFixed(3)}±${f.std.toFixed(3)}`).join(', ');
      return`<div class="bar-r"><div class="bar-l" style="min-width:100px">${type}</div><div class="bar-t"><div class="bar-f" style="width:${Math.min(p.count/100,100).toFixed(0)}%;background:var(--teal)"></div></div><div class="bar-p" style="min-width:180px">${p.count.toLocaleString()} samples · ${stable}</div></div>`;
    }).join('');
  }
}

function mlCls(){
  const t=$('mlIn').value.trim();if(!t)return;const o=$('mlOut');
  if(!mlModel.trained){o.innerHTML='<div class="rb err"><div class="rl">NOT TRAINED</div><div class="rv">Run Training first.</div></div>';return;}
  const f=extractFeatures(t);const r=mlModel.predict(f);
  let h=`<div class="rb"><div class="rl">ML CLASSIFICATION</div><div style="font-family:var(--mono);font-size:.85rem;color:var(--bright);margin-bottom:8px">${r.cls} (${(r.confidence*100).toFixed(1)}%)</div>`;
  const sorted=Object.entries(r.probs).sort((a,b)=>b[1]-a[1]);const mx=sorted[0]?.[1]||1;
  for(const[k,v]of sorted){h+=`<div class="bar-r"><div class="bar-l">${k}</div><div class="bar-t"><div class="bar-f" style="width:${(v/mx*100).toFixed(0)}%;background:${k===r.cls?'var(--accent)':'var(--blue)'}"></div></div><div class="bar-p">${(v*100).toFixed(1)}%</div></div>`;}
  h+=`</div>`;o.innerHTML=h;
}

function mlFeat(){
  const t=$('mlFIn').value.trim();if(!t)return;const f=extractFeatures(t);const o=$('mlFOut');
  const names=['ic','chi²','freqCorr','entropy','normEnt','distinct','maxFreq','minFreq','freqStd',
    'bigramDiv','commonBi','commonTri','repTri','bigramEnt','trigramEnt','quadHitRate','quadScore','longestRepeat','uniqueBiRatio','hapaxBiRatio','bigramSkew','maxConCluster','vcTransRate',
    'ic_kl2','ic_kl3','ic_kl4','ic_kl5','ic_kl6','ic_kl7','ic_kl8','ic_kl9','ic_kl10','ic_kl11','maxIC','bestKL','icVariance','friedmanKL',
    'ac1','ac2','ac3','ac4','ac5','ac6','ac7','ac8','acPeakRatio','acArgmax',
    'vowels','spaces','upper','logLen','dev_e','dev_t','dev_a','dev_o','devSum','freqKurtosis','charClassTrans','sepRegularity','wordLenMean','wordLenStd',
    'byteEnt','printable','control','highByte','nulls','byteStd','distinctByte','spaceRatio','digitRatio','punctRatio','byteBigramEnt','byteDeltaStd','byteDeltaMean','rlCompRatio','byteChiNorm','byteSkew','byteKurtosis','upperByte','lowerByte','mixedCase',
    'firstByte','lastByte','trailingEq','firstIsPct','firstIsDigit','qEnt1','qEnt2','qEnt3','qEnt4','qEntStd','qEntRange','halfByteEnt1','halfByteEnt2','halfByteEntDiff','byteMono','maxRunRatio','byteRange','byteMedian','byteIQR',
    'lenMod2','lenMod3','lenMod4','lenMod5','lenMod8','lenMod6','isAlpha','isHex','isBinary','isBase64','isBacon','isOctal','encPreCheck','rawLenSig','logRawLen','alphaRatio','digitTotal','symbolDensity','pctCharRatio','plusSlashRatio','dotDashRatio','newlineRatio','hexDigitRatio','evenOddDiff','repeatPeriod','uniqueWordRatio','isPrintableOnly','bitsPerChar'];
  let h='<div class="fg" id="mlFeatGrid">';
  for(let i=0;i<Math.min(names.length,f.length);i++)h+=renderFI(names[i],f[i],'mlFeatGrid');
  h+='</div><p style="font-family:var(--mono);font-size:.58rem;color:var(--dim);margin-top:10px">Click any feature for explanation</p>';
  o.innerHTML=h;
}

// Model export/import
function exportModel(){
  if(!mlModel.trained){alert('Train the model first.');return;}
  const blob=new Blob([mlModel.save()],{type:'application/json'});
  const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='cipherlab_model.json';a.click();
}
function importModel(input){
  const file=input.files[0];if(!file)return;
  const reader=new FileReader();reader.onload=e=>{
    try{mlModel.load(e.target.result);ModelStore.save(mlModel);renderML();alert('Model imported!');}
    catch(err){alert('Invalid model file.');}};
  reader.readAsText(file);
}

// 5A: User correction — called when user clicks "Correct this" on decrypt page
const ALL_TYPES=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','word_sub','hex_shuffle'];
function correctPrediction(text){
  const sel=$('corrType');if(!sel)return;
  const correctType=sel.value;
  if(!correctType){alert('Select the correct type first.');return;}
  DataStore.saveCorrection(text,correctType).then(()=>{
    $('corrStatus').innerHTML='<span style="color:var(--accent)">✓ Saved! This correction will be used in future training (weighted 3x).</span>';
    // Also update centroid immediately
    const feats=extractFeatures(text);
    CentroidStore.update(correctType,feats);
    CentroidStore.save();
  });
}

// 5B: Silently capture encrypt-page outputs for training
function captureEncrypt(ciphertext,type){
  if(ciphertext&&type&&ciphertext.length>=8){
    DataStore.saveEncryptCapture(ciphertext,type).then(()=>{
      console.log('Captured encrypt output: '+type+' ('+ciphertext.length+' chars)');
    });
  }
}

// Init
syncAllStats();renderKB();renderML();

