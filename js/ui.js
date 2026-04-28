/**
 * CipherLab - User Interface Module
 * 
 * This module handles all user interface interactions including the training system,
 * decryption pipeline, knowledge base display, and machine learning visualizations.
 * It coordinates between the ML model, cipher implementations, and storage systems
 * to provide a cohesive user experience.
 * 
 * Dependencies: ciphers.js, encoders.js, ml.js, kb.js, crackers.js
 */

// Utility functions for DOM manipulation and HTML escaping

const $=id=>document.getElementById(id);
const $$=id=>document.getElementById(id);
const H=s=>s?String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'):'';

function go(id,btn){
  document.querySelectorAll('.pg').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.nb').forEach(b=>b.classList.remove('on'));
  $('pg-'+id).classList.add('on');btn.classList.add('on');
  if(typeof KB!=='undefined')syncAllStats();
  if(id==='kb')renderKB();if(id==='ml')renderML();
  if(id==='enc')selC(curC);
}

// ═══════════════════════════════════════════════════════════════════════
// Procedural text generator: creates unique plaintext samples
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
//  TRAINING ENGINE: Web Worker for non-blocking training
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
    case'hex_shuffle':return HexShuffle.encrypt(text,Math.floor(Math.random()*1e9));
    default:return text;
  }
}

// Build a Web Worker: tries the dedicated worker.js first (multi-file mode),
// then falls back to building one from inline script tags (CipherLab.html).
// Returns a Promise that resolves to the worker or null.
async function createTrainWorker(){
  // Try worker.js first. new Worker() always succeeds so errors only come
  // back via onerror. We use a two-stage handshake:
  //   1. worker.js posts {type:'ready', status:'loading'} immediately on start
  //   2. worker.js posts {type:'ready', status:'loaded'} after importScripts completes
  // If we get 'loading' within 2s we know the file resolved; we then wait
  // up to 10s for 'loaded'. If importScripts fails, the worker posts {type:'error'}.
  const result = await new Promise(resolve => {
    let done = false;
    let gotLoading = false;
    let w;
    try { w = new Worker('js/worker.js'); } catch(e) { console.error('[Worker] constructor threw:', e); resolve(null); return; }
    console.log('[Worker] new Worker() succeeded, waiting for ready/loading...');

    // Outer timeout: 2s to receive the first 'ready/loading' ping
    let loadingTimer = setTimeout(() => {
      if(!done && !gotLoading){
        done=true;
        console.warn('[Worker] no response in 2s — worker.js may not be reachable or crashed before first postMessage');
        w.terminate(); resolve(null);
      }
    }, 2000);

    // Inner timeout: after 'loading', wait up to 10s for importScripts to finish
    let loadedTimer = null;

    w.onmessage = (e) => {
      if(done) return;
      console.log('[Worker] message received:', e.data);
      const msg = e.data;
      if(msg.type === 'ready' && msg.status === 'loading'){
        gotLoading = true;
        clearTimeout(loadingTimer);
        console.log('[Worker] got loading ping — waiting for importScripts...');
        loadedTimer = setTimeout(() => {
          if(!done){ done=true; console.warn('[Worker] importScripts timed out after 10s'); w.terminate(); resolve(null); }
        }, 10000);
      } else if(msg.type === 'ready' && msg.status === 'loaded'){
        done=true; clearTimeout(loadedTimer);
        console.log('[Worker] fully loaded — handing off to startTrain');
        resolve(w);
      } else if(msg.type === 'error'){
        done=true; clearTimeout(loadedTimer);
        console.error('[Worker] worker.js reported error:', msg.msg);
        w.terminate(); resolve(null);
      }
    };
    w.onerror = (e) => {
      if(!done){
        done=true; clearTimeout(loadingTimer); clearTimeout(loadedTimer);
        console.error('[Worker] onerror event — filename:', e.filename, 'line:', e.lineno, 'col:', e.colno, 'message:', e.message, 'full event:', e);
        w.terminate(); resolve(null);
      }
    };
  });

  if(result) return result;

  // Inline fallback: grab script tag contents from the DOM (CipherLab.html only)
  const scriptTags=[...document.querySelectorAll('script')];
  let ciphersCode='',encodersCode='',mlCode='';
  for(const s of scriptTags){
    const txt=s.textContent||'';
    if(!ciphersCode&&txt.includes('const ENGLISH_FREQ=')&&txt.includes('Caesar=')&&!txt.includes('createTrainWorker'))ciphersCode=txt;
    else if(!encodersCode&&txt.includes('const Encoders=')&&txt.includes('detectEncoding')&&!txt.includes('createTrainWorker'))encodersCode=txt;
    else if(!mlCode&&txt.includes('const FEATURE_COUNT')&&txt.includes('extractFeatures')&&!txt.includes('createTrainWorker'))mlCode=txt;
  }

  // If we couldn't find inline scripts, give up and use main-thread fallback
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
    const types=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','hex_shuffle'];

    for(let iter=1;iter<=maxIter&&!abort;iter++){
      self.postMessage({type:'log',msg:'── Iteration '+iter+(continuous?' (continuous)':'/'+maxIter)+' ──'});
      self.postMessage({type:'progress',iter:iter,phase:'generating'});

      // Phase 1: Generate fresh samples — all types get the same count to keep
      // training balanced. Double-sampling confused types skewed the model.
      const freshX=[],freshY=[],freshTexts=[];
      for(const type of types){
        for(let i=0;i<sampPerType;i++){
          try{
            const isShort=i>=sampPerType*0.8;
            const ct=genSample(type,isShort);
            if(ct&&ct.length>=8){const f=extractFeatures(ct);if(!f.some(isNaN)){freshX.push(f);freshY.push(type);freshTexts.push(ct);}}
          }catch(e){}
        }
        if(abort)break;
      }
      if(abort)break;
      self.postMessage({type:'log',msg:'[data] Generated '+freshX.length+' fresh samples'+(missX.length?' + '+missX.length+' misclassified reinforcement':'')});

      // Phase 2: Train on fresh samples + misclassified reinforcement
      self.postMessage({type:'progress',iter:iter,phase:'training'});
      const trainX=[...freshX,...missX];const trainY=[...freshY,...missY];
      model.train(trainX,trainY,20,12,3);
      self.postMessage({type:'log',msg:'[ml] Trained on '+trainX.length+' samples (20 trees, depth 12), OOB: '+(model.oobAccuracy*100).toFixed(1)+'%'});
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
    w._source='blob';
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
  const sampPerType=baseSampPerType;
  const types=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','hex_shuffle'];
  const log=[];
  function addLog(msg,ok=true){log.push({msg,ok});if(log.length>500)log.splice(0,log.length-500);
    $('tLog').innerHTML=log.map(l=>`<div class="${l.ok?'lok':'lfail'}">${H(l.msg)}</div>`).join('');$('tLog').scrollTop=$('tLog').scrollHeight;}

  if(continuous)addLog('═══ CONTINUOUS MODE — will run until you click STOP ═══');

  // Load previously misclassified samples for training reinforcement
  addLog('[store] Loading misclassified samples from previous sessions...');
  const missData=await SampleDB.loadMisclassified(200);
  if(missData.count>0)addLog(`[store] Loaded ${missData.count} previously misclassified samples (up to 200/type)`);
  else addLog('[store] No misclassified samples stored yet');

  // Try Web Worker
  const worker=await createTrainWorker();
  if(worker){
    addLog('Training in Web Worker — UI stays responsive');
    trainWorker=worker;

    // Wire up onmessage BEFORE sending the train command so we don't miss any messages
    worker.onmessage=async function(e){
      const msg=e.data;
      if(msg.type==='ready')return; // handshake messages — ignore after startup
      if(msg.type==='error'){addLog('[Worker] '+msg.msg,false);return;}
      if(msg.type==='log')addLog(msg.msg,msg.ok!==false);
      else if(msg.type==='progress'){
        $('tsS').textContent=continuous?'RUNNING ∞ [Worker]':'RUNNING [Worker]';$('tsS').style.color='var(--accent)';
        $('tsI').textContent=msg.iter;
        // Move the bar forward in thirds within each iteration based on current phase
        const phaseOffset={generating:0,training:0.33,evaluating:0.66}[msg.phase]||0;
        if(!continuous)$('tBar').style.width=((msg.iter-1)/maxIter*100+(phaseOffset/maxIter*100))+'%';
        else $('tBar').style.width=(((msg.iter%20)/20+phaseOffset/20)*100)+'%';
      }
      else if(msg.type==='model'){
        // Don't accept yet. Wait for eval to compare against champion
        // Store challenger JSON temporarily
        trainWorker._pendingModel=msg.json;
      }
      else if(msg.type==='samples'){
        // Save fresh samples to IndexedDB and update centroids
        const X=msg.X.map(a=>new Float64Array(a));
        await DataStore.saveWithTexts(X,msg.Y,msg.texts,{iteration:msg.iter});
        // Update centroids
        const byType={};for(let i=0;i<X.length;i++){if(!byType[msg.Y[i]])byType[msg.Y[i]]=[];byType[msg.Y[i]].push(X[i]);}
        for(const type in byType)CentroidStore.updateBatch(type,byType[type]);
        await CentroidStore.save();
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
          if(msg.challengerJson){mlModel.load(msg.challengerJson);await ModelStore.save(mlModel);}
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

          // Decisive threshold: if challenger beats champion by >= 3 percentage
          // points, do a full replacement then backfill the best old champion
          // trees back in. Otherwise do the conservative selective tree merge.
          const DECISIVE_THRESHOLD=0.03;
          if(challengerAcc>championAcc+DECISIVE_THRESHOLD){
            const result=mlModel.replaceWithBestOf(challenger,testX,testY,30);
            if(result.replaced){
              await ModelStore.save(mlModel);
              addLog(`[replace] ▲ Decisive win — replaced champion with challenger (${(challengerAcc*100).toFixed(1)}% vs ${(championAcc*100).toFixed(1)}%)`);
              addLog(`[replace] Backfilled ${result.backfilled} old champion trees — final: ${(result.afterAcc*100).toFixed(1)}% (${result.totalTrees} trees)`);
            }else{
              addLog(`[replace] ▬ Replacement skipped: ${result.reason}`,false);
            }
          }else{
            const result=mlModel.mergeFrom(challenger,testX,testY,5,30);
            if(result.merged){
              await ModelStore.save(mlModel);
              addLog(`[merge] ▲ Merged ${result.added} trees into champion (replaced ${result.removed} worst) — ${mlModel.trees.length} total trees`);
              addLog(`[merge] Champion: ${(championAcc*100).toFixed(1)}% → ${(result.newAcc*100).toFixed(1)}% | Challenger: ${(challengerAcc*100).toFixed(1)}%`);
            }else{
              addLog(`[merge] ▬ No merge: ${result.reason} (champion ${(championAcc*100).toFixed(1)}% already optimal)`,false);
            }
          }
        }
        trainWorker._pendingModel=null;

        const finalAcc=mlModel.trained?(function(){let c=0;for(let i=0;i<testX.length;i++)if(mlModel.predict(testX[i]).cls===testY[i])c++;return testX.length?c/testX.length:0;})():challengerAcc;
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
        await ConfusionTracker.save();await CalibrationTracker.save();
        // Save misclassified samples to IndexedDB + UnsolvedStore
        if(misclassified.length>0){
          const toSave=misclassified.slice(0,500);
          SampleDB.saveMisclassifiedBatch(toSave).then(()=>{
            addLog(`[store] Saved ${toSave.length} misclassified samples for future training`);
          });
          // Add to unsolved store (persistent JSON, up to 100K)
          await UnsolvedStore.addUnsolved(toSave);
          const uStats=await UnsolvedStore.getStats();
          addLog(`[unsolved] Added ${toSave.length} unsolved samples (${uStats.unsolved.toLocaleString()} unsolved, ${uStats.solved.toLocaleString()} solved total)`);
        }
        // Test unsolved samples against the current champion — mark solved if model now gets them right
        if(mlModel.trained){
          const solveResult=await UnsolvedStore.testAndSolve(mlModel);
          if(solveResult.solved>0){
            addLog(`[unsolved] ★ SOLVED ${solveResult.solved}/${solveResult.tested} previously unsolved samples! (${solveResult.remaining.toLocaleString()} remaining)`);
            const solvedTypes={};
            for(const s of solveResult.solvedSamples){solvedTypes[s.actual]=(solvedTypes[s.actual]||0)+1;}
            const solvedList=Object.entries(solvedTypes).sort((a,b)=>b[1]-a[1]).slice(0,5);
            if(solvedList.length)addLog(`[unsolved] Solved types: ${solvedList.map(([t,n])=>t+':'+n).join(', ')}`);
          }
          await UnsolvedStore.save();
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
        renderKB(); // refresh KB grid so IC values update live during training
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
      const detail=e.filename?` (${e.filename.split('/').pop()} line ${e.lineno})`:'';

      addLog('[Worker ERROR] '+(e.message||'unknown error')+detail,false);
      $('bStart').style.display='';$('bStop').style.display='none';$('tDot').innerHTML='';
      trainRunning=false;trainWorker=null;
    };

    // Send training command AFTER both handlers are wired which avoids dropped messages
    worker.postMessage({
      cmd:'train',
      storedX:missData.X.map(f=>Array.from(f)),
      storedY:missData.Y,
      sampPerType:sampPerType,
      maxIter:maxIter,
      continuous:continuous,
      existingModel:mlModel.trained?mlModel.save():null
    });
  } else {
    // ── FALLBACK: Main-thread training ──
    addLog('[fallback] Training on main thread');
    const fallbackMiss=await SampleDB.loadMisclassified(200);
    if(fallbackMiss.count>0)addLog(`[store] Loaded ${fallbackMiss.count} misclassified samples for reinforcement`);
    for(let iter=1;iter<=maxIter&&!trainAbort;iter++){
      $('tsS').textContent=continuous?'RUNNING ∞':'RUNNING';$('tsS').style.color='var(--accent)';$('tsI').textContent=iter;
      if(!continuous)$('tBar').style.width=((iter-1)/maxIter*100)+'%';
      else $('tBar').style.width=((iter%20)/20*100)+'%';
      addLog(`── Iteration ${iter}${continuous?' (continuous)':'/'+maxIter} ──`);
      const freshX=[],freshY=[],freshTexts=[];
      for(const type of types){
        for(let i=0;i<sampPerType;i++){try{const isShort=i>=sampPerType*0.8;const ct=genSample(type,isShort);if(ct&&ct.length>=8){const f=extractFeatures(ct);if(!f.some(isNaN)){freshX.push(f);freshY.push(type);freshTexts.push(ct);}}}catch(e){}}
        await new Promise(r=>setTimeout(r,0));if(trainAbort)break;
      }
      addLog(`[data] Generated ${freshX.length} fresh samples${fallbackMiss.count?' + '+fallbackMiss.count+' misclassified reinforcement':''}`);
      const trainX=[...freshX,...fallbackMiss.X];const trainY=[...freshY,...fallbackMiss.Y];
      addLog(`[ml] Training challenger (${trainX.length} samples, ${FEATURE_COUNT} features)...`);
      await new Promise(r=>setTimeout(r,10));
      const challenger=new DecisionForest();
      // trainAsync yields between trees so the main thread doesn't freeze
      await challenger.trainAsync(trainX,trainY,20,12,3,(done,total)=>{
        if(!continuous)$('tBar').style.width=(((iter-1)/maxIter)+(done/total/maxIter))*100+'%';
      });
      if(trainAbort)break;
      addLog(`[ml] Trained on ${trainX.length} samples (20 trees, depth 12), OOB: ${(challenger.oobAccuracy*100).toFixed(1)}%`);
      await DataStore.saveWithTexts(freshX,freshY,freshTexts,{iteration:iter});
      if(trainAbort)break;
      const cbt={};for(let i=0;i<freshX.length;i++){if(!cbt[freshY[i]])cbt[freshY[i]]=[];cbt[freshY[i]].push(freshX[i]);}
      for(const t in cbt)CentroidStore.updateBatch(t,cbt[t]);await CentroidStore.save();
      // Evaluate on actual training samples
      const testX=freshX,testY=freshY;
      let challCorrect=0;for(let i=0;i<testX.length;i++){if(challenger.predict(testX[i]).cls===testY[i])challCorrect++;}
      const challAcc=testX.length?challCorrect/testX.length:0;
      // Federated merge
      if(!mlModel.trained){
        mlModel=challenger;await ModelStore.save(mlModel);
        addLog(`[champion] ▲ First model: ${(challAcc*100).toFixed(1)}%`);
      }else{
        let champCorrect=0;for(let i=0;i<testX.length;i++){if(mlModel.predict(testX[i]).cls===testY[i])champCorrect++;}
        const champAcc=testX.length?champCorrect/testX.length:0;
        const DECISIVE_THRESHOLD=0.03;
        if(challengerAcc>champAcc+DECISIVE_THRESHOLD){
          const result=mlModel.replaceWithBestOf(challenger,testX,testY,30);
          if(result.replaced){await ModelStore.save(mlModel);addLog(`[replace] ▲ Decisive win — replaced champion with challenger (${(challengerAcc*100).toFixed(1)}% vs ${(champAcc*100).toFixed(1)}%)`);addLog(`[replace] Backfilled ${result.backfilled} old champion trees — final: ${(result.afterAcc*100).toFixed(1)}% (${result.totalTrees} trees)`);}
          else addLog(`[replace] ▬ Replacement skipped: ${result.reason}`,false);
        }else{
          const result=mlModel.mergeFrom(challenger,testX,testY,5,30);
          if(result.merged){await ModelStore.save(mlModel);addLog(`[merge] ▲ Merged ${result.added} trees — ${(champAcc*100).toFixed(1)}%→${(result.newAcc*100).toFixed(1)}% (${mlModel.trees.length} trees)`);}
          else addLog(`[merge] ▬ No merge: ${result.reason}`,false);
        }
      }
      if(trainAbort)break;
      // Record confusion/calibration (batched — save once) + collect misclassified
      const byType={};const misclassified=[];
      for(let i=0;i<testX.length;i++){const pred=mlModel.predict(testX[i]);const ok=pred.cls===testY[i];
        if(!byType[testY[i]])byType[testY[i]]={c:0,t:0};byType[testY[i]].t++;if(ok)byType[testY[i]].c++;
        if(!ok)misclassified.push({features:testX[i],actual:testY[i],predicted:pred.cls});
        ConfusionTracker.recordBatch(testY[i],pred.cls);CalibrationTracker.recordBatch(pred.confidence,ok);if(KB[testY[i]]){KB[testY[i]].stats.tested++;if(ok)KB[testY[i]].stats.cracked++;KB[testY[i]].icObs.push(+testX[i][0].toFixed(5));KB[testY[i]].entObs.push(+testX[i][3].toFixed(4));if(KB[testY[i]].icObs.length>200)KB[testY[i]].icObs=KB[testY[i]].icObs.slice(-200);if(KB[testY[i]].entObs.length>200)KB[testY[i]].entObs=KB[testY[i]].entObs.slice(-200);}}
      await ConfusionTracker.save();await CalibrationTracker.save();
      if(trainAbort)break;
      if(misclassified.length>0){
        const toSave=misclassified.slice(0,500);
        SampleDB.saveMisclassifiedBatch(toSave).then(()=>addLog(`[store] Saved ${toSave.length} misclassified samples`));
        await UnsolvedStore.addUnsolved(toSave);
        const uCount=await UnsolvedStore.getUnsolvedCount();
        addLog(`[unsolved] Added ${toSave.length} unsolved (${uCount.toLocaleString()} total unsolved)`);
      }
      // Test unsolved against current model
      if(mlModel.trained){
        const solveResult=await UnsolvedStore.testAndSolve(mlModel);
        if(solveResult.solved>0)addLog(`[unsolved] ★ SOLVED ${solveResult.solved}/${solveResult.tested} previously unsolved! (${solveResult.remaining.toLocaleString()} remaining)`);
        await UnsolvedStore.save();
      }
      let fCorrect=0;for(let i=0;i<testX.length;i++)if(mlModel.predict(testX[i]).cls===testY[i])fCorrect++;
      const finalAcc=testX.length?fCorrect/testX.length:0;
      addLog(`[eval] Active: ${(finalAcc*100).toFixed(1)}% (${mlModel.trees.length} trees)`);
      $('tsA').textContent=(finalAcc*100).toFixed(1)+'%';syncAllStats();
      $('tTypeSection').style.display='';$('tTypeAcc').innerHTML=Object.entries(byType).sort((a,b)=>(b[1].c/b[1].t)-(a[1].c/a[1].t)).map(([t,d])=>{const pct=d.t?(d.c/d.t*100):0;return`<div class="bar-r"><div class="bar-l">${t}</div><div class="bar-t"><div class="bar-f" style="width:${pct.toFixed(0)}%;background:${pct>80?'var(--accent)':pct>50?'var(--orange)':'var(--red)'}"></div></div><div class="bar-p">${pct.toFixed(0)}%</div></div>`;}).join('');
      // Compute IC/entropy means and update KB discoveries
      for(const type of types){if(KB[type]&&KB[type].icObs.length>=5){
        const ics=KB[type].icObs;const icMean=ics.reduce((a,b)=>a+b,0)/ics.length;const icStd=Math.sqrt(ics.reduce((a,v)=>a+(v-icMean)**2,0)/ics.length);
        KB[type].icMean=+icMean.toFixed(5);KB[type].icStd=+icStd.toFixed(5);KB[type].icRange=[+Math.min(...ics).toFixed(5),+Math.max(...ics).toFixed(5)];
        if(KB[type].entObs.length>=5){const ents=KB[type].entObs;KB[type].entMean=+(ents.reduce((a,b)=>a+b,0)/ents.length).toFixed(4);}
        const st=KB[type].stats;const rate=st.tested?(st.cracked/st.tested):0;
        KB[type].insights=`${(rate*100).toFixed(1)}% accuracy (${st.tested} tests). IC=${icMean.toFixed(4)}±${icStd.toFixed(4)}.`;
        if(!KB[type].discoveries)KB[type].discoveries=[];
        KB[type].discoveries.push(`Iter ${iter}: IC=${icMean.toFixed(4)}, acc=${(rate*100).toFixed(1)}%`);
        if(KB[type].discoveries.length>20)KB[type].discoveries=KB[type].discoveries.slice(-20);
      }}
      saveKB();renderKB();await new Promise(r=>setTimeout(r,0));
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
function extractKeyFromMethod(method){
  if(!method)return null;
  // Named key: key="SECRET" or key=0x41 or key=VALUE
  let m=method.match(/key=["']?([^"'\s,)]+)["']?/i);
  if(m)return{label:'Key',value:m[1]};
  // Caesar: "Caesar shift 3" (space, no equals) or "shift=3" (equals)
  m=method.match(/shift[=\s]+(\d+)/i);
  if(m)return{label:'Shift',value:m[1]};
  // Affine
  m=method.match(/a=(\d+)\s+b=(\d+)/i);
  if(m)return{label:'Key',value:'a='+m[1]+' b='+m[2]};
  // Enigma rotors [r,r,r]
  m=method.match(/\[([^\]]+)\]/);
  if(m)return{label:'Rotor positions',value:m[1]};
  // Columnar N cols (KEY)
  // Columnar / columnar key in parens — only match digits/letters, not 'hill-climb' etc.
  m=method.match(/\((\w+)\)/);
  if(m)return{label:'Key',value:m[1]};
  // Rail fence N rails
  m=method.match(/(\d+)\s+rails?/i);
  if(m)return{label:'Rails',value:m[1]};
  // Scytale width=N
  m=method.match(/width=(\d+)/i);
  if(m)return{label:'Width',value:m[1]};
  // Scytale / Route Cipher: 'Scytale cols=7' or 'Route Cipher cols=5'
  m=method.match(/cols=(\d+)/i);
  if(m)return{label:'Columns',value:m[1]};
  // Route cipher N cols
  m=method.match(/(\d+)\s+cols?/i);
  if(m)return{label:'Columns',value:m[1]};
  return null;
}

function doDec(){
  const text=$('dIn').value.trim();if(!text)return;const o=$('dOut');
  // Run ML first so its prediction can inform the pipeline's candidate ranking
  let mlResult=null;
  if($('dML').checked&&mlModel.trained){
    const f=extractFeatures(text);
    mlResult=mlModel.predict(f);
    const sorted=Object.entries(mlResult.probs).sort((a,b)=>b[1]-a[1]);
    const top=sorted[0]?.[1]||0, second=sorted[1]?.[1]||0;
    if(top-second<0.08)mlResult.lowMargin=true;
  }
  const dec=decodeInput(text, mlResult);
  const feats=extractFeatures(text);
  // Store runner-ups globally so TRY NEXT ANSWER can cycle through them.
  // First entry is the primary result, rest come from dec.runners which use {name, text, score}.
  window._decRunners=[{text:dec.decoded,name:dec.method,score:99},...(dec.runners||[])];
  window._decRunnerIdx=0;

  let h='';
  const hasRunners=dec.runners&&dec.runners.length>0;
  const keyInfo=extractKeyFromMethod(dec.method);
  if(dec.decoded!==text||dec.steps.length){
    h+=`<div class="rb" id="decOrigBlock"><div class="rl">DECODED OUTPUT`;
    h+=`<span style="float:right;display:flex;gap:6px">`;
    h+=`<button class="bs" style="font-size:.55rem;padding:3px 10px;border-color:rgba(255,159,67,.4);color:var(--orange)" onclick="decRetry()">RETRY</button>`;
    if(hasRunners)h+=`<button class="bs" style="font-size:.55rem;padding:3px 10px;border-color:rgba(0,200,150,.35);color:var(--teal)" onclick="decNextAnswer()">TRY NEXT ANSWER</button>`;
    h+=`<button class="bs" style="font-size:.55rem;padding:3px 10px" onclick="copyText(this.closest('.rb').querySelector('.rv').textContent)">COPY</button>`;
    h+=`</span></div>`;
    h+=`<div class="rv" id="decMainOut">${H(dec.decoded)}</div>`;
    if(keyInfo)h+=`<div style="font-family:var(--mono);font-size:.65rem;margin-top:6px"><span style="color:var(--dim)">${H(keyInfo.label)}:</span> <span style="color:var(--accent);font-weight:600">${H(keyInfo.value)}</span> &nbsp;<span style="color:var(--dim);font-size:.6rem">— ${H(dec.method)}</span></div>`;
    else h+=`<div style="font-family:var(--mono);font-size:.65rem;color:var(--dim);margin-top:6px">Method: ${H(dec.method)}</div>`;
    if(hasRunners)h+=`<div style="font-family:var(--mono);font-size:.6rem;color:var(--dim);margin-top:4px" id="decAnswerLabel">Answer 1 of ${dec.runners.length+1}</div>`;
    h+=`</div>`;
    h+=`<div id="decRetryBlock"></div>`;
  }
  h+=`<div class="rb blu"><div class="rl">DETECTION</div><div style="font-family:var(--mono);font-size:.75rem;color:var(--text);line-height:2">`;
  h+=`<span style="color:var(--dim);font-size:.65rem">PIPELINE (rule-based decoder):</span><br>`;
  h+=`Result: <b style="color:var(--bright)">${dec.method}</b>`;
  if(dec.encoding&&dec.encoding!=='plaintext'&&dec.encoding!=='unknown')h+=` &nbsp; Detected encoding: <b style="color:var(--bright)">${dec.encoding}</b>`;
  h+=`<br><span style="color:var(--dim);font-size:.6rem">The pipeline tries every decoder and cracker in sequence and picks the output that scores highest as English text. This is the primary result.</span><br>`;
  if(mlResult){
    h+=`<br><span style="color:var(--dim);font-size:.65rem">ML MODEL (Random Forest classifier — 20 trees, 128 features):</span><br>`;
    const MIN_CONF=0.35;
    const calConf=CalibrationTracker.getCalibratedConfidence(mlResult.confidence);
    const confToShow=Math.abs(calConf-mlResult.confidence)>0.05?calConf:mlResult.confidence;
    if(mlResult.confidence>=MIN_CONF&&!mlResult.lowMargin){
      const pipelineType=dec.method.toLowerCase().replace(/[^a-z0-9_]/g,'_').replace(/_+/g,'_');
      const mlType=mlResult.cls.toLowerCase();
      const agrees=pipelineType.includes(mlType)||mlType.includes(pipelineType.split('_')[0])||
                   (dec.encoding&&dec.encoding.toLowerCase().includes(mlType));
      const confColor=mlResult.confidence>0.7?'var(--accent)':mlResult.confidence>0.5?'var(--orange)':'var(--dim)';
      h+=`Best match: <b style="color:${confColor}">${mlResult.cls}</b> (${(confToShow*100).toFixed(1)}% confidence)`;
      if(!agrees&&mlResult.confidence>0.5)h+=` <span style="color:var(--orange);font-size:.65rem">⚠ differs from pipeline</span>`;
      h+=`<br><span style="color:var(--dim);font-size:.6rem">This confidence is calibrated — it reflects how often the model has historically been correct at this level, not just the raw tree vote. A calibrated 70% means the model gets it right about 70% of the time when this confident.</span><br>`;
      const sorted=Object.entries(mlResult.probs).sort((a,b)=>b[1]-a[1]).slice(0,5);
      h+=`<br>Other candidates: `+sorted.map(([k,v],i)=>`<span style="color:${i===0?confColor:'var(--dim)'}">${k} ${(v*100).toFixed(1)}%</span>`).join(' · ')+`<br>`;
      h+=`<span style="color:var(--dim);font-size:.6rem">Raw tree-vote probabilities — the share of total forest vote weight each cipher type received across all 20 trees. These sum to 100%. The calibrated confidence above may differ because it is adjusted for historical accuracy, while these are the unmodified model outputs.</span><br>`;
    } else {
      const reason=mlResult.lowMargin?`top candidates are too close to call`:`confidence too low (${(mlResult.confidence*100).toFixed(1)}%)`;
      h+=`<span style="color:var(--dim)">Model is uncertain — ${reason}. The pipeline result above is more reliable here.</span><br>`;
    }
    const escapedText=text.replace(/[\\]/g,'\\\\').replace(/'/g,"\\'").replace(/\n/g,'\\n');
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
  // Playfair recovered key square — show whenever the pipeline found a Playfair result
  if(dec.method&&dec.method.toLowerCase().includes('playfair')){
    // Extract key from method string, e.g. "Playfair (hill-climb)" won't have it,
    // but dec.steps may include the key in the step detail
    const pfStep=dec.steps.find(s=>s.l&&s.l.toLowerCase().includes('playfair'));
    const pfKeyStr=pfStep&&pfStep.key?pfStep.key:null;
    // Also check runners for any Playfair result with a key
    const pfRunner=(dec.runners||[]).find(r=>r.name&&r.name.toLowerCase().includes('playfair'));
    // Build display key: prefer step key, fall back to last 25 chars of a full key in method name
    const keyMatch=dec.method.match(/key=?["\s]*([A-Z]{25})/i);
    const displayKey=pfKeyStr||(keyMatch&&keyMatch[1])||null;
    if(displayKey&&displayKey.length===25){
      h+=`<div class="rb" style="border-color:rgba(0,255,136,.15)"><div class="rl">RECOVERED PLAYFAIR KEY SQUARE</div>`;
      h+=`<div style="display:grid;grid-template-columns:repeat(5,32px);gap:3px;margin-bottom:10px">`;
      for(const c of displayKey){
        h+=`<div style="width:32px;height:32px;display:flex;align-items:center;justify-content:center;`+
          `background:var(--bg3);border:1px solid var(--brd);border-radius:5px;`+
          `font-family:var(--mono);font-size:.75rem;font-weight:600;color:var(--accent)">${H(c)}</div>`;
      }
      h+=`</div>`;
      h+=`<div style="font-family:var(--mono);font-size:.62rem;color:var(--dim)">Key string: ${H(displayKey)}</div>`;
      h+=`</div>`;
    }
  }
  if(dec.steps.length){h+=`<div class="pipe"><div class="pt">PIPELINE</div>`;dec.steps.forEach((s,i)=>h+=`<div class="ps"><div class="pn">${i+1}</div><div class="pl">${H(s.l)}</div><div class="pd">${H(s.d)}</div></div>`);h+=`</div>`;}
  if(dec.runners&&dec.runners.length){h+=`<div class="pipe"><div class="pt">RUNNER-UP ATTEMPTS (${dec.runners.length})</div>`;dec.runners.forEach(r=>h+=`<div class="ps"><div class="pn">~</div><div class="pl">${H(r.name)}</div><div class="pd">score: ${r.score.toFixed(3)}</div></div>`);h+=`</div>`;}
  h+=`<div class="pipe"><div class="pt">EXTRACTED METADATA (${FEATURE_COUNT} features)</div><div class="fg" id="decFG">`;
  
  // Basic 13 features
  const fnames=['ic','chi²','freqCorr','entropy','normEnt','distinct','maxFreq','minFreq','freqStd','bigramDiv','commonBi','commonTri','repTri'];
  for(let i=0;i<13;i++)h+=renderFI(fnames[i],feats[i],'decFG');
  
  // Additional key features from original set
  h+=renderFI('byteEnt',feats[61],'decFG');
  h+=renderFI('printable',feats[62],'decFG');
  h+=renderFI('highByte',feats[64],'decFG');
  
  // All contextual features are organized by category for better understanding
  const contextualFeatures=[
    ['charClassTrans',57],['sepRegularity',58],['bigramEnt',13],['trigramEnt',14],
    ['quadHitRate',15],['longestRepeat',17],['acPeakRatio',45],['maxIC',33],['bestKL',34],
    ['isAlpha',106],['isHex',107],['isBinary',108],['isBase64',109],['isBacon',110],
    ['encPreCheck',112],['rawLenSig',113],
    ['byteBigramEnt',71],['byteDeltaStd',72],['rlCompRatio',74],['byteChiNorm',75],
    ['mixedCase',80],['trailingEq',83],['qEntStd',90],['byteMedian',98],['byteIQR',99],
    ['bitsPerChar',127]
  ];
  for(const[name,idx]of contextualFeatures)h+=renderFI(name,feats[idx],'decFG');
  
  h+=`</div><p style="font-family:var(--mono);font-size:.58rem;color:var(--dim);margin-top:10px">Click any feature for explanation · ${FEATURE_COUNT} total features extracted</p></div>`;
  o.innerHTML=h;
}

// Cycle through runner-up answers without re-running the full pipeline
function decNextAnswer(){
  if(!window._decRunners||window._decRunners.length<2)return;
  window._decRunnerIdx=(window._decRunnerIdx+1)%window._decRunners.length;
  const r=window._decRunners[window._decRunnerIdx];
  const outEl=$('decMainOut');
  const lblEl=$('decAnswerLabel');
  if(outEl)outEl.innerHTML=H(r.text||'');
  if(lblEl)lblEl.textContent=`Answer ${window._decRunnerIdx+1} of ${window._decRunners.length} — method: ${r.name||'unknown'}`;
}

function decRetry(){
  const text=$('dIn').value.trim();if(!text)return;
  const retryBlock=$('decRetryBlock');if(!retryBlock)return;
  let mlResult=null;
  if($('dML').checked&&mlModel.trained){
    const f=extractFeatures(text);
    mlResult=mlModel.predict(f);
    const sorted=Object.entries(mlResult.probs).sort((a,b)=>b[1]-a[1]);
    const top=sorted[0]?.[1]||0,second=sorted[1]?.[1]||0;
    if(top-second<0.08)mlResult.lowMargin=true;
  }
  const dec=decodeInput(text,mlResult);
  const keyInfo=extractKeyFromMethod(dec.method);
  const hasRunners=dec.runners&&dec.runners.length>0;
  const prevRetries=retryBlock.querySelectorAll('.decRetryResult').length;
  const retryNum=prevRetries+1;
  // Each retry gets a unique id so its TRY NEXT ANSWER button can target it
  const retryId=`decRetry_${retryNum}`;
  // Store runners on window keyed by retryId so decRetryNext can access them
  window._retryRunners=window._retryRunners||{};
  window._retryRunners[retryId]=[{text:dec.decoded,name:dec.method,score:99},...(dec.runners||[])];
  window._retryRunnerIdx=window._retryRunnerIdx||{};
  window._retryRunnerIdx[retryId]=0;
  let h=`<div class="rb decRetryResult" id="${retryId}" style="border-color:rgba(255,159,67,.3);margin-top:4px">`;
  h+=`<div class="rl" style="color:var(--orange)">RETRY ${retryNum} — DECODED OUTPUT`;
  h+=`<span style="float:right;display:flex;gap:6px">`;
  if(hasRunners)h+=`<button class="bs" style="font-size:.55rem;padding:3px 10px;border-color:rgba(0,200,150,.35);color:var(--teal)" onclick="decRetryNext('${retryId}')">TRY NEXT ANSWER</button>`;
  h+=`<button class="bs" style="font-size:.55rem;padding:3px 10px" onclick="copyText(this.closest('.rb').querySelector('.rv').textContent)">COPY</button>`;
  h+=`</span></div>`;
  h+=`<div class="rv" id="${retryId}_out">${H(dec.decoded)}</div>`;
  if(keyInfo)h+=`<div style="font-family:var(--mono);font-size:.65rem;margin-top:6px" id="${retryId}_key"><span style="color:var(--dim)">${H(keyInfo.label)}:</span> <span style="color:var(--accent);font-weight:600">${H(keyInfo.value)}</span> &nbsp;<span style="color:var(--dim);font-size:.6rem">— ${H(dec.method)}</span></div>`;
  else h+=`<div style="font-family:var(--mono);font-size:.65rem;color:var(--dim);margin-top:6px" id="${retryId}_key">Method: ${H(dec.method)}</div>`;
  if(hasRunners)h+=`<div style="font-family:var(--mono);font-size:.6rem;color:var(--dim);margin-top:4px" id="${retryId}_lbl">Answer 1 of ${dec.runners.length+1}</div>`;
  h+=`</div>`;
  retryBlock.insertAdjacentHTML('beforeend',h);
}

function decRetryNext(retryId){
  const runners=window._retryRunners&&window._retryRunners[retryId];
  if(!runners||runners.length<2)return;
  window._retryRunnerIdx[retryId]=(window._retryRunnerIdx[retryId]+1)%runners.length;
  const idx=window._retryRunnerIdx[retryId];
  const r=runners[idx];
  const outEl=$(retryId+'_out');
  const lblEl=$(retryId+'_lbl');
  const keyEl=$(retryId+'_key');
  if(outEl)outEl.innerHTML=H(r.text||'');
  if(lblEl)lblEl.textContent=`Answer ${idx+1} of ${runners.length} — method: ${r.name||'unknown'}`;
  if(keyEl){
    const ki=extractKeyFromMethod(r.name||'');
    if(ki)keyEl.innerHTML=`<span style="color:var(--dim)">${H(ki.label)}:</span> <span style="color:var(--accent);font-weight:600">${H(ki.value)}</span> &nbsp;<span style="color:var(--dim);font-size:.6rem">— ${H(r.name||'')}</span>`;
    else keyEl.innerHTML=`<span style="color:var(--dim)">Method: ${H(r.name||'')}</span>`;
  }
}

// Encrypt
let curC='caesar';let xorMode='single';
function selC(c,btn){curC=c;
  document.querySelectorAll('#cBtns .bs, #eBtns .bs').forEach(b=>b.classList.remove('on'));if(btn)btn.classList.add('on');
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
    playfair:`<div class="lbl" style="margin-top:12px">KEY</div>
<input type="text" id="pfK" value="CIPHER" style="width:200px;margin-bottom:8px" oninput="buildPlayfairGrid()" onchange="buildPlayfairGrid()">
<div id="pfErr" style="font-family:var(--mono);font-size:.68rem;color:var(--red);margin-bottom:6px;display:none"></div>
<div class="lbl" style="margin-top:8px;margin-bottom:6px">5×5 KEY SQUARE</div>
<div id="pfGrid" style="display:grid;grid-template-columns:repeat(5,32px);gap:3px;margin-bottom:10px"></div>
<div class="lbl" style="margin-top:4px;margin-bottom:4px">REMAINING LETTERS</div>
<div id="pfRem" style="font-family:var(--mono);font-size:.72rem;color:var(--dim);letter-spacing:2px;word-spacing:4px"></div>
<p style="margin-top:12px;font-size:.75rem;color:var(--dim);line-height:1.6">
  <span style="color:var(--orange);font-weight:600">J is treated as I.</span>
  The Playfair grid has 25 cells but the alphabet has 26 letters, so one letter must be dropped.
  By convention, J is merged with I — any J in your key or message is automatically converted to I before encryption.
  This means <span style="color:var(--bright)">JOHN</span> encrypts identically to <span style="color:var(--bright)">IOHN</span>,
  and the decrypted output will always show I where you originally typed J.
</p>`,
    vigenere_autokey:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="akK" value="SECRET" style="width:200px">',
    reverse:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Reverses the text character by character. Self-inverse.</p>',
    scytale:'<div class="lbl" style="margin-top:12px">DIAMETER (columns)</div><input type="number" id="scD" value="5" min="2" max="20" style="width:80px">',
    route_cipher:'<div class="lbl" style="margin-top:12px">COLUMNS</div><input type="number" id="rtC" value="5" min="2" max="20" style="width:80px">',
    bifid:'<div class="lbl" style="margin-top:12px">KEY</div><input type="text" id="biK" value="CIPHER" style="width:200px">',
    substitution:`<div class="lbl" style="margin-top:12px;margin-bottom:8px">SUBSTITUTION KEY — each plaintext letter maps to the output letter below it</div>
<div id="subGrid" style="display:grid;grid-template-columns:repeat(13,46px);gap:4px;margin-bottom:8px"></div>
<div id="subErr" style="font-family:var(--mono);font-size:.68rem;color:var(--red);min-height:1.2em;margin-bottom:6px"></div>
<div style="display:flex;gap:8px;margin-top:4px">
  <button onclick="buildSubGrid(true)" style="font-family:var(--mono);font-size:.7rem;padding:4px 10px;background:var(--bg3);border:1px solid var(--brd);border-radius:5px;color:var(--dim);cursor:pointer">Randomize</button>
  <button onclick="buildSubGrid(false,true)" style="font-family:var(--mono);font-size:.7rem;padding:4px 10px;background:var(--bg3);border:1px solid var(--brd);border-radius:5px;color:var(--dim);cursor:pointer">Reset A→A</button>
</div>
<p style="margin-top:10px;font-size:.73rem;color:var(--dim);line-height:1.7">Each of the 26 letters maps to a unique output letter. Two plaintext letters cannot share the same output — the red indicator will appear until the conflict is fixed. There are 26! (≈ 4×10²⁶) possible keys.</p>`,
    hex_shuffle:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Hex-encodes then shuffles byte pairs randomly.</p>',
    base32:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">RFC 4648. Uses A-Z, 2-7, and = padding. Case-insensitive.</p>',
    base58:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Bitcoin alphabet. No 0/O/I/l to avoid visual confusion.</p>',
    ascii85:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Base85 encoding in &lt;~ ~&gt; wrapper. Higher density than Base64.</p>',
    a1z26:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">A=1, B=2, ..., Z=26. Space-separated numbers.</p>',
    html_entities:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Each character as &amp;#CODE; numeric entity.</p>',
    polybius:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">5×5 grid: each letter becomes a two-digit coordinate (11-55).</p>',
    adfgvx:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">6×6 grid using only letters A, D, F, G, V, X.</p>',
    tap_code:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Prison cipher. Each letter as dots: row dots, space, col dots (e.g. A = ". .", H = ".. ..."). Words separated by " / ".</p>',
    phone_keypad:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Multi-press: A=2, B=22, C=222, D=3, E=33... Tokens separated by spaces.</p>',
    nato_phonetic:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Alpha Bravo Charlie... NATO/ICAO phonetic alphabet.</p>',
    uuencode:'<p style="margin-top:12px;font-size:.78rem;color:var(--dim)">Legacy Unix encoding with begin/end markers.</p>',
  };$('cOpts').innerHTML=m[c]||'';if(c==='playfair')buildPlayfairGrid();if(c==='substitution')buildSubGrid();}

function buildPlayfairGrid(){
  const raw=($('pfK')||{value:''}).value.toUpperCase().replace(/J/g,'I');
  const errEl=$('pfErr');const gridEl=$('pfGrid');const remEl=$('pfRem');
  if(!errEl||!gridEl||!remEl)return;

  // Check for duplicate letters in the raw key (before de-duplication)
  const keyOnly=raw.replace(/[^A-Z]/g,'');
  const seen={};let hasDup=false;let dupLetter='';
  for(const c of keyOnly){
    if(seen[c]){hasDup=true;dupLetter=c;break;}
    seen[c]=true;
  }
  if(hasDup){
    errEl.textContent='Every letter must be different — "'+dupLetter+'" appears more than once.';
    errEl.style.display='';
  } else {
    errEl.style.display='none';
  }

  // Build the 25-char key square (de-duplicated key + remaining alphabet)
  const used=new Set();const grid=[];
  for(const c of (raw+'ABCDEFGHIKLMNOPQRSTUVWXYZ')){
    if(c>='A'&&c<='Z'&&!used.has(c)){used.add(c);grid.push(c);}
  }

  // Render 5×5 grid cells
  gridEl.innerHTML=grid.map((c,i)=>{
    const inKey=keyOnly.length>0&&keyOnly.includes(c);
    const bg=inKey?'rgba(0,255,136,.12)':'var(--bg3)';
    const color=inKey?'var(--accent)':'var(--text)';
    const brd=inKey?'rgba(0,255,136,.35)':'var(--brd)';
    return`<div style="width:32px;height:32px;display:flex;align-items:center;justify-content:center;`+
      `background:${bg};border:1px solid ${brd};border-radius:5px;`+
      `font-family:var(--mono);font-size:.75rem;font-weight:600;color:${color}">${c}</div>`;
  }).join('');

  // Remaining letters (not in key)
  const remaining='ABCDEFGHIKLMNOPQRSTUVWXYZ'.split('').filter(c=>!used.has(c));
  remEl.textContent=remaining.length?remaining.join(' '):'— all letters used —';
  remEl.style.color=remaining.length?'var(--dim)':'var(--accent)';
}

function buildSubGrid(randomize=false, reset=false){
  const grid=$('subGrid');const errEl=$('subErr');
  if(!grid)return;

  // On first call (no existing inputs) or when randomize/reset requested, seed the key
  const existing=grid.querySelectorAll('input');
  let key=[...Array(26)].map((_,i)=>i); // identity A→A default

  if(existing.length===26&&!randomize&&!reset){
    // Read current values from inputs
    key=[...existing].map(inp=>{const v=inp.value.toUpperCase();return v&&v>='A'&&v<='Z'?v.charCodeAt(0)-65:-1;});
  } else if(randomize){
    // Fisher-Yates shuffle
    for(let i=25;i>0;i--){const j=Math.floor(Math.random()*(i+1));[key[i],key[j]]=[key[j],key[i]];}
  }
  // else reset stays as identity

  // Build or rebuild the 26 cells (2 rows of 13)
  grid.innerHTML='';
  for(let i=0;i<26;i++){
    const ptLetter=String.fromCharCode(65+i);
    const ctLetter=key[i]>=0?String.fromCharCode(65+key[i]):ptLetter;
    const cell=document.createElement('div');
    cell.style.cssText='display:flex;flex-direction:column;align-items:center;gap:2px';
    cell.innerHTML=
      `<div style="font-family:var(--mono);font-size:.7rem;color:var(--dim);font-weight:600">${ptLetter}</div>`+
      `<div style="font-family:var(--mono);font-size:.65rem;color:var(--brd2)">↓</div>`+
      `<input maxlength="1" value="${ctLetter}" data-idx="${i}" `+
        `style="width:34px;height:34px;text-align:center;font-family:var(--mono);font-size:.85rem;font-weight:700;`+
        `background:var(--bg3);border:1px solid var(--brd);border-radius:5px;color:var(--text);text-transform:uppercase" `+
        `oninput="this.value=this.value.toUpperCase().replace(/[^A-Z]/g,'').slice(-1);validateSubGrid()">`;
    grid.appendChild(cell);
  }
  validateSubGrid();
}

function validateSubGrid(){
  const grid=$('subGrid');const errEl=$('subErr');
  if(!grid||!errEl)return;
  const inputs=[...grid.querySelectorAll('input')];
  const vals=inputs.map(inp=>inp.value.toUpperCase());

  // Reset all borders
  inputs.forEach(inp=>{inp.style.borderColor='var(--brd)';inp.style.color='var(--text)';});

  // Find duplicates
  const seen={};const dupes=new Set();
  vals.forEach((v,i)=>{
    if(!v){return;}
    if(seen[v]!==undefined){dupes.add(v);dupes.add(seen[v]);}
    else seen[v]=i;
  });

  // Find empty cells
  const empty=vals.filter(v=>!v).length;

  if(dupes.size){
    inputs.forEach((inp,i)=>{
      if(dupes.has(vals[i])){inp.style.borderColor='var(--red)';inp.style.color='var(--red)';}
    });
    const dupList=[...dupes].join(', ');
    errEl.textContent=`Output letter${dupes.size>1?'s':''} used more than once: ${dupList}. Each output letter must be unique.`;
  } else if(empty){
    errEl.textContent=`${empty} cell${empty>1?'s are':' is'} empty — fill all 26 letters before encrypting.`;
  } else {
    errEl.textContent='';
  }
}

function getSubKey(){
  // Returns the 26-element key array from the current grid, or null if invalid
  const grid=$('subGrid');
  if(!grid)return null;
  const vals=[...grid.querySelectorAll('input')].map(inp=>inp.value.toUpperCase());
  if(vals.some(v=>!v||!/^[A-Z]$/.test(v)))return null;
  const seen=new Set();
  const key=vals.map(v=>{const idx=v.charCodeAt(0)-65;if(seen.has(idx))return -1;seen.add(idx);return idx;});
  if(key.includes(-1))return null;
  return key;
}

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
    else if(curC==='playfair'){
      const pfErr=$('pfErr');
      if(pfErr&&pfErr.style.display!=='none'){o.innerHTML='<span style="color:var(--red)">'+H(pfErr.textContent)+'</span>';return;}
      ct=Playfair.encrypt(t,v('pfK')||'CIPHER');
    }
    else if(curC==='vigenere_autokey')ct=VigenereAutokey.encrypt(t,v('akK')||'SECRET');
    else if(curC==='reverse')ct=ReverseText.encrypt(t);
    else if(curC==='scytale')ct=Scytale.encrypt(t,+(v('scD'))||5);
    else if(curC==='route_cipher')ct=RouteCipher.encrypt(t,+(v('rtC'))||5);
    else if(curC==='bifid')ct=Bifid.encrypt(t,v('biK')||'CIPHER');
    else if(curC==='substitution'){
      const subErrEl=$('subErr');
      if(subErrEl&&subErrEl.textContent){o.innerHTML='<span style="color:var(--red)">'+H(subErrEl.textContent)+'</span>';return;}
      const subKey=getSubKey();
      if(!subKey){o.innerHTML='<span style="color:var(--red)">Fix the substitution key before encrypting.</span>';return;}
      ct=applySub(t,subKey);
    }
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
  if(!KB){return;} // KB not loaded yet. kb.js Promise.all will call renderKB when ready
  const entries=Object.entries(KB);
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
async function renderML(){
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
    FNAMES.push();
    const sorted=Object.entries(mlModel.importances).sort((a,b)=>b[1]-a[1]).slice(0,15);
    $('mlImp').innerHTML=sorted.map(([k,v])=>{
      const name=FNAMES[+k]||`feat_${k}`;const pct=(v*100).toFixed(0);
      const color=v>.6?'var(--accent)':v>.3?'var(--blue)':'var(--dim)';
      return`<div class="bar-r"><div class="bar-l">${name}</div><div class="bar-t"><div class="bar-f" style="width:${pct}%;background:${color}"></div></div><div class="bar-p">${(v*100).toFixed(1)}%</div></div>`;
    }).join('');
  }
  // Accuracy history: async in OPFS-backed storage
  const history=await AccuracyHistory.load();
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
  // Centroid profiles
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
async function exportData(){
  if(!mlModel.trained){alert('Train the model first to export a complete dataset.');return;}
  
  try {
    // Gather all data components
    const [
      modelData,
      sampleStats,
      userSamples,
      unsolvedData,
      confusionData,
      calibrationData,
      centroidData,
      kbData
    ] = await Promise.all([
      Promise.resolve(JSON.parse(mlModel.save())), // Model data
      SampleDB.getStats(), // Sample statistics
      SampleDB.loadUserSamples(), // User corrections
      UnsolvedStore.exportJSON().then(JSON.parse), // Unsolved samples
      ConfusionTracker.getMatrix(), // Confusion matrix
      Promise.resolve(CalibrationTracker.getCalibration()), // Calibration data
      CentroidStore.getAllProfiles(), // Per-type centroids
      KBStore.load() // Knowledge base
    ]);

    // Build comprehensive export
    const exportData = {
      version: 2,
      exportedAt: new Date().toISOString(),
      featureCount: FEATURE_COUNT,
      
      // ML Model
      model: modelData,
      
      // Training data summary (don't export massive training chunks)
      trainingSummary: {
        totalSamples: sampleStats.total,
        samplesByType: sampleStats.byType
      },
      
      // User corrections (small, valuable data)
      userCorrections: {
        count: userSamples.count,
        samples: userSamples.X.map((features, i) => ({
          features: Array.from(features),
          type: userSamples.Y[i],
          source: userSamples.sources[i]
        }))
      },
      
      // Unsolved samples (for continued learning)
      unsolvedSamples: unsolvedData.samples || [],
      unsolvedStats: unsolvedData.stats || {},
      
      // Learning metadata
      confusionMatrix: confusionData || {},
      calibrationData: calibrationData || [],
      centroids: centroidData || {},
      knowledgeBase: kbData || {}
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {type: 'application/json'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `cipherlab_complete_${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    
    console.log(`[Export] Complete dataset exported: ${exportData.trainingSummary.totalSamples} training samples, ${exportData.userCorrections.count} user corrections, ${exportData.unsolvedSamples.length} unsolved samples`);
    
  } catch (error) {
    console.error('[Export] Failed:', error);
    alert('Export failed. Check console for details.');
  }
}
async function importData(input){
  const file = input.files[0];
  if (!file) return;
  
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const data = JSON.parse(e.target.result);
      
      // Validate the import file
      if (!data.version || !data.model) {
        // Try legacy model-only import
        if (data.trees && data.trained) {
          mlModel.load(e.target.result);
          await ModelStore.save(mlModel);
          renderML();
          alert('Legacy model imported successfully!');
          return;
        }
        throw new Error('Invalid export file format');
      }
      
      if (data.featureCount !== FEATURE_COUNT) {
        throw new Error(`Feature count mismatch: file has ${data.featureCount}, system expects ${FEATURE_COUNT}`);
      }
      
      console.log(`[Import] Loading dataset from ${data.exportedAt}`);
      console.log(`[Import] Contains: ${data.trainingSummary?.totalSamples || 0} training samples, ${data.userCorrections?.count || 0} user corrections, ${data.unsolvedSamples?.length || 0} unsolved samples`);
      
      // Import ML model
      if (data.model) {
        mlModel.load(JSON.stringify(data.model));
        await ModelStore.save(mlModel);
      }
      
      // Import user corrections
      if (data.userCorrections?.samples) {
        for (const sample of data.userCorrections.samples) {
          await SampleDB.addUserSample(
            '', // text not stored in export to save space
            sample.type,
            new Float64Array(sample.features),
            sample.source || 'imported'
          );
        }
      }
      
      // Import unsolved samples
      if (data.unsolvedSamples?.length) {
        await UnsolvedStore.load(); // Initialize if needed
        const unsolvedItems = data.unsolvedSamples.map(s => ({
          features: new Float64Array(s.features),
          actual: s.actual,
          predicted: s.predicted
        }));
        await UnsolvedStore.addUnsolved(unsolvedItems);
      }
      
      // Import metadata
      if (data.confusionMatrix && Object.keys(data.confusionMatrix).length > 0) {
        ConfusionTracker.matrix = data.confusionMatrix;
        await ConfusionTracker.save();
      }
      
      if (data.calibrationData?.length) {
        CalibrationTracker.buckets = {};
        for (const bucket of data.calibrationData) {
          const key = bucket.confidence.toFixed(1);
          CalibrationTracker.buckets[key] = {
            total: bucket.total,
            correct: bucket.correct
          };
        }
        await CalibrationTracker.save();
      }
      
      if (data.centroids && Object.keys(data.centroids).length > 0) {
        // Restore centroids by reconstructing the internal profiles structure
        CentroidStore._profiles = {};
        for (const [type, profile] of Object.entries(data.centroids)) {
          if (profile && profile.mean && profile.count > 0) {
            CentroidStore._profiles[type] = {
              count: profile.count,
              mean: new Float64Array(profile.mean),
              m2: profile.variance ? new Float64Array(profile.variance.map((v, i) => v * (profile.count - 1))) : new Float64Array(FEATURE_COUNT)
            };
          }
        }
        await CentroidStore.save();
      }
      
      if (data.knowledgeBase && Object.keys(data.knowledgeBase).length > 0) {
        await KBStore.save(data.knowledgeBase);
        // Reload KB into global variable
        KB = await KBStore.load();
      }
      
      // Refresh UI
      await Promise.all([renderML(), renderKB()]);
      syncAllStats();
      
      alert(`Complete dataset imported successfully!\n\nModel: ${data.model.trained ? 'Trained' : 'Untrained'}\nUser corrections: ${data.userCorrections?.count || 0}\nUnsolved samples: ${data.unsolvedSamples?.length || 0}`);
      
    } catch (error) {
      console.error('[Import] Failed:', error);
      alert(`Import failed: ${error.message}`);
    }
  };
  reader.readAsText(file);
}

// User correction: called when user clicks "Correct this" on decrypt page
const ALL_TYPES=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','hex_shuffle'];
function correctPrediction(text){
  const sel=$('corrType');if(!sel)return;
  const correctType=sel.value;
  if(!correctType){alert('Select the correct type first.');return;}
  DataStore.saveCorrection(text,correctType).then(async ()=>{
    $('corrStatus').innerHTML='<span style="color:var(--accent)">✓ Saved! This correction will be used in future training (weighted 3x).</span>';
    // Also update centroid immediately
    const feats=extractFeatures(text);
    CentroidStore.update(correctType,feats);
    await CentroidStore.save();
  });
}

// Silently capture encrypt-page outputs for training
function captureEncrypt(ciphertext,type){
  if(ciphertext&&type&&ciphertext.length>=8){
    DataStore.saveEncryptCapture(ciphertext,type).then(()=>{
      console.log('Captured encrypt output: '+type+' ('+ciphertext.length+' chars)');
    });
  }
}

// Standalone evaluation: generates a fresh held-out set and tests the current
// model without doing any training. Gives an unbiased accuracy estimate since
// the samples are generated after training, not drawn from the training pool.
async function runEval(){
  if(!mlModel.trained){
    // addLog isn't available here so write directly to the log box
    const logEl=$('tLog');
    if(logEl)logEl.innerHTML='<div class="lfail">[eval] No model trained yet — run Training first.</div>';
    return;
  }
  if(trainRunning){
    const logEl=$('tLog');
    if(logEl)logEl.innerHTML='<div class="lfail">[eval] Training is already running — wait for it to finish.</div>';
    return;
  }

  // Local log function: mirrors the one inside startTrain
  const evalLog=[];
  function addLog(msg,ok=true){
    evalLog.push({msg,ok});
    if(evalLog.length>500)evalLog.splice(0,evalLog.length-500);
    const logEl=$('tLog');
    if(logEl){logEl.innerHTML=evalLog.map(l=>`<div class="${l.ok?'lok':'lfail'}">${H(l.msg)}</div>`).join('');logEl.scrollTop=logEl.scrollHeight;}
  }

  $('tsS').textContent='EVALUATING';$('tsS').style.color='var(--teal)';
  const evalBar=$('tBar');if(evalBar)evalBar.style.width='0';
  const sampPerType=+($('tSamp').value)||500;
  addLog(`── Standalone Evaluation (${sampPerType} samples per type) ──`);
  const types=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','hex_shuffle'];
  const evalX=[],evalY=[];
  for(let ti=0;ti<types.length;ti++){
    const type=types[ti];
    for(let i=0;i<sampPerType;i++){
      try{const ct=genSample(type,false);if(ct&&ct.length>=8){const f=extractFeatures(ct);if(!f.some(isNaN)){evalX.push(f);evalY.push(type);}}}catch(e){}
    }
    if(evalBar)evalBar.style.width=((ti+1)/types.length*50)+'%';
    await new Promise(r=>setTimeout(r,0));
  }
  addLog('[eval] Generated '+evalX.length+' held-out samples — running predictions...');
  let correct=0;const byType={};const confCounts={};
  for(let i=0;i<evalX.length;i++){
    const pred=mlModel.predict(evalX[i]);const actual=evalY[i];const ok=pred.cls===actual;
    if(!byType[actual])byType[actual]={c:0,t:0};byType[actual].t++;if(ok){correct++;byType[actual].c++;}
    if(!ok){const k=actual+' → '+pred.cls;confCounts[k]=(confCounts[k]||0)+1;}
    if(evalBar&&i%200===0)evalBar.style.width=(50+((i+1)/evalX.length*50))+'%';
  }
  const acc=evalX.length?correct/evalX.length:0;
  if(evalBar)evalBar.style.width='100%';
  $('tsA').textContent=(acc*100).toFixed(1)+'%';
  $('tsS').textContent='IDLE';$('tsS').style.color='var(--dim)';
  addLog('[eval] ══ Overall accuracy: '+(acc*100).toFixed(1)+'% ('+correct+'/'+evalX.length+') ══');
  // Record to accuracy history with proper date-based run numbering
  const today = new Date().toISOString().split('T')[0]; // YYYY-MM-DD
  const history = await AccuracyHistory.load();
  const todaysRuns = history.filter(entry => {
    const entryDate = new Date(entry.timestamp).toISOString().split('T')[0];
    return entryDate === today;
  });
  const runNumber = todaysRuns.length + 1;
  
  await AccuracyHistory.record(acc, evalX.length, runNumber);
  $('tTypeSection').style.display='';
  $('tTypeAcc').innerHTML=Object.entries(byType).sort((a,b)=>(b[1].c/b[1].t)-(a[1].c/a[1].t)).map(([t,d])=>{const pct=d.t?(d.c/d.t*100):0;return`<div class="bar-r"><div class="bar-l">${t}</div><div class="bar-t"><div class="bar-f" style="width:${pct.toFixed(0)}%;background:${pct>80?'var(--accent)':pct>50?'var(--orange)':'var(--red)'}"></div></div><div class="bar-p">${pct.toFixed(0)}%</div></div>`;}).join('');
  const worst=Object.entries(byType).sort((a,b)=>(a[1].c/a[1].t)-(b[1].c/b[1].t)).slice(0,5);
  addLog('[eval] Weakest types:');for(const[t,d]of worst)addLog(`  ${t}: ${d.c}/${d.t} (${(d.c/d.t*100).toFixed(0)}%)`);
  const topConf=Object.entries(confCounts).sort((a,b)=>b[1]-a[1]).slice(0,5);
  if(topConf.length){addLog('[eval] Top confusions:');for(const[pair,count]of topConf)addLog(`  ${pair}: ${count}×`);}
  syncAllStats();
  renderML(); // update accuracy history chart on ML page
}

// Init: startup is handled by Promise.all in kb.js which awaits storage
// before calling syncAllStats, renderKB, and renderML in the correct order

