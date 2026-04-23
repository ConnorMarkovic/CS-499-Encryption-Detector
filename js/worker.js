/**
 * CipherLab - Web Worker Training Module
 * 
 * This Web Worker runs the machine learning training pipeline off the main thread
 * to keep the user interface responsive during intensive computation. It handles
 * sample generation, forest training, and model evaluation.
 * 
 * The worker communicates with the main thread via a message-passing protocol
 * to provide progress updates and deliver trained models back to the UI.
 * 
 * Message Protocol:
 * Main → Worker:
 *   { cmd: 'train', ... } - Start training with specified parameters
 *   { cmd: 'stop' } - Abort current training operation
 * 
 * Worker → Main:
 *   { type: 'ready' } - Worker initialized and ready
 *   { type: 'log', msg, ok } - Status message for UI display
 *   { type: 'progress', iter, phase } - Training progress update
 *   { type: 'model', json } - Completed model data
 *   { type: 'samples', X, Y, texts, iter } - Generated training samples
 */
//    { type: 'eval', acc, total, correct, byType, confusion, oob, iter, testSamples, challengerJson }
//    { type: 'done', aborted }
// ═══════════════════════════════════════════════════════════════════════

// Signal the main thread immediately so the handshake doesn't time out
// while importScripts is fetching files. The main thread will wait for
// the 'loaded' message before sending the train command.
console.log('[worker.js] script started');
self.postMessage({type:'ready',status:'loading'});
console.log('[worker.js] posted loading ping, starting importScripts...');

// Load dependencies: wrap in try/catch so a fetch failure posts a clear
// error back to the main thread instead of silently killing the worker.
try {
  importScripts('ciphers.js', 'encoders.js', 'ml.js');
  console.log('[worker.js] importScripts completed successfully');
} catch(e) {
  console.error('[worker.js] importScripts failed:', e);
  self.postMessage({type:'error', msg:'importScripts failed: ' + e.message});
  // Don't call close() — let the main thread terminate us via onerror/message
}

// All three scripts loaded successfully — tell the main thread we're ready for work
self.postMessage({type:'ready',status:'loaded'});
console.log('[worker.js] posted loaded, waiting for train command...');

// ═══════════════════════════════════════════════════════════════════════
//  CORPUS: procedural text generator (same word pools as ui.js)
// ═══════════════════════════════════════════════════════════════════════

const _NOUNS=[
  'system','network','server','cipher','algorithm','protocol','message','database','password','firewall','signal','module','packet','token','session','device','buffer','kernel','vector','matrix','cluster','payload','header','socket','gateway','archive','sensor','router','filter','handler','parser','driver','thread','process','channel','registry','sandbox','container','pipeline','function','variable','array','table','index','query','schema','record','cache','stack','queue','node','edge','branch','block','chain','frame','layer','stream','cursor','pointer','instance','template','interface','pattern','command','strategy',
  'river','mountain','forest','ocean','valley','desert','island','canyon','glacier','volcano','meadow','cliff','waterfall','shore','prairie','marsh','cavern','ridge','plateau','storm','thunder','lightning','rainbow','sunset','horizon','breeze','current','tide','wave','stone','crystal','diamond','ember','flame','shadow','echo','frost','mist','dawn','twilight',
  'captain','soldier','merchant','scholar','traveler','guardian','hunter','builder','healer','messenger','inventor','explorer','navigator','commander','engineer','artist','musician','philosopher','detective','apprentice','champion','volunteer','pioneer','architect','librarian','professor','student','teacher','pilot','surgeon',
  'bridge','tower','castle','fortress','temple','library','garden','market','harbor','lighthouse','compass','telescope','lantern','anchor','shield','sword','crown','banner','scroll','mirror','clock','engine','hammer','anvil','wheel','lever','spring','basket','candle','torch','bell','drum','flag','coin','key','lock','gate','door','window','wall','fence','path','road','trail','ladder',
  'freedom','justice','courage','wisdom','honor','truth','balance','harmony','chaos','order','silence','mystery','knowledge','power','strength','fortune','destiny','legacy','progress','victory','challenge','journey','promise','secret','legend','memory','reason','purpose','vision','spirit','energy','motion','rhythm','pattern','signal','measure','limit','threshold','boundary','origin'
];
const _ADJS=[
  'secure','encrypted','hidden','volatile','persistent','dynamic','static','parallel','distributed','recursive','virtual','portable','modular','scalable','robust','adaptive','reactive','autonomous','redundant','critical','fragile','stable','quantum','symmetric','asymmetric','compressed','encoded','verified','trusted','isolated','connected','hardened','vulnerable','lightweight','complex','nested','linear','random','sequential','logical','physical','temporal','spatial','global','local','public','private','internal','external','primary','secondary','active','passive',
  'ancient','modern','classical','bright','dark','narrow','wide','tall','short','deep','shallow','sharp','smooth','rough','heavy','light','swift','slow','loud','quiet','warm','cold','frozen','burning','golden','silver','iron','wooden','crystal','hollow','solid','broken','whole','empty','full','open','closed','vast','tiny','enormous','miniature',
  'brilliant','clever','careful','reckless','patient','restless','fearless','cautious','bold','gentle','fierce','calm','wild','strange','familiar','mysterious','obvious','subtle','elegant','crude','precise','vague','certain','doubtful','reliable','unstable','powerful','weak','mighty','humble','proud','loyal','defiant','silent','noisy','peaceful','violent','graceful','clumsy','cunning',
  'crimson','azure','emerald','obsidian','ivory','amber','violet','scarlet','cobalt','copper','bronze','sapphire','jade','coral','onyx','pearl','turquoise','mahogany','slate','charcoal','dusty','gleaming','glowing','shimmering','sparkling','flickering','pulsing','fading','vivid','pale','muted','translucent'
];
const _VERBS=[
  'encrypts','decrypts','processes','analyzes','monitors','detects','prevents','validates','transmits','receives','compiles','executes','generates','transforms','parses','scans','filters','routes','caches','queries','hashes','verifies','authenticates','authorizes','synchronizes','compresses','encodes','decodes','intercepts','bypasses','deploys','configures','initializes','terminates','recovers','restores','archives','optimizes',
  'carries','crosses','follows','reaches','climbs','descends','circles','surrounds','breaks','builds','destroys','creates','opens','closes','locks','unlocks','lifts','drops','pushes','pulls','throws','catches','holds','releases','gathers','scatters','strikes','blocks','dodges','chases','flees','hides','reveals','covers','exposes',
  'discovers','remembers','forgets','understands','believes','doubts','decides','chooses','refuses','accepts','demands','offers','promises','warns','teaches','learns','studies','solves','questions','answers','explains','describes','imagines','considers','evaluates','judges','measures','compares','combines','separates','connects','divides','arranges','organizes','inspects','examines','investigates','challenges','conquers','defends','protects','guards','watches','observes','notices','recognizes','identifies','locates','searches','finds','loses','wins','fails','succeeds','attempts','achieves','abandons','continues','begins','finishes','completes'
];
const _ADVS=['quickly','silently','efficiently','securely','repeatedly','automatically','continuously','periodically','randomly','sequentially','concurrently','atomically','gracefully','forcefully','temporarily','permanently','partially','completely','incrementally','dramatically','substantially','reliably','consistently','occasionally','frequently','rarely','always','never','sometimes','internally','externally','locally','remotely','carefully','carelessly','boldly','cautiously','steadily','suddenly','gradually','instantly','eventually','immediately','deliberately','accidentally','naturally','artificially','precisely','roughly','approximately','exactly','merely','entirely','barely','hardly','mostly','largely','mainly','purely','simply','deeply','highly','strongly','weakly','firmly','loosely','tightly','broadly','narrowly','openly','secretly','directly','indirectly','formally','casually','desperately','calmly','furiously','patiently','reluctantly','eagerly','willingly'];
const _PREPS=['through','across','behind','beyond','within','without','beneath','between','against','toward','around','along','above','below','inside','outside','under','over','before','after','during','until','since','despite','regarding','concerning','involving','including','excluding','following','preceding','surrounding','underlying','supporting','protecting','among','amid','alongside','opposite','near','past','beside','throughout','upon','onto','into','from','towards','aboard','atop'];
const _NAMES=['alice','robert','chen','maria','james','sarah','dmitri','elena','marcus','priya','thomas','fatima','kenji','sofia','oliver','nadia','carlos','ingrid','hassan','maya','felix','diana','oscar','petra','rafael','clara','boris','leona','samuel','yuki'];
const _PLACES=['london','tokyo','berlin','cairo','mumbai','sydney','toronto','oslo','dublin','prague','vienna','lisbon','nairobi','santiago','bangkok','moscow','havana','athens','seoul','lima','zurich','ankara','warsaw','bogota','manila','hanoi','riyadh','stockholm','bucharest','helsinki'];
const _TIMES=['yesterday','today','tomorrow','last night','this morning','at midnight','before sunrise','after sunset','at noon','during the storm','in the evening','at dusk','before dawn','in the afternoon','moments ago','hours later','days before','weeks after','long ago','recently'];

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

const _TEMPLATES=[
  ()=>`the ${ra()} ${rn()} ${rv()} the ${ra()} ${rn()} ${rp()} the ${rn()}`,
  ()=>`a ${ra()} ${rn()} ${rv()} the ${rn()} and the ${rn()} ${rad()}`,
  ()=>`the ${rn()} ${rv()} every ${ra()} ${rn()} ${rp()} the ${ra()} ${rn()}`,
  ()=>`${ra()} ${rn()} and ${ra()} ${rn()} ${rv()} the ${rn()} ${rp()} ${rn()} ${rad()}`,
  ()=>`the ${ra()} ${rn()} ${rp()} the ${rn()} ${rv()} ${rad()} and ${rv()} the ${rn()}`,
  ()=>`the ${rn()} ${rn()} ${rv()} ${rad()} while the ${ra()} ${rn()} ${rv()} the ${rn()}`,
  ()=>`the ${rn()} ${rv()} the ${rn()} ${rp()} the ${rn()} and ${rv()} the ${ra()} ${rn()} ${rad()}`,
  ()=>`when the ${rn()} ${rv()} the ${ra()} ${rn()} must ${rv2()} ${rad()}`,
  ()=>`after the ${rn()} ${rv()} the ${rn()} ${rv()} ${rad()} ${rp()} ${rn()}`,
  ()=>`before the ${ra()} ${rn()} can ${rv2()} the ${rn()} needs to ${rv2()} first`,
  ()=>`if the ${rn()} ${rv()} ${rad()} then the ${ra()} ${rn()} will ${rv2()} the ${rn()}`,
  ()=>`until the ${ra()} ${rn()} ${rv()} the ${rn()} the ${rn()} cannot ${rv2()}`,
  ()=>`every ${rn()} ${rv()} ${ra()} ${rn()} but the ${rn()} ${rv()} ${rad()}`,
  ()=>`no ${ra()} ${rn()} can ${rv2()} the ${rn()} ${rp()} a ${ra()} ${rn()}`,
  ()=>`several ${ra()} ${rn()} ${rv()} the ${rn()} ${rp()} the ${ra()} ${rn()}`,
  ()=>`each ${ra()} ${rn()} ${rv()} another ${ra()} ${rn()} ${rp()} their ${rn()}`,
  ()=>`most ${ra()} ${rn()} ${rv()} ${rad()} but some ${rv()} the ${rn()} ${rp()} ${rn()}`,
  ()=>`only the ${ra()} ${rn()} ${rv()} the ${rn()} ${rn()} ${rad()} ${rp()} the ${rn()}`,
  ()=>`both the ${rn()} and the ${rn()} ${rv()} the ${ra()} ${rn()} ${rad()}`,
  ()=>`our ${ra()} ${rn()} ${rv()} their ${ra()} ${rn()} ${rp()} the ${rn()} ${rn()}`,
  ()=>`this ${ra()} ${rn()} ${rv()} ${ra()} ${rn()} that ${rv()} ${rad()}`,
  ()=>`${rname()} said the ${ra()} ${rn()} ${rv()} the ${rn()} ${rad()}`,
  ()=>`${rname()} and ${rname()} ${rv2()} the ${ra()} ${rn()} ${rp()} ${rplace()}`,
  ()=>`the ${rn()} ${rp()} ${rplace()} ${rv()} ${rad()} ${rp()} the ${ra()} ${rn()}`,
  ()=>`${rname()} ${rv2()} the ${ra()} ${rn()} ${rp()} the ${rn()} in ${rplace()} ${rad()}`,
  ()=>`in ${rplace()} the ${ra()} ${rn()} ${rv()} the ${rn()} that ${rname()} ${rv2()}`,
  ()=>`${rtime()} the ${ra()} ${rn()} ${rv2()} the ${rn()} ${rp()} the ${ra()} ${rn()}`,
  ()=>`the ${rn()} ${rv2()} ${rad()} ${rtime()} while the ${rn()} ${rv2()} ${rp()} ${rplace()}`,
  ()=>`${rnum()} ${ra()} ${rn()} ${rv()} the ${rn()} ${rp()} ${rnum()} ${ra()} ${rn()}`,
  ()=>`the ${rn()} ${rv()} exactly ${rnum()} ${ra()} ${rn()} ${rad()} ${rp()} the ${rn()}`,
  ()=>`after ${rnum()} ${rn()} ${rv2()} the ${ra()} ${rn()} finally ${rv2()} ${rad()}`,
  ()=>`the ${ra()} ${rn()} was ${rv2()}ed ${rp()} the ${rn()} by ${rname()} ${rtime()}`,
  ()=>`the ${rn()} had been ${rv2()}ed ${rad()} ${rp()} the ${ra()} ${rn()} for ${rnum()} days`,
  ()=>`whether the ${rn()} ${rv()} the ${ra()} ${rn()} ${rp()} the ${rn()} remains unclear`,
  ()=>`how the ${ra()} ${rn()} ${rv()} the ${rn()} ${rad()} is still a ${rn()} to ${rname()}`,
  ()=>`the ${rn()} ${rv()} ${rad()} and the ${ra()} ${rn()} ${rv()} the ${rn()} but the ${rn()} ${rv()} ${rp()} ${rn()}`,
  ()=>`although the ${ra()} ${rn()} ${rv()} ${rad()} the ${rn()} still ${rv()} the ${ra()} ${rn()} ${rp()} ${rplace()}`,
  ()=>`${rname()} ${rv2()} that the ${ra()} ${rn()} ${rv()} the ${rn()} while the ${rn()} ${rv()} ${rad()} ${rp()} ${rn()}`,
  ()=>`the ${rn()} the ${rn()} and the ${rn()} all ${rv2()} the ${ra()} ${rn()} ${rp()} ${rplace()} ${rad()}`,
  ()=>`${rname()} ${rv2()} ${rnum()} ${rn()} ${rnum()} ${rn()} and ${rnum()} ${ra()} ${rn()} ${rp()} the ${rn()}`,
];

function generateText(short=false){
  const tmpl=_TEMPLATES[Math.floor(Math.random()*_TEMPLATES.length)];
  let text=tmpl();
  if(short)text=text.split(' ').slice(0,3+Math.floor(Math.random()*4)).join(' ');
  return text;
}

// ═══════════════════════════════════════════════════════════════════════
//  CIPHER KEY POOLS
// ═══════════════════════════════════════════════════════════════════════

const VIG_KEYS=['KEY','SECRET','CIPHER','ALPHA','BRAVO','DELTA','ENIGMA','CRYPTO','SECURE','HIDDEN','PHOENIX','STORM','QUANTUM','NEBULA','FALCON'];
const AFFINE_A=[1,3,5,7,9,11,15,17,19,21,23,25];
const COL_KEYS=['ZEBRA','CASTLE','STORM','PYTHON','MATRIX','FALCON','CRYPTO','HIDDEN'];

// ═══════════════════════════════════════════════════════════════════════
//  SAMPLE GENERATOR: one labeled sample per cipher type
// ═══════════════════════════════════════════════════════════════════════

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

// ═══════════════════════════════════════════════════════════════════════
//  TRAINING LOOP
// ═══════════════════════════════════════════════════════════════════════

const TYPES=['plaintext','caesar','vigenere','substitution','atbash','affine','rail_fence','enigma','xor_single','xor_repeating','rc4','beaufort','porta','columnar','rot47','binary','hex','base64','morse','octal','decimal','url','bacon','multi_layer','rot13','a1z26','playfair','vigenere_autokey','reverse','scytale','route_cipher','base32','base58','ascii85','uuencode','html_entities','bifid','polybius','adfgvx','tap_code','phone_keypad','nato_phonetic','hex_shuffle'];

let model=new DecisionForest();
let abort=false;

self.onmessage=function(e){
  const msg=e.data;
  if(msg.cmd==='stop'){abort=true;return;}
  if(msg.cmd!=='train')return;

  abort=false;
  const{storedX,storedY,sampPerType,maxIter,continuous,existingModel}=msg;

  // Misclassified samples from previous sessions which are included in every iteration
  const missX=storedX.map(a=>new Float64Array(a));
  const missY=[...storedY];
  if(existingModel){try{model.load(existingModel);}catch(e){}}
  let confusedTypes=new Set();

  for(let iter=1;iter<=maxIter&&!abort;iter++){
    self.postMessage({type:'log',msg:'── Iteration '+iter+(continuous?' (continuous)':'/'+maxIter)+' ──'});
    self.postMessage({type:'progress',iter,phase:'generating'});

    // Phase 1: Generate fresh samples for all types
    const freshX=[],freshY=[],freshTexts=[];
    for(const type of TYPES){
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
    self.postMessage({type:'progress',iter,phase:'training'});
    const trainX=[...freshX,...missX];const trainY=[...freshY,...missY];
    model.train(trainX,trainY,20,10,3);
    self.postMessage({type:'log',msg:'[ml] Trained on '+trainX.length+' samples (20 trees, depth 10), OOB: '+(model.oobAccuracy*100).toFixed(1)+'%'});
    self.postMessage({type:'model',json:model.save()});

    // Send fresh samples back to the main thread for IndexedDB storage
    self.postMessage({type:'samples',X:freshX.map(f=>Array.from(f)),Y:freshY,texts:freshTexts,iter});

    // Phase 3: Evaluate on the training samples
    self.postMessage({type:'progress',iter,phase:'evaluating'});
    let correct=0,total=0;
    const byType={};const confusion=[];const testSamples=[];
    for(let i=0;i<freshX.length;i++){
      try{
        const f=freshX[i];const type=freshY[i];
        const pred=model.predict(f);
        total++;
        if(!byType[type])byType[type]={t:0,c:0};byType[type].t++;
        const ok=pred.cls===type;if(ok){correct++;byType[type].c++;}
        confusion.push({actual:type,predicted:pred.cls,confidence:pred.confidence,ok,ic:f[0],ent:f[3]});
        testSamples.push({features:Array.from(f),actual:type});
      }catch(e){}
    }
    const acc=total?correct/total:0;

    // Update confused types for next iteration so types below 80% get boosted
    confusedTypes=new Set();
    for(const type in byType){
      if(byType[type].t>=3&&byType[type].c/byType[type].t<0.8)confusedTypes.add(type);
    }

    self.postMessage({type:'eval',acc,total,correct,byType,confusion,oob:model.oobAccuracy,iter,testSamples,challengerJson:model.save()});
  }
  self.postMessage({type:'done',aborted:abort});
};
