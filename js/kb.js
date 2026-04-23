/**
 * CipherLab - Knowledge Base Module
 * 
 * This module manages the persistent knowledge base that stores information about
 * cipher types, their characteristics, and user interaction data. It also provides
 * detailed feature descriptions and tooltips for the statistical analysis features.
 * 
 * The knowledge base grows over time as users interact with different cipher types,
 * building up performance statistics and insights.
 * 
 * Dependencies: ciphers.js (ENGLISH_FREQ), ml.js (mlModel)
 */

/**
 * KNOWLEDGE BASE DATA
 * Initial seed data for all supported cipher types and encodings.
 * Each entry contains classification information, descriptions, and vulnerability analysis.
 */

const SEED_KB={
  caesar:{name:'Caesar Cipher',cat:'monoalphabetic_substitution',desc:'A simple substitution cipher where every letter is shifted by the same number of positions in the alphabet. For example, with a shift of 3, A becomes D, B becomes E, and so on. When you reach Z, it wraps around to A.',enc:'Choose shift 1-25. Each letter moves forward by that amount, wrapping Z→A.',dec:'Try all 25 shifts, score each against English letter frequencies. Chi-squared scoring automates this.',ic:[.060,.070],weakness:['Only 25 keys — trivially brute-forced','Preserves letter frequency distribution','Single-letter words reveal themselves'],hist:'Used by Julius Caesar ~50 BCE.'},
  vigenere:{name:'Vigenère Cipher',cat:'polyalphabetic_substitution',desc:'Uses a repeating keyword to encrypt text, where each letter of the keyword determines how much to shift each corresponding letter in the message. This creates a polyalphabetic cipher because the same letter in the plaintext can be encrypted differently depending on its position.',enc:'Repeat keyword to match plaintext length. Shift each letter by the key letter position.',dec:'Kasiski examination: find repeated trigrams, GCD of spacings = key length. Friedman IC test confirms. Split into Caesar streams, solve each.',ic:[.038,.055],weakness:['Kasiski reveals key length','Short keys especially vulnerable','Reduces to multiple Caesar ciphers'],hist:'Described by Bellaso 1553. Called "le chiffre indéchiffrable" for 300 years.'},
  substitution:{name:'Simple Substitution',cat:'monoalphabetic_substitution',desc:'Each letter of the alphabet is consistently replaced with a different letter according to a fixed substitution table. Unlike Caesar, there\'s no pattern to the replacements - A might become Q, B might become M, etc.',enc:'Create a random permutation of the alphabet as the key.',dec:'Frequency analysis + hill-climbing: swap letter pairs, score against n-gram frequencies.',ic:[.060,.070],weakness:['Preserves frequency distribution','Hill-climbing solves texts >50 chars'],hist:'Used since antiquity.'},
  atbash:{name:'Atbash Cipher',cat:'monoalphabetic_substitution',desc:'A simple substitution where the alphabet is reversed - A maps to Z, B maps to Y, C maps to X, and so on. It\'s completely self-reversing, meaning applying it twice gets you back to the original text.',enc:'Replace each letter with its mirror. No key.',dec:'Apply same transformation. Check if result is English.',ic:[.060,.070],weakness:['Only one possible key','Self-inverse'],hist:'Hebrew cipher from the Bible.'},
  enigma:{name:'Enigma Machine',cat:'electromechanical_polyalphabetic',desc:'A complex electromechanical cipher machine that uses rotating wheels (rotors) and electrical connections to scramble letters. Each keypress advances the rotors, changing how subsequent letters are encrypted. The machine was self-reciprocal, meaning typing the ciphertext with the same settings would produce the plaintext.',enc:'Configure 3 rotors, positions, ring settings, plugboard. Signal passes through rotors and reflector.',dec:'Self-inverse with same settings. Without: Bombe-style attack exploiting no-self-encryption.',ic:[.038,.042],weakness:['No letter encrypts to itself','Reflector reduces keyspace','Double-stepping anomaly'],hist:'Nazi Germany WWII. Cracked by Turing at Bletchley Park.'},
  affine:{name:'Affine Cipher',cat:'monoalphabetic_substitution',desc:'A mathematical cipher that transforms each letter using the formula (ax + b) mod 26, where x is the letter\'s position, and a and b are key values. It\'s essentially a generalized version of the Caesar cipher with multiplication and addition.',enc:'Choose a (coprime to 26) and b (0-25).',dec:'Brute-force 312 combinations.',ic:[.060,.070],weakness:['Only 312 keys','Preserves frequency distribution'],hist:'Generalization of Caesar.'},
  rail_fence:{name:'Rail Fence Cipher',cat:'transposition',desc:'A transposition cipher where you write the message in a zigzag pattern across multiple "rails" (lines), then read off the letters horizontally from each rail. The number of rails determines the pattern complexity.',enc:'Choose rails. Write zigzag, read each rail.',dec:'Try all rail counts 2-N/2, score against English.',ic:[.060,.070],weakness:['Frequencies unchanged','Tiny keyspace'],hist:'American Civil War.'},
  playfair:{name:'Playfair Cipher',cat:'digraph_substitution',desc:'Works with pairs of letters instead of individual ones. Uses a 5×5 grid filled with a keyword to encrypt letter pairs according to specific rules based on their positions in the grid. If the letters are in the same row, column, or form a rectangle, different substitution rules apply.',enc:'Build matrix from keyword. Same row: shift right. Same column: shift down. Rectangle: swap.',dec:'Reverse rules. Simulated annealing on digraph frequencies.',ic:[.045,.060],weakness:['Only 25 chars (I=J)','Digraph patterns preserved'],hist:'Wheatstone 1854, Boer War and WWI.'},
  xor_single:{name:'XOR Single-Byte',cat:'modern_broken',desc:'Takes every byte in the message and performs an XOR operation with the same key byte. Since XOR with the same value twice returns the original, this cipher is self-reversing. It\'s commonly used in malware to obfuscate strings.',enc:'XOR each byte with key byte (0-255). Self-inverse.',dec:'Brute-force all 256 keys in milliseconds. One known byte reveals the key.',ic:[.055,.068],weakness:['256 keys — trivial','Known plaintext reveals key','Preserves byte frequency patterns'],hist:'Ubiquitous in malware and CTF challenges.'},
  xor_repeating:{name:'XOR Repeating-Key',cat:'modern_broken',desc:'Similar to single-byte XOR, but uses a multi-byte key that repeats throughout the message. Each byte of the message is XORed with the corresponding byte of the repeating key. This is essentially the byte-level equivalent of the Vigenère cipher.',enc:'Repeat key to plaintext length. XOR each byte.',dec:'Hamming distance finds key length. Split into single-byte streams, crack each.',ic:[.040,.058],weakness:['Hamming distance reveals key length','Key reuse is catastrophic: C₁⊕C₂ = P₁⊕P₂'],hist:'WEP WiFi was broken 2001 via related attack on RC4.'},
  rc4:{name:'RC4 Stream Cipher',cat:'modern_broken',desc:'A stream cipher that generates a pseudo-random keystream based on a variable-length key. The keystream is then XORed with the plaintext. RC4 uses two main algorithms: KSA (Key Scheduling Algorithm) to initialize the internal state, and PRGA (Pseudo-Random Generation Algorithm) to produce the keystream.',enc:'KSA initializes 256-byte S-box. PRGA steps indices, swaps, outputs keystream bytes.',dec:'Short keys (1-2 bytes) brute-forced. Second output byte biased toward zero (p=1/128).',ic:[.038,.045],weakness:['Second byte biased toward zero','Initial bytes have detectable biases','Fluhrer-Mantin-Shamir broke WEP','Banned from TLS (RFC 7465, 2015)'],hist:'Rivest 1987. Leaked 1994. Once 30% of TLS. Banned 2015.'},
  beaufort:{name:'Beaufort Cipher',cat:'polyalphabetic_substitution',desc:'A variant of the Vigenère cipher that uses subtraction instead of addition. Each plaintext letter is subtracted from the corresponding key letter (modulo 26) to produce the ciphertext. The interesting property is that it\'s self-reciprocal - the same operation both encrypts and decrypts.',enc:'For each letter: ciphertext = (Key - Plaintext) mod 26.',dec:'Same formula (self-inverse). Kasiski/Friedman attacks work identically to Vigenère.',ic:[.038,.055],weakness:['Same as Vigenère','Self-inverse reveals decryption'],hist:'Named after Sir Francis Beaufort.'},
  porta:{name:'Porta Cipher',cat:'polyalphabetic_substitution',desc:'Uses a series of reciprocal alphabets for encryption. The key determines which alphabet to use for each letter, but since the alphabets are reciprocal (symmetric), the same process both encrypts and decrypts. Key letters are grouped in pairs, effectively halving the key length.',enc:'Key pairs select from 13 alphabets swapping A-M with N-Z.',dec:'Similar to Vigenère cracking but effective key length is halved.',ic:[.042,.058],weakness:['Key pairs halve effective key length','Kasiski-style attacks work'],hist:'Giovanni della Porta, 1563.'},
  columnar:{name:'Columnar Transposition',cat:'transposition',desc:'A transposition cipher where the message is written into a grid row by row, then the columns are rearranged according to a keyword. The ciphertext is read column by column in the new order. No letters are substituted, just rearranged.',enc:'Write rows of keyword width. Read columns by sorted keyword order.',dec:'Try column count permutations. Letter frequencies unchanged = transposition giveaway.',ic:[.060,.070],weakness:['Frequencies unchanged','Limited column permutations'],hist:'WWI and WWII. Double transposition used by SOE.'},
  rot47:{name:'ROT47',cat:'modern_obfuscation',desc:'An extension of ROT13 that applies to all printable ASCII characters (from ! to ~). Each character is shifted forward by 47 positions in the ASCII table, wrapping around when necessary. Like ROT13, it\'s self-reversing.',enc:'Each char code 33-126: new = 33 + ((code-33+47) mod 94). Self-inverse.',dec:'Apply same transform. Trivially detected.',ic:[.055,.068],weakness:['No key','Self-inverse','Easily detected'],hist:'Extension of ROT13. Config file obfuscation.'},
  binary:{name:'Binary Encoding',cat:'encoding',desc:'Converts each character into its 8-bit binary representation using only 0s and 1s. Each letter becomes an 8-digit binary number that represents its ASCII code. This is how computers actually store text internally.',enc:'Convert each character to its ASCII code, then to an 8-bit binary string. Pad with leading zeros to 8 digits. Separate bytes with spaces.',dec:'Split on spaces, parse each 8-bit group as base-2, convert to character. Immediately recognizable by containing only 0s, 1s, and spaces in groups of 8.',ic:[0,0],weakness:['Not encryption — trivially reversible','Instantly recognizable pattern (only 0s and 1s)','No key or secret involved'],hist:'Fundamental data representation. Used in computing since the 1940s.'},
  hex:{name:'Hexadecimal Encoding',cat:'encoding',desc:'Represents data using base-16 (hexadecimal) notation with digits 0-9 and letters A-F. Each byte becomes exactly two hex characters, making it a compact way to display binary data in a human-readable format.',enc:'Convert each character to its ASCII code, then to a 2-digit hex string (00-FF).',dec:'Parse each pair of hex characters as base-16, convert to character. Recognizable by even-length strings containing only 0-9 and a-f.',ic:[0,0],weakness:['Not encryption — trivially reversible','Even-length hex-only strings are easily detected','Commonly seen in memory dumps, color codes, and packet captures'],hist:'Standard representation for binary data since early computing. Used in HTML colors (#FF0000), MAC addresses, and debugging.'},
  base64:{name:'Base64 Encoding',cat:'encoding',desc:'Encodes binary data into a text format using 64 printable ASCII characters: A-Z, a-z, 0-9, plus (+) and slash (/). Groups of 3 bytes become 4 characters, with equals signs (=) used for padding when needed.',enc:'Split input into 3-byte groups. Convert each group to four 6-bit indices. Map each index to the Base64 alphabet. Pad with = if the input length is not divisible by 3.',dec:'Map each Base64 character back to its 6-bit value. Recombine into 8-bit bytes. Recognized by the character set and trailing = padding.',ic:[0,0],weakness:['Not encryption — trivially reversible','= padding is a strong detection signal','Character set is distinctive (mixed case + digits + /+)','Data expands by ~33%'],hist:'Defined in RFC 4648. Ubiquitous in email (MIME), data URIs, JSON Web Tokens, and API payloads.'},
  morse:{name:'Morse Code',cat:'encoding',desc:'Encodes letters and numbers as sequences of dots (.) and dashes (-), separated by spaces. Words separated by wider gaps.',enc:'Map each letter/digit to its Morse pattern using the International Morse Code table. Separate letters with single spaces, words with " / " or triple spaces.',dec:'Split on wide gaps for words, narrow gaps for letters. Look up each dot-dash pattern in the reverse Morse table.',ic:[0,0],weakness:['Not encryption — standard public encoding','Dots and dashes are instantly recognizable','Limited character set in output'],hist:'Developed by Samuel Morse and Alfred Vail in the 1830s-1840s. Used in telegraphy for over a century. SOS (... --- ...) remains a universal distress signal.'},
  octal:{name:'Octal Encoding',cat:'encoding',desc:'Represents each character as a 3-digit octal (base-8) number using digits 0-7.',enc:'Convert each character to its ASCII code, then to a 3-digit base-8 string (000-177 for printable ASCII).',dec:'Parse each 3-digit group as base-8, convert to character. Recognized by strings of only 0-7 digits in groups of 3.',ic:[0,0],weakness:['Not encryption — trivially reversible','Only digits 0-7 appear, which is distinctive','Consistent 3-digit grouping is a strong pattern'],hist:'Used in Unix file permissions (chmod 755), early PDP minicomputers, and C/JavaScript escape sequences (\\077).'},
  decimal:{name:'Decimal Encoding',cat:'encoding',desc:'Represents each character as its decimal ASCII code (32-126 for printable), separated by spaces.',enc:'Convert each character to its ASCII decimal value. Separate values with spaces.',dec:'Split on spaces, convert each number to a character. Recognized by space-separated 2-3 digit numbers in the 32-126 range.',ic:[0,0],weakness:['Not encryption — trivially reversible','Space-separated numbers in the printable ASCII range are easy to spot','No key involved'],hist:'The most human-readable byte encoding. ASCII table decimal values are printed on every programmer reference card.'},
  url:{name:'URL Encoding',cat:'encoding',desc:'Encodes unsafe characters in URLs by replacing them with a percent sign followed by their two-digit hexadecimal ASCII code. Spaces become %20, exclamation marks become %21, etc.',enc:'Replace each non-alphanumeric character (except - _ . ~) with %XX where XX is its hex ASCII code. Spaces can become %20 or +.',dec:'Replace each %XX sequence with the character at that hex code value. Recognized by frequent % characters followed by two hex digits.',ic:[0,0],weakness:['Not encryption — standard reversible encoding','% followed by hex pairs is instantly recognizable','Alphanumeric characters pass through unchanged, revealing partial plaintext'],hist:'Defined in RFC 3986 for URIs. Essential for web forms, query strings, and any data transmitted in URLs.'},
  bacon:{name:"Bacon's Cipher",cat:'steganographic_encoding',desc:"Encodes each letter as a 5-character sequence of A's and B's (or any two symbols). 26 letters map to 32 possible 5-bit patterns.",enc:"Map each letter to its 5-bit Bacon code: A=AAAAA, B=AAAAB, C=AAABA, ..., Z=BAAAB. The original cipher hid A/B in two typefaces to conceal the message in innocent-looking text.",dec:"Take the A/B string in groups of 5, look up each group in the Bacon table. Recognized by long strings of only two characters (A and B) with length divisible by 5.",ic:[0,0],weakness:['Only 2 symbols — trivially decoded once identified','5-bit groups make the pattern obvious','Original steganographic hiding in typeface differences is lost in digital text'],hist:"Invented by Sir Francis Bacon in 1605. One of the earliest binary encoding schemes — predating modern binary by 300+ years. Originally a form of steganography."},
  multi_layer:{name:'Multi-Layer Encoding',cat:'encoding',desc:'Multiple encoding layers stacked on top of each other (e.g., Base64 wrapping Hex wrapping plaintext). Requires peeling layers one at a time.',enc:'Apply two or more encodings in sequence. For example: plaintext → hex → base64 produces base64-encoded hex. Each layer wraps the previous output.',dec:'Detect the outermost encoding, decode it, then repeat on the result until no more encoding layers are detected. The system peels layers automatically by checking if each decoded result is itself a recognizable encoding.',ic:[0,0],weakness:['Each layer is individually trivial to reverse','Stacking layers adds obscurity but not security — any automated tool can peel them','The outermost layer is always detectable by its character pattern'],hist:'Common in CTF challenges and obfuscated payloads. Real-world example: Base64-encoded JSON containing hex-encoded values.'},
  rot13:{name:'ROT13',cat:'monoalphabetic_substitution',desc:'A Caesar cipher with a fixed shift of 13 positions. Since there are 26 letters in the alphabet, applying ROT13 twice returns you to the original text - it\'s completely self-reversing.',enc:'Shift each letter by 13 positions.',dec:'Apply ROT13 again — self-inverse.',ic:[.060,.070],weakness:['Fixed key — no secret','Self-inverse','Trivially detected'],hist:'Unix tradition. Used to hide spoilers on Usenet. "ROT13 encryption" is a running joke.'},
  a1z26:{name:'A1Z26 (Letter-Number)',cat:'encoding',desc:'A simple encoding where each letter is replaced by its position in the alphabet: A becomes 1, B becomes 2, C becomes 3, and so on up to Z=26. Numbers are typically separated by spaces or dashes.',enc:'Replace each letter with its alphabet position, space-separated.',dec:'Parse each number 1-26 back to a letter.',ic:[0,0],weakness:['Trivially reversible','Numbers restricted to 1-26 make detection easy'],hist:'Common in geocaching puzzles and elementary ciphers.'},
  playfair:{name:'Playfair Cipher',cat:'polygraphic_substitution',desc:'A cipher that works with pairs of letters instead of individual ones. Uses a 5×5 grid filled with a keyword to encrypt letter pairs according to specific geometric rules: same row (shift right), same column (shift down), or rectangle (swap corners).',enc:'Build 5×5 grid from keyword. Pair letters. Same row: shift right. Same column: shift down. Rectangle: swap corners.',dec:'Reverse the row/column/rectangle rules.',ic:[.045,.060],weakness:['Digraph patterns preserved','Only 25 characters (I=J merge)','Simulated annealing breaks it'],hist:'Invented by Charles Wheatstone 1854. Used by British in Boer War and WWI.'},
  vigenere_autokey:{name:'Vigenère Autokey',cat:'polyalphabetic_substitution',desc:'A variation of the Vigenère cipher where, after using up the initial keyword, the plaintext itself becomes the continuing key. This means the key never repeats, making it stronger than regular Vigenère.',enc:'Start with keyword, then append plaintext as key. Each letter shifted by key letter.',dec:'Decrypt first letters with keyword, then use recovered plaintext as key for remaining.',ic:[.040,.058],weakness:['Known keyword prefix allows progressive decryption','IC analysis is harder than standard Vigenère'],hist:'Blaise de Vigenère described the autokey concept in 1586.'},
  reverse:{name:'Reversed Text',cat:'transposition',desc:'Text written backwards, character by character.',enc:'Reverse the entire string.',dec:'Reverse again. Self-inverse.',ic:[.060,.070],weakness:['Self-inverse','IC and letter frequencies identical to English','Bigram analysis reveals reversed patterns'],hist:'One of the simplest ciphers. Leonardo da Vinci wrote in mirror script.'},
  scytale:{name:'Scytale',cat:'transposition',desc:'An ancient Greek cipher where a message was written on a leather strip wrapped around a wooden rod. When unwrapped, the letters appeared scrambled. Only someone with a rod of the same diameter could read it by rewrapping the strip.',enc:'Write text into rows of cylinder-diameter width, read columns.',dec:'Try different diameters. Letter frequencies unchanged.',ic:[.060,.070],weakness:['Small keyspace (column widths)','Frequencies preserved'],hist:'Used by Spartans ~700 BCE. One of the oldest known ciphers.'},
  route_cipher:{name:'Route Cipher',cat:'transposition',desc:'A transposition cipher where text is written into a rectangular grid row by row, then read out following a specific route pattern like a clockwise spiral, zigzag, or other path. The route pattern serves as the key.',enc:'Fill grid row by row. Read in clockwise spiral from top-left.',dec:'Reverse the spiral read pattern.',ic:[.060,.070],weakness:['Frequencies preserved','Grid dimensions limit keyspace'],hist:'Used in American Civil War battlefield communications.'},
  base32:{name:'Base32 Encoding',cat:'encoding',desc:'Similar to Base64 but uses only 32 characters: A-Z and digits 2-7. This avoids potentially confusing characters and makes it case-insensitive. Commonly used in systems where case-sensitivity or certain characters might cause problems.',enc:'Convert bytes to 5-bit groups, map each to A-Z/2-7 alphabet. Pad with = to multiple of 8.',dec:'Remove padding, convert each character to 5-bit value, reconstruct bytes.',ic:[0,0],weakness:['Not encryption — trivially reversible','Uppercase-only output with restricted digit set is distinctive','= padding signals Base32'],hist:'RFC 4648. Used in TOTP tokens, onion addresses, and DNS-safe encodings.'},
  base58:{name:'Base58 Encoding',cat:'encoding',desc:'An encoding that uses letters and numbers but deliberately omits characters that look similar to avoid confusion when transcribed by hand: no 0 (zero), O (capital o), I (capital i), or l (lowercase L). Popular in cryptocurrency addresses.',enc:'Convert bytes to big integer, repeatedly divide by 58, map remainders to alphabet.',dec:'Reverse the base conversion.',ic:[0,0],weakness:['Not encryption','Absence of 0/O/I/l is a detection signal'],hist:'Invented for Bitcoin addresses. Used in IPFS CIDs and Flickr short URLs.'},
  ascii85:{name:'Ascii85 (Base85)',cat:'encoding',desc:'A more efficient encoding than Base64 that converts every 4 bytes into 5 ASCII characters, achieving better compression. Often wrapped in special delimiters (<~ and ~>) and includes shortcuts like "z" for four zero bytes.',enc:'Group bytes in 4s, convert to base-85 using characters !-u. Special case: four zeros become "z".',dec:'Reverse the base-85 conversion. Strip <~ ~> wrapper.',ic:[0,0],weakness:['Not encryption','<~ ~> wrapper is instantly recognizable','Unusual punctuation-heavy output is distinctive'],hist:'Used in PostScript and PDF for binary data embedding. Also called btoa encoding.'},
  uuencode:{name:'UUEncode',cat:'encoding',desc:'An older Unix encoding format that wraps encoded data in "begin" and "end" markers. Each line starts with a character indicating the line length, followed by the actual encoded data using printable ASCII characters.',enc:'Each line: length prefix + 4 encoded chars per 3 input bytes. Characters offset by 32.',dec:'Parse line-by-line, subtract 32 from each char, reconstruct 3-byte groups.',ic:[0,0],weakness:['Not encryption','begin/end markers and line structure are obvious','Characters 32-95 only'],hist:'Unix-to-Unix encoding from 1980. Replaced by Base64/MIME but still seen in legacy systems.'},
  html_entities:{name:'HTML Entities',cat:'encoding',desc:'Encodes characters as HTML numeric entities in the format &#NUMBER; where NUMBER is the decimal ASCII code. This allows special characters to be safely displayed in HTML without being interpreted as markup.',enc:'Replace each character with &#CODE; where CODE is its charCodeAt value.',dec:'Parse each &#N; and convert N back to a character.',ic:[0,0],weakness:['Not encryption','&#...; pattern is unmistakable','Semicolons and ampersands make detection trivial'],hist:'Defined in HTML specification. Used to display special characters in web pages safely.'},
  bifid:{name:'Bifid Cipher',cat:'fractionation',desc:'A cipher that combines a Polybius square with fractionation. Each letter becomes a pair of coordinates (row, column), then all the rows are listed followed by all the columns. These are then regrouped into new pairs and converted back to letters.',enc:'Map letters to 5×5 grid coordinates. Collect all rows then all columns. Recombine pairs into grid positions.',dec:'Reverse the fractionation process.',ic:[.045,.060],weakness:['Grid-based — 5×5 key matrix has limited keyspace','Period-based patterns can be exploited'],hist:'Invented by Félix Delastelle in 1901.'},
  polybius:{name:'Polybius Square',cat:'encoding',desc:'Each letter is converted to a two-digit coordinate based on its position in a 5×5 grid. For example, if A is at position (1,1), it becomes "11". Since there are only 25 positions, I and J typically share the same spot.',enc:'Map each letter to row-column position in the grid. Output pairs of digits 1-5.',dec:'Parse digit pairs, look up grid positions.',ic:[0,0],weakness:['Not encryption — trivially reversible','Only digits 1-5 appear','Always even-length digit output'],hist:'Invented by the Greek historian Polybius ~150 BCE. Basis for many later ciphers including Bifid and ADFGVX.'},
  adfgvx:{name:'ADFGVX Cipher',cat:'fractionation',desc:'WWI German cipher. 6×6 grid maps 36 characters to pairs of A,D,F,G,V,X. Originally combined with columnar transposition.',enc:'Map each alphanumeric character to a pair from the 6-letter set. Optionally apply columnar transposition.',dec:'Reverse the transposition, then the substitution.',ic:[0,0],weakness:['Only 6 distinct output characters','Column transposition key limits complexity','Broken by Painvin in 1918'],hist:'Used by German army in spring 1918. Extended from ADFGX (5×5) to include digits. Broken by French cryptanalyst Georges Painvin.'},
  tap_code:{name:'Tap Code',cat:'encoding',desc:'A communication method used by prisoners where each letter corresponds to a series of taps. Based on a 5×5 grid, letters are encoded as "row.column" (like 2.3 for H). Originally transmitted by tapping on walls - first the row number, pause, then the column number.',enc:'Map each letter to its 5×5 grid position as R.C format.',dec:'Parse R.C pairs back to grid positions.',ic:[0,0],weakness:['Not encryption — simple grid lookup','K/C merge','Digit pairs 1.1-5.5 are distinctive'],hist:'Used by prisoners of war, especially in Vietnam War POW camps. Based on Polybius square.'},
  phone_keypad:{name:'Phone Keypad',cat:'encoding',desc:'Based on old telephone keypads where each number (2-9) corresponds to 3-4 letters. ABC=2, DEF=3, GHI=4, etc. This creates a lossy encoding since multiple letters map to the same number, making exact decoding impossible without additional context.',enc:'Replace each letter with its keypad digit (2-9).',dec:'Ambiguous — each digit maps to 3-4 letters. First letter of group is used as approximation.',ic:[0,0],weakness:['Lossy — multiple letters per digit','Not encryption','Digits 2-9 only'],hist:'Based on telephone keypad layout standardized in the 1960s. T9 predictive text disambiguated using dictionaries.'},
  nato_phonetic:{name:'NATO Phonetic Alphabet',cat:'encoding',desc:'Replaces each letter with its standardized phonetic word: A becomes "Alpha", B becomes "Bravo", C becomes "Charlie", and so on through "Zulu" for Z. Used to clearly communicate letters over radio or phone where audio quality might be poor.',enc:'Replace each letter with its NATO word, space-separated.',dec:'Map each NATO word back to its letter.',ic:[0,0],weakness:['Not encryption — standard public alphabet','Fixed 26-word vocabulary is instantly recognizable','Word lengths follow a distinctive pattern'],hist:'Adopted by NATO and ICAO in 1956. Used in aviation, military, and radio communications worldwide.'},
  hex_shuffle:{name:'Hex Shuffle',cat:'modern_obfuscation',desc:'Encodes to hexadecimal then randomly shuffles the byte pairs. Same charset as hex but with destroyed positional order.',enc:'Convert to hex, split into 2-char pairs, Fisher-Yates shuffle the pairs.',dec:'Without the shuffle seed, pair order cannot be recovered. Charset is identical to hex.',ic:[0,0],weakness:['Same charset as hex — hard to distinguish without positional analysis','Shuffle seed required for decryption','Byte frequency preserved'],hist:'Used in CTF challenges to create hex-like output that resists standard hex decoding.'},
  plaintext:{name:'Plaintext',cat:'plaintext',desc:'Unencrypted English text. High Index of Coincidence (~0.067), strong n-gram patterns, and letter frequencies matching standard English.',enc:'No transformation applied.',dec:'Already readable. No decryption needed.',ic:[.062,.072],weakness:['All patterns visible','Frequency analysis trivial','No key required'],hist:'The baseline — what every cipher is trying to hide. Identified by high IC, strong bigram correlation, and normal English letter distribution.'},
};

let KB;
async function loadKB(){KB=await KBStore.load();
  for(const[k,seed]of Object.entries(SEED_KB)){if(!KB[k])KB[k]={...seed,stats:{tested:0,cracked:0,avgTime:0},icObs:[],entObs:[],insights:'',discoveries:[]};}
}
async function saveKB(){await KBStore.save(KB);}
// Kick off async KB load so everything that needs KB runs after this resolves.
// We also wait for CentroidStore, ConfusionTracker, and CalibrationTracker to
// finish reading from OPFS so the ML page renders with real data on the first load.
Promise.all([
  loadKB(),
  CentroidStore.load(),
  ConfusionTracker.load(),
  CalibrationTracker.load(),
  ModelStore.load(mlModel)
]).then(async ()=>{syncAllStats();await renderKB();await renderML();});

// ── UNIFIED STATS: single source of truth from KB ──
function syncAllStats(){
  if(typeof KB==='undefined'||!KB)return;
  let totalTested=0,totalCorrect=0,totalDiscoveries=0;
  const entries=Object.entries(KB);
  for(const[k,e]of entries){
    totalTested+=(e.stats?.tested||0);
    totalCorrect+=(e.stats?.cracked||0);
    totalDiscoveries+=(e.discoveries||[]).length;
  }
  // Training page — show total generated training samples, not eval test count
  if($('tsT'))DataStore.getCount().then(n=>{ if($('tsT'))$('tsT').textContent=n.toLocaleString(); });
  // Push to KB page
  if($('kbT'))$('kbT').textContent=entries.length;
  if($('kbD'))$('kbD').textContent=totalDiscoveries;
  if($('kbTe'))$('kbTe').textContent=totalTested;
  if($('kbC'))$('kbC').textContent=totalCorrect;
  // Push to ML page
  if($('mlN'))$('mlN').textContent=mlModel.total||0;
  if($('mlK'))$('mlK').textContent=mlModel.classes?mlModel.classes.length:0;
  if($('mlS')){$('mlS').textContent=mlModel.trained?'TRAINED':'UNTRAINED';$('mlS').style.color=mlModel.trained?'var(--accent)':'var(--red)';}
}

// ═══════════════════════════════════════════════════════════════════════
//  FEATURE DESCRIPTIONS + INTERACTIVE TOOLTIPS
// ═══════════════════════════════════════════════════════════════════════

const FEAT_INFO={
  ic:{name:'Index of Coincidence',desc:'Probability that two randomly chosen letters from the text are the same. Measures how "peaked" the letter frequency distribution is.',
    interpret:v=>v>.062?'Close to English (~0.067) — likely plaintext, Caesar, substitution, or transposition.':v>.048?'Between English and random — suggests polyalphabetic cipher (Vigenère, Beaufort) with a short key.':'Near random (~0.038) — strong polyalphabetic cipher (long Vigenère key, Enigma) or non-alphabetic encryption.'},
  'chi²':{name:'Chi-Squared Distance',desc:'Measures how far the letter frequencies deviate from standard English. Lower = closer to English.',
    interpret:v=>v<15?'Very close to English letter distribution. Text is either plaintext or a cipher that preserves frequency (Caesar, transposition).':v<50?'Moderate deviation. Consistent with a shifted or partially scrambled alphabet.':'High deviation from English. Likely polyalphabetic encryption, XOR, or non-English source text.'},
  corr:{name:'Frequency Correlation',desc:'Pearson correlation between observed letter frequencies and expected English frequencies. Ranges from -1 to +1.',
    interpret:v=>v>.8?'Strong positive correlation — frequency distribution closely matches English.':v>.4?'Moderate correlation — some English structure preserved, possibly shifted.':v>0?'Weak correlation — frequencies are substantially different from English.':'Negative or zero correlation — no resemblance to English frequency distribution.'},
  freqCorr:{name:'Frequency Correlation',desc:'Pearson correlation between observed letter frequencies and expected English frequencies. Ranges from -1 to +1.',
    interpret:v=>v>.8?'Strong positive correlation — frequency distribution closely matches English.':v>.4?'Moderate correlation — some English structure preserved, possibly shifted.':v>0?'Weak correlation — frequencies substantially different from English.':'Negative or zero — no resemblance to English frequency distribution.'},
  entropy:{name:'Shannon Entropy',desc:'Measures the information density / randomness of the letter distribution (bits per character). Max for 26 letters ≈ 4.7 bits.',
    interpret:v=>v<3.8?'Low entropy — some letters dominate heavily. Typical of short texts or very skewed distributions.':v<4.2?'Moderate entropy — normal range for English text and monoalphabetic ciphers.':'High entropy — distribution is nearly uniform. Typical of polyalphabetic ciphers or byte-level encryption.'},
  normEnt:{name:'Normalized Entropy',desc:'Shannon entropy divided by the theoretical maximum. 1.0 = perfectly uniform distribution, 0.0 = single repeated character.',
    interpret:v=>v>.95?'Near-uniform letter distribution. Strong indicator of polyalphabetic or byte-level encryption.':v>.85?'Moderately uniform. Normal range for English or monoalphabetic ciphers.':'Concentrated distribution — few letters carry most of the frequency weight.'},
  distinct:{name:'Distinct Character Ratio',desc:'Fraction of the 26 alphabet letters that appear at least once. Higher = more variety.',
    interpret:v=>v>.9?'Nearly all 26 letters present — typical of longer texts regardless of cipher type.':v>.6?'Most letters present. Normal for medium-length texts.':'Many letters missing — either very short text or a cipher that maps to a restricted alphabet.'},
  maxFreq:{name:'Max Letter Frequency',desc:'Frequency of the single most common letter. In English, "E" appears ~12.7% of the time.',
    interpret:v=>v>.12?'One letter dominates — consistent with English or a monoalphabetic cipher where the peak is shifted.':v>.06?'Moderate peak — could be polyalphabetic with a short key or transposition.':'Very flat distribution — strong polyalphabetic encryption or random data.'},
  minFreq:{name:'Min Letter Frequency',desc:'Frequency of the rarest occurring letter.',
    interpret:v=>v<.005?'Some letters are very rare or absent — normal for English (Q, Z, X are rare).':'Even the rarest letter appears frequently — suggests a flattening cipher or very long uniform text.'},
  freqStd:{name:'Frequency Std Dev',desc:'Standard deviation of all 26 letter frequencies. Higher = more variation between common and rare letters.',
    interpret:v=>v>.03?'High variation — peaked distribution typical of English or monoalphabetic substitution.':v>.015?'Moderate variation — could be polyalphabetic with a short key.':'Low variation — nearly flat frequency distribution. Strong polyalphabetic or random.'},
  bigramDiv:{name:'Bigram Diversity',desc:'Ratio of unique bigrams (letter pairs) to total possible. Higher = more varied letter pair combinations.',
    interpret:v=>v>.7?'High bigram diversity — many unique letter pairs. Normal for longer or well-mixed text.':v>.4?'Moderate diversity. Typical range for most cipher types.':'Low diversity — repeated patterns. Could indicate short text or a cipher with limited output alphabet.'},
  commonBi:{name:'Common Bigram Score',desc:'Fraction of bigrams that match the top 20 English bigrams (TH, HE, IN, ER, AN, etc.).',
    interpret:v=>v>.08?'Many common English bigrams present — strong indicator of English plaintext or transposition cipher.':v>.03?'Some English bigrams — partial English structure remains (Caesar, simple substitution).':'Very few common bigrams — polyalphabetic encryption or non-English text.'},
  commonTri:{name:'Common Trigram Score',desc:'Fraction of trigrams matching the top 10 English trigrams (THE, AND, ING, etc.).',
    interpret:v=>v>.04?'English trigrams detected — text retains word-level structure. Likely plaintext or transposition.':v>.01?'Occasional English trigrams — some structure preserved.':'No common trigrams — text structure is fully disrupted by encryption.'},
  repTri:{name:'Repeated Trigram Ratio',desc:'Fraction of trigrams that appear more than once. Repeated trigrams are the basis of Kasiski examination for cracking Vigenère.',
    interpret:v=>v>.15?'Many repeated trigrams — normal for English. In ciphertext, this enables Kasiski key-length detection.':v>.05?'Some repetition. In Vigenère ciphertext, these spacings reveal the key length.':'Few repeats — either short text or a cipher that eliminates repetition patterns.'},
  ic_kl2:{name:'IC at Key Length 2',desc:'Average IC when text is split into 2 interleaved streams. High values suggest the true key length divides 2.',interpret:v=>v>.055?'IC rises toward English normal — key length 2 (or a multiple) is plausible.':'IC stays low — key length is probably not 2.'},
  ic_kl3:{name:'IC at Key Length 3',desc:'Average IC when split into 3 streams.',interpret:v=>v>.055?'IC rises — key length 3 is a candidate.':'IC stays low — key length probably not 3.'},
  ic_kl4:{name:'IC at Key Length 4',desc:'Average IC when split into 4 streams.',interpret:v=>v>.055?'IC rises — key length 4 is a candidate.':'IC stays low — key length probably not 4.'},
  ic_kl5:{name:'IC at Key Length 5',desc:'Average IC when split into 5 streams.',interpret:v=>v>.055?'IC rises — key length 5 is a candidate.':'IC stays low — key length probably not 5.'},
  ic_kl6:{name:'IC at Key Length 6',desc:'Average IC when split into 6 streams.',interpret:v=>v>.055?'IC rises — key length 6 is a candidate.':'IC stays low — key length probably not 6.'},
  ic_kl7:{name:'IC at Key Length 7',desc:'Average IC when split into 7 streams.',interpret:v=>v>.055?'IC rises — key length 7 is a candidate.':'IC stays low — key length probably not 7.'},
  maxIC:{name:'Max IC Across Key Lengths',desc:'The highest IC found when splitting at key lengths 2–7. The key length that produces the highest IC is the most likely true key length.',
    interpret:v=>v>.06?'Strong peak — the best key length produces near-English IC, confirming polyalphabetic cipher with that key length.':v>.045?'Moderate peak — some polyalphabetic structure detected but key length may be longer than 7.':'No key length produces high IC — either monoalphabetic, very long key, or non-alphabetic cipher.'},
  ac1:{name:'Autocorrelation (offset 1)',desc:'Fraction of adjacent letter pairs that are identical. Measures local repetition patterns.',interpret:v=>v>.05?'Above random chance — some local repetition structure.':'Near or below random (~0.038) — no adjacent-letter pattern.'},
  ac2:{name:'Autocorrelation (offset 2)',desc:'Fraction of letters matching 2 positions later.',interpret:v=>v>.05?'Pattern at distance 2 — could indicate key length 2.':'No pattern at offset 2.'},
  ac3:{name:'Autocorrelation (offset 3)',desc:'Fraction of letters matching 3 positions later.',interpret:v=>v>.05?'Pattern at distance 3.':'No pattern at offset 3.'},
  ac4:{name:'Autocorrelation (offset 4)',desc:'Fraction matching 4 positions later.',interpret:v=>v>.05?'Pattern at distance 4.':'No pattern at offset 4.'},
  ac5:{name:'Autocorrelation (offset 5)',desc:'Fraction matching 5 positions later.',interpret:v=>v>.05?'Pattern at distance 5.':'No pattern at offset 5.'},
  ac6:{name:'Autocorrelation (offset 6)',desc:'Fraction matching 6 positions later.',interpret:v=>v>.05?'Pattern at distance 6.':'No pattern at offset 6.'},
  vowels:{name:'Vowel Ratio',desc:'Fraction of alphabetic characters that are vowels (a, e, i, o, u). English averages ~40%.',
    interpret:v=>v>.35?'Near-normal vowel ratio — consistent with English or a transposition cipher (which preserves letter identities).':v>.25?'Somewhat low — could be a substitution cipher that remaps vowels to consonants.':'Very low or very high vowel ratio — alphabet has been substantially rearranged.'},
  spaces:{name:'Has Spaces',desc:'Whether the text contains space characters (1.0 = yes, 0.0 = no).',interpret:v=>v>0?'Spaces present — word boundaries preserved. Rules out most block cipher outputs.':'No spaces — could be concatenated ciphertext or a cipher that strips whitespace.'},
  upper:{name:'Uppercase Ratio',desc:'Fraction of alphabetic characters that are uppercase.',interpret:v=>v>.9?'Almost all uppercase — typical of Enigma output, Columnar transposition, or Playfair.':v>.4?'Mixed case — normal English text or a cipher that preserves case.':'Mostly lowercase — typical of processed/normalized text.'},
  logLen:{name:'Log Length',desc:'Log₂ of the alphabetic character count. Captures text size on a compressed scale.',interpret:v=>v>6?'Long text (64+ chars) — statistical features are reliable at this length.':v>4?'Medium text (16-64 chars) — features are somewhat reliable but short-text effects may appear.':'Short text (<16 chars) — statistical features are unreliable. Classification confidence should be low.'},
  byteEnt:{name:'Byte Entropy',desc:'Shannon entropy computed over all 256 possible byte values (not just a-z). Captures randomness in the full byte range.',
    interpret:v=>v>7?'Very high byte entropy — near-random byte distribution. Typical of XOR, RC4, or AES-encrypted data.':v>5?'Moderate byte entropy — mixed printable and non-printable characters.':'Low byte entropy — mostly printable ASCII text with limited byte variety.'},
  byteEntropy:{name:'Byte Entropy',desc:'Shannon entropy over all 256 byte values.',interpret:v=>v>7?'Near-random bytes — XOR, RC4, or block cipher output.':v>5?'Moderate — mixed printable/non-printable.':'Low — mostly ASCII text.'},
  printable:{name:'Printable ASCII Ratio',desc:'Fraction of bytes in the printable range (32–126). English text is nearly 100% printable.',
    interpret:v=>v>.95?'Almost all printable — normal text or a cipher that stays within ASCII.':v>.5?'Mixed — some non-printable bytes. Could be XOR or RC4 with a key that pushes bytes out of printable range.':'Mostly non-printable — raw encrypted bytes. Typical of block ciphers or strong XOR encryption.'},
  printableRatio:{name:'Printable ASCII Ratio',desc:'Fraction of bytes in the printable range (32–126).',interpret:v=>v>.95?'Almost all printable ASCII.':v>.5?'Mixed printable/non-printable bytes.':'Mostly non-printable — raw encrypted data.'},
  control:{name:'Control Character Ratio',desc:'Fraction of bytes in the 0–31 range (null, tab, newline, etc.).',interpret:v=>v<.01?'No control characters — normal text.':v<.05?'A few control characters — could be encoding artifacts.':'Many control characters — likely binary/encrypted data, not text.'},
  highByte:{name:'High Byte Ratio',desc:'Fraction of bytes with value 128–255 (outside standard ASCII).',
    interpret:v=>v<.01?'No high bytes — pure ASCII text.':v<.1?'Some high bytes — could be UTF-8, accented characters, or light XOR artifacts.':'Many high bytes — text has been XOR/RC4 encrypted or contains binary data.'},
  highByteRatio:{name:'High Byte Ratio',desc:'Fraction of bytes with value 128–255.',interpret:v=>v<.01?'Pure ASCII.':v<.1?'Some high bytes — UTF-8 or light encryption.':'Many high bytes — binary or encrypted data.'},
  nulls:{name:'Null Byte Ratio',desc:'Fraction of bytes that are 0x00. Null bytes are common in binary encrypted output but absent in text.',interpret:v=>v<.001?'No null bytes — normal for text.':'Null bytes present — indicates binary encrypted data, not text-based cipher output.'},
  byteStd:{name:'Byte Frequency Std Dev',desc:'Standard deviation of byte value frequencies across all 256 possible values. Low = uniform (random), high = peaked (text).',interpret:v=>v>.01?'Peaked byte distribution — text-like data where some bytes dominate.':'Flat byte distribution — bytes are uniformly distributed, suggesting strong encryption or random data.'},
  distinctByte:{name:'Distinct Byte Ratio',desc:'Fraction of the 256 possible byte values that actually appear in the text.',interpret:v=>v>.5?'Many distinct byte values — wide byte range used. Common in encrypted binary data.':v>.2?'Moderate variety — normal for text with some non-ASCII characters.':'Few distinct bytes — limited character set, typical of pure alphabetic text.'},
  spaceRatio:{name:'Space Byte Ratio',desc:'Fraction of bytes that are the space character (0x20). English text averages ~15-18% spaces.',interpret:v=>v>.12?'Normal space frequency — word boundaries present, suggesting readable text.':v>.03?'Some spaces — partial word structure.':'Very few or no spaces — concatenated ciphertext or binary data.'},
  digitRatio:{name:'Digit Ratio',desc:'Fraction of bytes that are digit characters (0-9).',interpret:v=>v>.3?'Many digits — could be hex encoding, decimal encoding, or numeric data.':v>.05?'Some digits — normal mixed text.':'Few or no digits — pure alphabetic text.'},
  punctRatio:{name:'Punctuation Ratio',desc:'Fraction of bytes that are punctuation characters.',interpret:v=>v>.15?'Heavy punctuation — could be ROT47 output (which transforms digits/punctuation) or encoded data.':v>.03?'Normal punctuation level for English text.':'Very little punctuation — stripped or purely alphabetic.'},
  icRange:{name:'IC Range (Observed)',desc:'Min and max IC values observed across all test samples for this cipher type.',interpret:v=>'Narrow range = IC alone can identify this type; wide = needs multi-feature analysis.'},

  // Advanced Statistical Features - Higher-order pattern analysis
  
  // N-gram analysis group
  bigramEnt:{name:'Bigram Entropy',desc:'Shannon entropy over letter-pair frequencies, normalized. Captures 2nd-order structure unigram entropy misses.',
    interpret:v=>v>.9?'Near-uniform bigram distribution — strong polyalphabetic or long-key cipher.':v>.7?'High bigram diversity — moderate encryption or long text.':v>.5?'Some English bigram patterns preserved (transposition or Caesar).':'Highly structured bigrams — plaintext or very short text.'},
  trigramEnt:{name:'Trigram Entropy',desc:'Shannon entropy over letter-triplet frequencies, normalized. Higher-order structure measure than bigram entropy.',
    interpret:v=>v>.85?'Near-uniform trigrams — encryption has fully disrupted word structure.':v>.6?'Moderate trigram variety.':'Low — structured trigram patterns remain, suggesting plaintext or simple cipher.'},
  quadHitRate:{name:'Quadgram Hit Rate',desc:'Fraction of 4-letter windows matching top English quadgrams (TION, THER, THAT, etc.). Much more sensitive than trigrams for residual English.',
    interpret:v=>v>.03?'English quadgrams detected — word-level structure remains. Likely plaintext or transposition.':v>.01?'Some quadgrams — partial structure preserved.':'No common quadgrams — text structure fully disrupted.'},
  quadScore:{name:'Quadgram Weighted Score',desc:'Sum of log-probability scores for matching quadgrams, normalized. Weighted version of hit rate gives more credit to common quadgrams.',
    interpret:v=>v>.05?'Strong English word patterns detected.':v>.01?'Some English structure.':'No significant English quadgram signal.'},
  longestRepeat:{name:'Longest Repeated Substring',desc:'Length of longest substring appearing 2+ times, divided by total length. Vigenère ciphertext has characteristically long repeats (Kasiski basis).',
    interpret:v=>v>.15?'Long repeats — normal for English or exploitable via Kasiski attack.':v>.05?'Moderate repetition.':'Very short repeats — highly random, typical of strong encryption.'},
  uniqueBiRatio:{name:'Unique Bigram Ratio',desc:'Number of unique bigrams divided by total bigrams. Low ratio means many repeated bigram patterns.',
    interpret:v=>v>.8?'Most bigrams are unique — diverse text or strong encryption.':v>.5?'Moderate uniqueness.':'Many repeated bigrams — short text or constrained alphabet.'},
  hapaxBiRatio:{name:'Hapax Bigram Ratio',desc:'Fraction of unique bigrams that appear exactly once (hapax legomena of bigrams). High values indicate sparse, diverse bigram usage.',
    interpret:v=>v>.7?'Most bigrams appear only once — typical of encrypted or very varied text.':v>.4?'Moderate hapax ratio.':'Many bigrams repeat — structured text or short key cipher.'},
  bigramSkew:{name:'Bigram Frequency Skewness',desc:'Skewness of bigram count distribution. High positive skew means a few bigrams dominate.',
    interpret:v=>v>3?'Highly skewed — a few bigrams appear much more than others (English-like).':v>1?'Moderate skew.':'Near-symmetric distribution — encryption has flattened bigram frequencies.'},
  maxConCluster:{name:'Max Consonant Cluster',desc:'Length of longest consecutive consonant run, divided by text length. English has natural consonant cluster limits.',
    interpret:v=>v>.1?'Long consonant cluster — unusual for English, could indicate non-English or cipher output.':v>.03?'Normal consonant clustering for English text.':'Short clusters — heavily vowel-mixed or very short text.'},
  vcTransRate:{name:'Vowel-Consonant Transition Rate',desc:'Fraction of consecutive letter pairs that switch between vowel and consonant. English averages ~60%.',
    interpret:v=>v>.55?'High V-C transition rate — consonant-vowel alternation typical of natural language.':v>.35?'Moderate transitions.':'Low transitions — unusual letter clustering, possibly cipher output or encoding.'},

  // C. IC & key-length probing
  ic_kl8:{name:'IC at Key Length 8',desc:'Average IC when split into 8 streams.',interpret:v=>v>.055?'IC rises — key length 8 is a candidate.':'IC stays low — key length probably not 8.'},
  ic_kl9:{name:'IC at Key Length 9',desc:'Average IC when split into 9 streams.',interpret:v=>v>.055?'IC rises — key length 9 is a candidate.':'IC stays low.'},
  ic_kl10:{name:'IC at Key Length 10',desc:'Average IC when split into 10 streams.',interpret:v=>v>.055?'IC rises — key length 10 is a candidate.':'IC stays low.'},
  ic_kl11:{name:'IC at Key Length 11',desc:'Average IC when split into 11 streams.',interpret:v=>v>.055?'IC rises — key length 11 is a candidate.':'IC stays low.'},
  bestKL:{name:'Best Key Length (normalized)',desc:'Which key length (2-11) produces the highest IC, divided by 11. Directly encodes the Friedman/Kasiski signal for the ML model.',
    interpret:v=>{const kl=Math.round(v*11);return`Best key length estimate: ${kl}. The model uses this to distinguish polyalphabetic ciphers by key length.`;}},
  icVariance:{name:'IC Variance Across Key Lengths',desc:'Standard deviation of IC values across key lengths 2-11. High variance means one key length is a clear winner.',
    interpret:v=>v>.01?'Clear IC peak — one key length stands out, strong polyalphabetic signal.':v>.005?'Moderate variance — some key-length preference detected.':'Flat IC curve — no key length is favored. Monoalphabetic or very long key.'},
  friedmanKL:{name:'Friedman Key Length',desc:'Friedman test estimate of key length based on overall IC, normalized to 0-1.',
    interpret:v=>{const kl=Math.round(v*20);return kl<=1?'Friedman estimates monoalphabetic (key length 1).':kl<=5?`Friedman estimates key length ~${kl} — short polyalphabetic key.`:`Friedman estimates key length ~${kl} — longer key, harder to crack.`;}},

  // D. Autocorrelation
  ac7:{name:'Autocorrelation (offset 7)',desc:'Fraction of letters matching 7 positions later.',interpret:v=>v>.05?'Pattern at distance 7.':'No pattern at offset 7.'},
  ac8:{name:'Autocorrelation (offset 8)',desc:'Fraction of letters matching 8 positions later.',interpret:v=>v>.05?'Pattern at distance 8.':'No pattern at offset 8.'},
  acArgmax:{name:'AC Argmax (normalized)',desc:'Which offset (1-8) has the highest autocorrelation, divided by 8. Encodes the dominant periodicity.',
    interpret:v=>{const off=Math.round(v*8);return`Strongest autocorrelation at offset ${off}. For polyalphabetic ciphers, this often equals the key length.`;}},

  // E. Structural shape
  dev_e:{name:'Deviation: E',desc:'Absolute difference between observed E frequency and English expected (12.7%).',interpret:v=>v<.02?'E frequency is near English normal.':v<.05?'Moderate E deviation.':'Large E deviation — E is shifted or suppressed.'},
  dev_t:{name:'Deviation: T',desc:'Absolute difference between observed T frequency and English expected (9.1%).',interpret:v=>v<.02?'T frequency near normal.':v<.05?'Moderate deviation.':'Large T deviation.'},
  dev_a:{name:'Deviation: A',desc:'Absolute difference between observed A frequency and English expected (8.2%).',interpret:v=>v<.02?'A frequency near normal.':v<.05?'Moderate deviation.':'Large A deviation.'},
  dev_o:{name:'Deviation: O',desc:'Absolute difference between observed O frequency and English expected (7.5%).',interpret:v=>v<.02?'O frequency near normal.':v<.05?'Moderate deviation.':'Large O deviation.'},
  devSum:{name:'Total Freq Deviation',desc:'Sum of absolute deviations for all 26 letters from English. Single number summarizing overall frequency distance.',
    interpret:v=>v<.3?'Very close to English frequencies overall.':v<.8?'Moderate total deviation — some structure preserved.':'High total deviation — frequencies are very different from English.'},
  freqKurtosis:{name:'Frequency Kurtosis',desc:'Excess kurtosis of the 26 letter frequencies. Positive = peaked (English-like), negative = flat (encrypted).',
    interpret:v=>v>2?'Highly peaked — a few letters dominate, typical of English or monoalphabetic substitution.':v>0?'Moderate peakedness.':'Flat or platykurtic — frequencies are uniformly spread, typical of polyalphabetic encryption.'},
  charClassTrans:{name:'Char-Class Transition Rate',desc:'Rate of switches between character classes (upper/lower/digit/space/symbol). High for Base64, low for pure-alpha ciphers.',
    interpret:v=>v>.6?'Very high transitions — mixed charset typical of Base64 or URL encoding.':v>.3?'Moderate — normal English with spaces and punctuation.':v>.1?'Low — single character class dominates.':'Almost no transitions.'},
  wordLenMean:{name:'Word Length Mean',desc:'Average word length (chars between spaces), normalized. Longer words suggest technical text or encoding artifacts.',
    interpret:v=>v>.3?'Long average word length — could be concatenated ciphertext or technical terms.':v>.15?'Normal English word length (~5 chars).':'Short words — simple vocabulary or encoding with frequent separators.'},
  wordLenStd:{name:'Word Length Std Dev',desc:'Variation in word lengths, normalized. English has moderate variation; encodings with fixed-width blocks have low variation.',
    interpret:v=>v>.15?'Highly varied word lengths — natural language pattern.':v>.05?'Moderate variation.':'Very uniform word lengths — possible fixed-width encoding blocks.'},

  // F. Byte-level
  byteBigramEnt:{name:'Byte Bigram Entropy',desc:'Shannon entropy over consecutive byte pairs (65536 possible), normalized. Captures sequential byte structure.',
    interpret:v=>v>.85?'Near-random byte pairs — RC4 or AES output.':v>.6?'Moderate byte-pair entropy.':'Structured byte sequences — text-based content.'},
  byteDeltaStd:{name:'Byte Delta Std Dev',desc:'Std dev of |byte[i+1]-byte[i]|, normalized. English has low delta-std (ASCII clustering). XOR preserves this; RC4 destroys it.',
    interpret:v=>v>.5?'High byte jumps — RC4 or strong XOR.':v>.2?'Moderate variation.':'Low variation — consecutive bytes cluster (text-like).'},
  byteDeltaMean:{name:'Byte Delta Mean',desc:'Average absolute difference between consecutive bytes, normalized. Low for text, high for random/encrypted data.',
    interpret:v=>v>.4?'Large average byte jumps — encrypted or binary data.':v>.15?'Moderate jumps — mixed content.':'Small jumps — bytes cluster near each other, typical of ASCII text.'},
  rlCompRatio:{name:'Run-Length Compression',desc:'Distinct runs / total length. 1.0 = every byte differs (random); low = many repeated consecutive bytes.',
    interpret:v=>v>.95?'Almost no consecutive repeats — high randomness.':v>.7?'Few repeated runs.':'Many consecutive repeated bytes — encoding pattern or structured data.'},
  byteChiNorm:{name:'Byte Chi² (normalized)',desc:'Chi-squared testing uniform 256-byte distribution, divided by length. Low = uniform (encrypted).',
    interpret:v=>v<1?'Near-uniform bytes — strong encryption.':v<5?'Moderately non-uniform.':'Highly non-uniform — text-based content.'},
  byteSkew:{name:'Byte Freq Skewness',desc:'Skewness of byte frequency distribution. Positive = few bytes dominate; zero = symmetric.',
    interpret:v=>v>2?'High skew — text with common characters.':v>.5?'Moderate skew.':'Near-symmetric — encryption or encoding.'},
  byteKurtosis:{name:'Byte Freq Kurtosis',desc:'Excess kurtosis of byte frequencies. High = sharp peak (text); low = flat (encrypted).',
    interpret:v=>v>5?'Very peaked — a few byte values dominate heavily.':v>1?'Moderate peak.':'Flat distribution — encrypted or random data.'},
  upperByte:{name:'Uppercase Byte Ratio',desc:'Fraction of bytes in A-Z (65-90). Distinguishes all-uppercase cipher outputs.',
    interpret:v=>v>.8?'Almost all uppercase — Enigma, Columnar, or Playfair output.':v>.3?'Significant uppercase — mixed case or Base64.':'Little to no uppercase.'},
  lowerByte:{name:'Lowercase Byte Ratio',desc:'Fraction of bytes in a-z (97-122).',
    interpret:v=>v>.8?'Almost all lowercase — normalized text.':v>.3?'Significant lowercase.':'Few lowercase bytes.'},
  mixedCase:{name:'Mixed-Case Balance',desc:'min(upper,lower)/max(upper,lower). High for Base64, low for case-unified ciphers.',
    interpret:v=>v>.7?'Balanced case mix — typical of Base64.':v>.3?'Moderate mix — normal English.':'One case dominates.'},

  // G. Positional & regional
  firstIsPct:{name:'First Byte is %',desc:'Whether first character is % (percent). URL-encoded strings frequently start with %.',
    interpret:v=>v>0?'Starts with % — strong URL encoding indicator.':'Does not start with %.'},
  firstIsDigit:{name:'First Byte is Digit',desc:'Whether first character is a digit. Numeric encodings (binary, octal, decimal, hex) often start with digits.',
    interpret:v=>v>0?'Starts with digit — compatible with numeric encoding.':'Does not start with digit.'},
  qEnt1:{name:'Quarter 1 Entropy',desc:'Shannon entropy of the first quarter of alphabetic text.',interpret:v=>v>4?'High entropy in first quarter.':v>3.5?'Moderate.':'Low entropy in first quarter.'},
  qEnt2:{name:'Quarter 2 Entropy',desc:'Shannon entropy of the second quarter.',interpret:v=>v>4?'High.':v>3.5?'Moderate.':'Low.'},
  qEnt3:{name:'Quarter 3 Entropy',desc:'Shannon entropy of the third quarter.',interpret:v=>v>4?'High.':v>3.5?'Moderate.':'Low.'},
  qEnt4:{name:'Quarter 4 Entropy',desc:'Shannon entropy of the fourth quarter.',interpret:v=>v>4?'High.':v>3.5?'Moderate.':'Low.'},
  qEntStd:{name:'Quarter Entropy Std Dev',desc:'Std dev of entropy across 4 quarters. Low = uniform encryption; high = positional variation.',
    interpret:v=>v<.1?'Very uniform entropy across text.':v<.3?'Moderate variation.':'High variation — different regions have different properties.'},
  qEntRange:{name:'Quarter Entropy Range',desc:'Max minus min quarter entropy.',
    interpret:v=>v<.2?'Tight range — uniform encryption.':v<.5?'Moderate range.':'Wide range — heterogeneous text.'},
  halfByteEnt1:{name:'First-Half Byte Entropy',desc:'Byte entropy of the first half of the input.',interpret:v=>v>6?'High byte entropy in first half.':v>4?'Moderate.':'Low.'},
  halfByteEnt2:{name:'Second-Half Byte Entropy',desc:'Byte entropy of the second half.',interpret:v=>v>6?'High.':v>4?'Moderate.':'Low.'},
  halfByteEntDiff:{name:'Half Byte Entropy Diff',desc:'First-half minus second-half byte entropy. Non-zero means entropy changes across the text.',
    interpret:v=>Math.abs(v)>.5?'Significant entropy difference between halves — mixed content or appended data.':'Similar entropy in both halves — consistent content.'},
  byteMono:{name:'Byte Monotonicity',desc:'Fraction of consecutive byte pairs where byte[i+1] >= byte[i]. 0.5 for random, higher for sorted-like data.',
    interpret:v=>v>.6?'More ascending than descending bytes — possible sorted or structured data.':v>.4?'Near random ordering.':'More descending — unusual pattern.'},
  maxRunRatio:{name:'Max Same-Byte Run',desc:'Longest consecutive identical byte run divided by total length.',
    interpret:v=>v>.1?'Long run of identical bytes — possible padding, encoding artifact, or repeated character.':v>.02?'Short runs.':'No significant runs — varied byte content.'},
  byteRange:{name:'Byte Value Range',desc:'(max byte - min byte) / 255. How much of the 0-255 range is actually used.',
    interpret:v=>v>.9?'Full byte range used — binary or encrypted data.':v>.5?'Wide range.':'Narrow range — text restricted to a small byte window.'},
  byteMedian:{name:'Byte Median',desc:'Median byte value, normalized. English text has median ~100 (lowercase letters). Encrypted data ~128.',
    interpret:v=>{const m=Math.round(v*255);return m>120?'High median — bytes spread across upper range, typical of encrypted data.':m>90?'Median in lowercase ASCII range — text-like.':'Low median — mostly low byte values.';}},
  byteIQR:{name:'Byte Interquartile Range',desc:'IQR (75th - 25th percentile) of byte values, normalized. Measures spread of the middle 50% of bytes.',
    interpret:v=>v>.5?'Wide IQR — bytes spread broadly, typical of encrypted data.':v>.2?'Moderate spread — normal for mixed text.':'Narrow IQR — bytes concentrated in a small range.'},

  // H. Pattern/charset/meta
  lenMod6:{name:'Length mod 6 = 0',desc:'Whether length is divisible by 6. Various block sizes use this.',interpret:v=>v>0?'Divisible by 6.':'Not divisible by 6.'},
  isAlpha:{name:'Alpha-Only Flag',desc:'Whether input (sans whitespace) is purely alphabetic.',
    interpret:v=>v>0?'Alpha-only — classical cipher or Bacon encoding.':'Non-alpha chars present.'},
  isHex:{name:'Hex-Compatible',desc:'Whether input is only hex characters (0-9, a-f, A-F).',
    interpret:v=>v>0?'Hex-compatible character set.':'Contains non-hex characters.'},
  isBinary:{name:'Binary-Compatible',desc:'Whether input is only 0s and 1s.',
    interpret:v=>v>0?'Binary-compatible.':'Not binary.'},
  isBase64:{name:'Base64-Compatible',desc:'Whether input matches Base64 charset (A-Z, a-z, 0-9, +, /, =).',
    interpret:v=>v>0?'Base64-compatible.':'Not Base64 charset.'},
  isBacon:{name:'Bacon-Compatible',desc:'Whether input is only A/B characters.',
    interpret:v=>v>0?'Only A and B — strong Bacon cipher signal.':'Not Bacon-compatible.'},
  isOctal:{name:'Octal-Compatible',desc:'Whether input is only digits 0-7.',
    interpret:v=>v>0?'Octal-compatible character set.':'Contains digits > 7 or non-digits.'},
  encPreCheck:{name:'Encoding Pre-Check',desc:'Numeric output of regex detector (0=plain..8=bacon). Gives ML hand-crafted rules as a hint feature.',
    interpret:v=>{const names=['plaintext','binary','octal','decimal','hex','base64','url','morse','bacon'];return`Pre-check: ${names[Math.round(v*8)]||'unknown'}.`;}},
  rawLenSig:{name:'Raw Length (sigmoid)',desc:'Text length compressed via sigmoid. Approaches 1.0 for long texts.',
    interpret:v=>v>.9?'Long text (900+ chars) — features reliable.':v>.5?'Medium text (~100 chars).':'Short text — statistical features may be noisy.'},
  logRawLen:{name:'Log Raw Length',desc:'Log₂ of total character count. Captures text size on compressed scale.',
    interpret:v=>v>8?'Long text (256+ chars).':v>5?'Medium (32+ chars).':'Short text.'},
  alphaRatio:{name:'Alpha-to-Total Ratio',desc:'Fraction of all characters that are alphabetic. High for ciphers, low for encodings with digits/symbols.',
    interpret:v=>v>.9?'Almost all alphabetic — classical cipher or plaintext.':v>.5?'Mixed alpha and non-alpha.':'Mostly non-alpha — numeric encoding or binary data.'},
  digitTotal:{name:'Digit Ratio (raw)',desc:'Fraction of all bytes that are digits 0-9.',
    interpret:v=>v>.5?'Majority digits — hex, octal, decimal, or binary encoding.':v>.1?'Some digits present.':'Few or no digits.'},
  symbolDensity:{name:'Symbol Density',desc:'Fraction of bytes that are non-alpha, non-digit, non-space. Captures special character load.',
    interpret:v=>v>.2?'High symbol density — URL encoding, ROT47, or Base64.':v>.05?'Some symbols — normal English punctuation.':'Very few symbols — pure alphabetic or numeric.'},
  pctCharRatio:{name:'% Character Ratio',desc:'Fraction of bytes that are the % character. URL encoding signature.',
    interpret:v=>v>.05?'Frequent % signs — strong URL encoding indicator.':'Few or no % characters.'},
  plusSlashRatio:{name:'+/Slash Ratio',desc:'Fraction of bytes that are + or /. These are Base64 alphabet characters rarely found in other encodings.',
    interpret:v=>v>.02?'Contains + or / — Base64 signal.':'No +/ characters.'},
  dotDashRatio:{name:'Dot-Dash Ratio',desc:'Fraction of bytes that are . or -. Morse code and domain names use these heavily.',
    interpret:v=>v>.2?'Heavy dot-dash usage — Morse code or domain/URL data.':v>.05?'Some dots and dashes.':'Few or none.'},
  newlineRatio:{name:'Newline Ratio',desc:'Fraction of bytes that are newline characters.',
    interpret:v=>v>.05?'Many newlines — multi-line text or formatted data.':'Few or no newlines.'},
  hexDigitRatio:{name:'Hex Digit Ratio',desc:'Fraction of bytes that are valid hex digits (0-9, a-f, A-F). Pure hex encoding approaches 1.0.',
    interpret:v=>v>.95?'Almost all hex digits — strong hex encoding signal.':v>.7?'Mostly hex digits — could be hex with some separators.':'Mixed character types.'},
  evenOddDiff:{name:'Even-Odd Byte Diff',desc:'Difference in mean byte value between even and odd positions, normalized. Detects interleaving patterns.',
    interpret:v=>v>.1?'Significant even-odd position difference — possible interleaved encoding.':'No interleaving pattern detected.'},
  repeatPeriod:{name:'Repeating Pattern Detector',desc:'Inverse of shortest period if text is built from a repeating unit (>95% match). Zero if no short repeat.',
    interpret:v=>v>0?'Text appears to be a short pattern repeated — possible encoding artifact or padding.':'No dominant repeating unit detected.'},
  uniqueWordRatio:{name:'Unique Word Ratio',desc:'Number of distinct words divided by total words. Low values indicate repeated words.',
    interpret:v=>v>.9?'Almost all unique words — diverse text.':v>.6?'Moderate uniqueness — some repetition.':'Many repeated words.'},
  isPrintableOnly:{name:'Printable-Only Flag',desc:'Whether all bytes are printable ASCII (32-126) or newlines. 0 means non-printable bytes present.',
    interpret:v=>v>0?'Entirely printable — text-based content or encoding.':'Non-printable bytes present — possible XOR, RC4, or binary encrypted output.'},
  bitsPerChar:{name:'Bits Per Character',desc:'Byte entropy divided by log₂(distinct byte count). Measures how efficiently the character set is used. 1.0 = perfectly uniform usage of available characters.',
    interpret:v=>v>.95?'Near-perfect character utilization — all available characters used equally (encrypted data).':v>.8?'High utilization.':'Uneven usage — some characters much more common than others.'},
  
  // Additional contextual features  
  sepRegularity:{name:'Separator Regularity',desc:'Measures how regularly non-alphabetic separators (spaces, punctuation) appear throughout the text. Higher values indicate consistent spacing patterns.',
    interpret:v=>v>.8?'Highly regular separator patterns — formatted text or encoding with consistent structure.':v>.4?'Moderate regularity — normal English spacing.':'Irregular separators — compressed text or cipher output.'},
  acPeakRatio:{name:'Autocorrelation Peak Ratio',desc:'Ratio of the strongest autocorrelation peak to the average. High values indicate strong periodic structure that could reveal key lengths.',
    interpret:v=>v>3?'Strong autocorrelation peak — clear periodic pattern, likely polyalphabetic cipher with detectable key length.':v>1.5?'Moderate peak — some periodicity detected.':'Flat autocorrelation — no clear periodic structure.'},
  trailingEq:{name:'Trailing Equals Count',desc:'Number of = characters at the end of the text. Base64 encoding uses = for padding, making this a strong indicator.',
    interpret:v=>v>=2?'Two trailing = signs — strong Base64 padding indicator.':v>=1?'One trailing = sign — possible Base64 padding.':'No trailing = characters.'}
};

function renderFI(name,val,gridId){
  const info=FEAT_INFO[name];
  if(!info)return `<div class="fi" onclick="toggleFITip(this,'${H(name)}',${val},'${gridId}')"><span class="fname">${name}</span><span class="fval">${typeof val==='number'?val.toFixed(5):val}</span></div>`;
  return `<div class="fi" onclick="toggleFITip(this,'${H(name)}',${val},'${gridId}')"><span class="fname">${name}</span><span class="fval">${typeof val==='number'?val.toFixed(5):val}</span></div>`;
}

function toggleFITip(el,name,val,gridId){
  // Remove any existing tip in this grid
  const grid=el.closest('.fg')||el.parentElement;
  const existing=grid.querySelector('.fi-tip');
  if(existing){const wasFor=existing.dataset.feat;existing.remove();if(wasFor===name)return;}
  // Build tip
  const info=FEAT_INFO[name];
  let tipHtml=`<div class="fi-tip" data-feat="${H(name)}">`;
  tipHtml+=`<div class="fi-tip-name">${info?info.name:name}</div>`;
  tipHtml+=`<div class="fi-tip-desc">${info?info.desc:'A statistical feature extracted from the input text.'}</div>`;
  const interp=info&&info.interpret?info.interpret(val):`Value: ${typeof val==='number'?val.toFixed(5):val}`;
  tipHtml+=`<div class="fi-tip-val">→ ${H(interp)}</div>`;
  tipHtml+=`<span class="fi-tip-close" onclick="this.parentElement.remove()">close ×</span></div>`;
  el.insertAdjacentHTML('afterend',tipHtml);
}

// Helper for dev_ features (per-letter frequency deviations)
function getDevInfo(letter){
  return{name:`Frequency Deviation: ${letter.toUpperCase()}`,
    desc:`Absolute difference between observed frequency of "${letter.toUpperCase()}" and its expected English frequency (${((ENGLISH_FREQ[letter]||0)*100).toFixed(1)}%).`,
    interpret:v=>v<.01?`"${letter.toUpperCase()}" frequency is very close to English normal.`:v<.03?`Moderate deviation from expected English frequency for "${letter.toUpperCase()}".`:`Large deviation — "${letter.toUpperCase()}" appears much more or less often than expected in English.`};}
// Register dev_ features
for(let i=0;i<22;i++){const c=String.fromCharCode(97+i);FEAT_INFO['dev_'+c]=getDevInfo(c);}

