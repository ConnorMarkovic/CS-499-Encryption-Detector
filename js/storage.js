// ═══════════════════════════════════════════════════════════════════════
//  storage.js — All persistent storage for CipherLab
//  Features:
//    - Binary-chunked IndexedDB for millions of samples
//    - Stratified loading with confusion-weighted oversampling (1A+1B)
//    - Per-type centroid profiles via Welford's algorithm (3A)
//    - User correction + encrypt capture stores (5A+5B)
//  Dependencies: ml.js must define FEATURE_COUNT before this loads
// ═══════════════════════════════════════════════════════════════════════

const ModelStore = {
  _key: 'cipherlab_ml',
  save(model) { try { localStorage.setItem(this._key, model.save()); } catch (e) { console.warn('[ModelStore] Save failed:', e.message); } },
  load(model) {
    try { const saved = localStorage.getItem(this._key); if (saved) { const ok = model.load(saved); if (!ok) { this.wipeAll(); return false; } return true; } } catch (e) {}
    return false;
  },
  wipeAll() {
    ['cipherlab_ml','cipherlab_datastore','cipherlab_confusion','cipherlab_calibration','cipherlab_acc_history','cipherlab_kb','cipherlab_centroids'].forEach(k => localStorage.removeItem(k));
    try { indexedDB.deleteDatabase('cipherlab_v3'); } catch(e){}
    console.warn('[CipherLab] Wiped all learning data.');
  }
};

const CHUNK_SIZE = 1000;
const SampleDB = {
  _dbName: 'cipherlab_v3', _chunkStore: 'chunks', _metaStore: 'meta', _userStore: 'user_samples', _missStore: 'misclassified',
  _version: 3, _db: null, _ready: false, _totalCached: null,

  async init() {
    if (this._db) return true;
    return new Promise((resolve) => {
      try {
        const req = indexedDB.open(this._dbName, this._version);
        req.onupgradeneeded = (e) => {
          const db = e.target.result;
          if (!db.objectStoreNames.contains(this._chunkStore)) {
            const store = db.createObjectStore(this._chunkStore, { keyPath: 'id', autoIncrement: true });
            store.createIndex('timestamp', 'timestamp', { unique: false });
          }
          if (!db.objectStoreNames.contains(this._metaStore)) db.createObjectStore(this._metaStore, { keyPath: 'key' });
          if (!db.objectStoreNames.contains(this._userStore)) {
            const us = db.createObjectStore(this._userStore, { keyPath: 'id', autoIncrement: true });
            us.createIndex('type', 'type', { unique: false });
            us.createIndex('source', 'source', { unique: false });
          }
          if (!db.objectStoreNames.contains(this._missStore)) {
            const ms = db.createObjectStore(this._missStore, { keyPath: 'id', autoIncrement: true });
            ms.createIndex('actual', 'actual', { unique: false });
          }
        };
        req.onsuccess = (e) => { this._db = e.target.result; this._ready = true; resolve(true); };
        req.onerror = () => resolve(false);
      } catch (e) { resolve(false); }
    });
  },

  async addSamples(featureArrays, labels, texts, meta = {}) {
    if (!this._db) return this._fbSave(featureArrays, labels);
    const total = featureArrays.length; const now = Date.now();
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._chunkStore, 'readwrite');
      const store = tx.objectStore(this._chunkStore);
      for (let start = 0; start < total; start += CHUNK_SIZE) {
        const end = Math.min(start + CHUNK_SIZE, total); const count = end - start;
        const buf = new Float32Array(count * FEATURE_COUNT);
        for (let i = 0; i < count; i++) { const src = featureArrays[start + i]; for (let j = 0; j < FEATURE_COUNT; j++) buf[i * FEATURE_COUNT + j] = src[j]; }
        store.add({ features: buf.buffer, labels: labels.slice(start, end), texts: texts ? texts.slice(start, end) : [], count, fc: FEATURE_COUNT, timestamp: now, iteration: meta.iteration || 0 });
      }
      tx.oncomplete = () => { this._totalCached = null; resolve(true); };
      tx.onerror = () => resolve(false);
    });
  },

  // Stratified loading - balance the dataset with oversampling for confused types
  async loadStratified(perType, confusionMatrix, boostFactor) {
    if (!this._db) return this._fbLoad();
    const boostedTypes = new Set();
    if (confusionMatrix) {
      for (const [actual, preds] of Object.entries(confusionMatrix)) {
        const total = Object.values(preds).reduce((s, v) => s + v, 0);
        for (const [pred, count] of Object.entries(preds)) {
          if (pred !== actual && count / total > 0.05) { boostedTypes.add(actual); boostedTypes.add(pred); }
        }
      }
    }
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._chunkStore, 'readonly');
      const req = tx.objectStore(this._chunkStore).getAll();
      req.onsuccess = () => {
        const chunks = req.result.filter(c => c.fc === FEATURE_COUNT);
        const reservoirs = {}; const limits = {}; const seenPerType = {};
        for (const chunk of chunks) for (const label of chunk.labels) { seenPerType[label] = (seenPerType[label] || 0) + 1; }
        for (const type in seenPerType) { limits[type] = boostedTypes.has(type) ? perType * boostFactor : perType; reservoirs[type] = []; }
        const seen2 = {};
        for (const chunk of chunks) {
          const f32 = new Float32Array(chunk.features);
          for (let i = 0; i < chunk.count; i++) {
            const type = chunk.labels[i]; seen2[type] = (seen2[type] || 0) + 1;
            const limit = limits[type] || perType;
            if (reservoirs[type].length < limit) {
              const vec = new Float64Array(FEATURE_COUNT); for (let j = 0; j < FEATURE_COUNT; j++) vec[j] = f32[i * FEATURE_COUNT + j];
              reservoirs[type].push(vec);
            } else {
              const r = Math.floor(Math.random() * seen2[type]);
              if (r < limit) { const vec = new Float64Array(FEATURE_COUNT); for (let j = 0; j < FEATURE_COUNT; j++) vec[j] = f32[i * FEATURE_COUNT + j]; reservoirs[type][r] = vec; }
            }
          }
        }
        const X = [], Y = [];
        for (const type in reservoirs) for (const vec of reservoirs[type]) { X.push(vec); Y.push(type); }
        resolve({ X, Y, count: X.length, typeCounts: seenPerType, boostedTypes: [...boostedTypes] });
      };
      req.onerror = () => resolve({ X: [], Y: [], count: 0, typeCounts: {}, boostedTypes: [] });
    });
  },

  async loadRecent(maxSamples) {
    if (!this._db) return this._fbLoad();
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._chunkStore, 'readonly');
      const idx = tx.objectStore(this._chunkStore).index('timestamp');
      const chunks = []; let totalCount = 0;
      const cursor = idx.openCursor(null, 'prev');
      cursor.onsuccess = (e) => {
        const c = e.target.result;
        if (c && totalCount < maxSamples) { const chunk = c.value; if (chunk.fc === FEATURE_COUNT) { chunks.unshift(chunk); totalCount += chunk.count; } c.continue(); }
        else { const X = [], Y = [];
          for (const chunk of chunks) { const f32 = new Float32Array(chunk.features); for (let i = 0; i < chunk.count; i++) { if (X.length >= maxSamples) break; const vec = new Float64Array(FEATURE_COUNT); for (let j = 0; j < FEATURE_COUNT; j++) vec[j] = f32[i * FEATURE_COUNT + j]; X.push(vec); Y.push(chunk.labels[i]); } }
          resolve({ X, Y, count: X.length }); }
      };
      cursor.onerror = () => resolve({ X: [], Y: [], count: 0 });
    });
  },

  async getCount() { if (this._totalCached !== null) return this._totalCached; if (!this._db) return this._fbCount();
    return new Promise((resolve) => { const tx = this._db.transaction(this._chunkStore, 'readonly'); const req = tx.objectStore(this._chunkStore).getAll();
      req.onsuccess = () => { let t = 0; for (const c of req.result) if (c.fc === FEATURE_COUNT) t += c.count; this._totalCached = t; resolve(t); }; req.onerror = () => resolve(0); }); },

  async getStats() { if (!this._db) return this._fbStats();
    return new Promise((resolve) => { const tx = this._db.transaction(this._chunkStore, 'readonly'); const req = tx.objectStore(this._chunkStore).getAll();
      req.onsuccess = () => { const byType = {}; let total = 0; for (const c of req.result) { if (c.fc !== FEATURE_COUNT) continue; total += c.count; for (const l of c.labels) byType[l] = (byType[l] || 0) + 1; } this._totalCached = total; resolve({ total, byType }); };
      req.onerror = () => resolve({ total: 0, byType: {} }); }); },

  async clear() { this._totalCached = null; if (!this._db) { localStorage.removeItem('cipherlab_datastore'); return; }
    return new Promise((resolve) => { const tx = this._db.transaction([this._chunkStore, this._userStore], 'readwrite'); tx.objectStore(this._chunkStore).clear(); tx.objectStore(this._userStore).clear(); tx.oncomplete = () => resolve(); tx.onerror = () => resolve(); }); },

  async setMeta(key, value) { if (!this._db) return; return new Promise((resolve) => { const tx = this._db.transaction(this._metaStore, 'readwrite'); tx.objectStore(this._metaStore).put({ key, value }); tx.oncomplete = () => resolve(); tx.onerror = () => resolve(); }); },
  async getMeta(key) { if (!this._db) return null; return new Promise((resolve) => { const tx = this._db.transaction(this._metaStore, 'readonly'); const req = tx.objectStore(this._metaStore).get(key); req.onsuccess = () => resolve(req.result ? req.result.value : null); req.onerror = () => resolve(null); }); },

  // 5A+5B: User samples
  async addUserSample(text, type, features, source) {
    if (!this._db) return;
    return new Promise((resolve) => { const tx = this._db.transaction(this._userStore, 'readwrite');
      tx.objectStore(this._userStore).add({ text, type, source, features: Array.from(features), fc: FEATURE_COUNT, timestamp: Date.now() });
      tx.oncomplete = () => resolve(true); tx.onerror = () => resolve(false); });
  },
  async loadUserSamples() { if (!this._db) return { X: [], Y: [], count: 0, sources: [] };
    return new Promise((resolve) => { const tx = this._db.transaction(this._userStore, 'readonly'); const req = tx.objectStore(this._userStore).getAll();
      req.onsuccess = () => { const recs = req.result.filter(r => r.fc === FEATURE_COUNT); resolve({ X: recs.map(r => new Float64Array(r.features)), Y: recs.map(r => r.type), count: recs.length, sources: recs.map(r => r.source) }); };
      req.onerror = () => resolve({ X: [], Y: [], count: 0, sources: [] }); });
  },
  async getUserSampleCount() { if (!this._db) return 0; return new Promise((resolve) => { const tx = this._db.transaction(this._userStore, 'readonly'); const req = tx.objectStore(this._userStore).count(); req.onsuccess = () => resolve(req.result); req.onerror = () => resolve(0); }); },

  // Store samples the model got wrong — these are high-value training data
  async saveMisclassified(features, actualType, predictedType) {
    if (!this._db) return;
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._missStore, 'readwrite');
      tx.objectStore(this._missStore).add({ features: Array.from(features), actual: actualType, predicted: predictedType, fc: FEATURE_COUNT, timestamp: Date.now() });
      tx.oncomplete = () => resolve(true); tx.onerror = () => resolve(false);
    });
  },

  // Save a batch of misclassified samples at once
  async saveMisclassifiedBatch(items) {
    if (!this._db || !items.length) return;
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._missStore, 'readwrite');
      const store = tx.objectStore(this._missStore);
      for (const item of items) store.add({ features: Array.from(item.features), actual: item.actual, predicted: item.predicted, fc: FEATURE_COUNT, timestamp: Date.now() });
      tx.oncomplete = () => resolve(true); tx.onerror = () => resolve(false);
    });
  },

  // Load misclassified samples, optionally filtered by type, capped at maxPerType
  async loadMisclassified(maxPerType=200) {
    if (!this._db) return { X: [], Y: [], count: 0 };
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._missStore, 'readonly');
      const req = tx.objectStore(this._missStore).getAll();
      req.onsuccess = () => {
        const recs = req.result.filter(r => r.fc === FEATURE_COUNT);
        // Stratify: keep up to maxPerType per actual type, preferring most recent
        const byType = {};
        for (let i = recs.length - 1; i >= 0; i--) {
          const t = recs[i].actual;
          if (!byType[t]) byType[t] = [];
          if (byType[t].length < maxPerType) byType[t].push(recs[i]);
        }
        const selected = Object.values(byType).flat();
        resolve({ X: selected.map(r => new Float64Array(r.features)), Y: selected.map(r => r.actual), count: selected.length });
      };
      req.onerror = () => resolve({ X: [], Y: [], count: 0 });
    });
  },

  async getMisclassifiedCount() {
    if (!this._db) return 0;
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._missStore, 'readonly');
      const req = tx.objectStore(this._missStore).count();
      req.onsuccess = () => resolve(req.result); req.onerror = () => resolve(0);
    });
  },

  async clearMisclassified() {
    if (!this._db) return;
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._missStore, 'readwrite');
      tx.objectStore(this._missStore).clear();
      tx.oncomplete = () => resolve(); tx.onerror = () => resolve();
    });
  },

  _fbSave(X, Y) { const max = 8000; const s = Math.max(0, X.length - max); try { localStorage.setItem('cipherlab_datastore', JSON.stringify({ X: X.slice(s).map(x => Array.from(x)), Y: Y.slice(s), fc: FEATURE_COUNT })); } catch (e) {} },
  _fbLoad() { try { const raw = localStorage.getItem('cipherlab_datastore'); if (raw) { const d = JSON.parse(raw); if (d.X && d.X.length > 0 && d.X[0].length !== FEATURE_COUNT) { localStorage.removeItem('cipherlab_datastore'); return { X: [], Y: [], count: 0 }; } return { X: d.X.map(x => new Float64Array(x)), Y: d.Y, count: d.Y.length }; } } catch (e) {} return { X: [], Y: [], count: 0 }; },
  _fbCount() { try { const raw = localStorage.getItem('cipherlab_datastore'); if (raw) return JSON.parse(raw).Y.length; } catch (e) {} return 0; },
  _fbStats() { try { const raw = localStorage.getItem('cipherlab_datastore'); if (raw) { const d = JSON.parse(raw); const c = {}; for (const y of d.Y) c[y] = (c[y] || 0) + 1; return { total: d.Y.length, byType: c }; } } catch (e) {} return { total: 0, byType: {} }; }
};

SampleDB.init().then(ok => { if (ok) SampleDB.getCount().then(n => console.log('[CipherLab] IndexedDB ready — ' + n.toLocaleString() + ' samples')); else console.log('[CipherLab] Using localStorage fallback'); });

// DataStore wrapper
const DataStore = {
  perType: 2000,
  async load(confusionMatrix) { if (SampleDB._db) return SampleDB.loadStratified(this.perType, confusionMatrix, 2); return SampleDB._fbLoad(); },
  async loadWithUserSamples(confusionMatrix) {
    const base = await this.load(confusionMatrix);
    const user = await SampleDB.loadUserSamples();
    if (user.count > 0) { for (let i = 0; i < user.count; i++) { const reps = user.sources[i] === 'correction' ? 3 : 1; for (let r = 0; r < reps; r++) { base.X.push(user.X[i]); base.Y.push(user.Y[i]); } } base.count = base.X.length; }
    return base;
  },
  async save(X, Y, meta) { await SampleDB.addSamples(X.map(x => (x instanceof Float64Array) ? x : new Float64Array(x)), Y, null, meta); },
  async saveWithTexts(X, Y, texts, meta) { await SampleDB.addSamples(X.map(x => (x instanceof Float64Array) ? x : new Float64Array(x)), Y, texts, meta); },
  async saveCorrection(text, correctType) { const f = extractFeatures(text); await SampleDB.addUserSample(text, correctType, f, 'correction'); },
  async saveEncryptCapture(ciphertext, type) { const f = extractFeatures(ciphertext); await SampleDB.addUserSample(ciphertext, type, f, 'encrypt'); },
  async getStats() { return SampleDB.getStats(); },
  async getCount() { return SampleDB.getCount(); },
  async getUserCount() { return SampleDB.getUserSampleCount(); },
  async clear() { return SampleDB.clear(); },
  loadSync() { return SampleDB._fbLoad(); },
  getStatsSync() { return SampleDB._fbStats(); }
};

// 3A: Centroid Store — per-type mean + variance via Welford's algorithm
const CentroidStore = {
  _key: 'cipherlab_centroids', _profiles: {},
  load() { try { const raw = localStorage.getItem(this._key); if (raw) { const d = JSON.parse(raw); this._profiles = {}; for (const type in d) this._profiles[type] = { count: d[type].count, mean: new Float64Array(d[type].mean), m2: new Float64Array(d[type].m2) }; } } catch (e) { this._profiles = {}; } },
  save() { const d = {}; for (const type in this._profiles) { const p = this._profiles[type]; d[type] = { count: p.count, mean: Array.from(p.mean), m2: Array.from(p.m2) }; } try { localStorage.setItem(this._key, JSON.stringify(d)); } catch (e) {} },
  update(type, features) {
    if (!this._profiles[type]) this._profiles[type] = { count: 0, mean: new Float64Array(FEATURE_COUNT), m2: new Float64Array(FEATURE_COUNT) };
    const p = this._profiles[type]; p.count++;
    for (let i = 0; i < FEATURE_COUNT; i++) { const delta = features[i] - p.mean[i]; p.mean[i] += delta / p.count; const delta2 = features[i] - p.mean[i]; p.m2[i] += delta * delta2; }
  },
  updateBatch(type, featureArrays) { for (const f of featureArrays) this.update(type, f); },
  getProfile(type) { const p = this._profiles[type]; if (!p || p.count < 2) return null; const v = new Float64Array(FEATURE_COUNT); const s = new Float64Array(FEATURE_COUNT); for (let i = 0; i < FEATURE_COUNT; i++) { v[i] = p.m2[i] / (p.count - 1); s[i] = Math.sqrt(v[i]); } return { mean: p.mean, variance: v, std: s, count: p.count }; },
  getAllProfiles() { const r = {}; for (const type in this._profiles) r[type] = this.getProfile(type); return r; },
  distance(features, type) { const p = this._profiles[type]; if (!p || p.count < 10) return Infinity; let sum = 0; for (let i = 0; i < FEATURE_COUNT; i++) { const v = p.m2[i] / (p.count - 1); if (v > 1e-10) { const d = features[i] - p.mean[i]; sum += (d * d) / v; } } return Math.sqrt(sum / FEATURE_COUNT); },
  rank(features) { const d = []; for (const type in this._profiles) { const dist = this.distance(features, type); if (dist !== Infinity) d.push({ type, distance: dist }); } d.sort((a, b) => a.distance - b.distance); return d; },
  reset() { this._profiles = {}; this.save(); }
};
CentroidStore.load();

// Confusion, Calibration, AccuracyHistory, KBStore
const ConfusionTracker = {
  _key: 'cipherlab_confusion', matrix: {},
  load() { try { this.matrix = JSON.parse(localStorage.getItem(this._key)) || {}; } catch (e) { this.matrix = {}; } },
  save() { localStorage.setItem(this._key, JSON.stringify(this.matrix)); },
  record(actual, predicted) { if (!this.matrix[actual]) this.matrix[actual] = {}; this.matrix[actual][predicted] = (this.matrix[actual][predicted] || 0) + 1; this.save(); },
  recordBatch(actual, predicted) { if (!this.matrix[actual]) this.matrix[actual] = {}; this.matrix[actual][predicted] = (this.matrix[actual][predicted] || 0) + 1; },
  getConfusedPairs(minConfusion) { const pairs = []; for (const [a, preds] of Object.entries(this.matrix)) { const t = Object.values(preds).reduce((s, v) => s + v, 0); for (const [p, c] of Object.entries(preds)) if (p !== a && c >= (minConfusion||5)) pairs.push({ actual: a, predicted: p, count: c, rate: c / t }); } pairs.sort((a, b) => b.rate - a.rate); return pairs; },
  getAccuracyByType() { const r = {}; for (const [a, preds] of Object.entries(this.matrix)) { const t = Object.values(preds).reduce((s, v) => s + v, 0); r[a] = { total: t, correct: preds[a] || 0, accuracy: t ? (preds[a] || 0) / t : 0 }; } return r; },
  reset() { this.matrix = {}; this.save(); }
};
ConfusionTracker.load();

const CalibrationTracker = {
  _key: 'cipherlab_calibration', buckets: {},
  load() { try { this.buckets = JSON.parse(localStorage.getItem(this._key)) || {}; } catch (e) { this.buckets = {}; } },
  save() { localStorage.setItem(this._key, JSON.stringify(this.buckets)); },
  record(confidence, correct) { const k = (Math.floor(confidence * 10) / 10).toFixed(1); if (!this.buckets[k]) this.buckets[k] = { total: 0, correct: 0 }; this.buckets[k].total++; if (correct) this.buckets[k].correct++; this.save(); },
  recordBatch(confidence, correct) { const k = (Math.floor(confidence * 10) / 10).toFixed(1); if (!this.buckets[k]) this.buckets[k] = { total: 0, correct: 0 }; this.buckets[k].total++; if (correct) this.buckets[k].correct++; },
  getCalibration() { const r = []; for (const [k, d] of Object.entries(this.buckets)) r.push({ confidence: +k, total: d.total, correct: d.correct, accuracy: d.total ? d.correct / d.total : 0 }); r.sort((a, b) => a.confidence - b.confidence); return r; },
  getCalibratedConfidence(raw) { const d = this.buckets[(Math.floor(raw * 10) / 10).toFixed(1)]; if (d && d.total >= 10) return d.correct / d.total; return raw; },
  reset() { this.buckets = {}; this.save(); }
};
CalibrationTracker.load();

const AccuracyHistory = {
  _key: 'cipherlab_acc_history',
  load() { try { return JSON.parse(localStorage.getItem(this._key)) || []; } catch (e) { return []; } },
  save(h) { localStorage.setItem(this._key, JSON.stringify(h.slice(-500))); },
  record(accuracy, samples, iteration) { const h = this.load(); h.push({ accuracy, samples, iteration, timestamp: Date.now() }); this.save(h); }
};

const KBStore = {
  _key: 'cipherlab_kb',
  load() { try { return JSON.parse(localStorage.getItem(this._key)) || {}; } catch (e) { return {}; } },
  save(kb) { try { localStorage.setItem(this._key, JSON.stringify(kb)); } catch (e) {} },
  clear() { localStorage.removeItem(this._key); }
};

// ═══════════════════════════════════════════════════════════════════════
//  UNSOLVED STORE — persistent JSON file of samples the AI cannot classify
//  Stores up to 100,000 samples that were misclassified. Each sample is
//  marked 'unsolved' until a future training iteration correctly identifies
//  its actual type, at which point it becomes 'solved'.
// ═══════════════════════════════════════════════════════════════════════

const UnsolvedStore = {
  _key: 'cipherlab_unsolved',
  _maxSamples: 100000,
  _data: null, // {samples: [], stats: {total, unsolved, solved, solvedByType}}

  // Load from localStorage (or initialize empty)
  load() {
    if (this._data) return this._data;
    try {
      const raw = localStorage.getItem(this._key);
      if (raw) {
        this._data = JSON.parse(raw);
        // Validate structure
        if (!this._data.samples) this._data = this._createEmpty();
      } else {
        this._data = this._createEmpty();
      }
    } catch (e) { this._data = this._createEmpty(); }
    return this._data;
  },

  _createEmpty() {
    return { samples: [], stats: { total: 0, unsolved: 0, solved: 0, solvedByType: {}, addedTotal: 0, solvedTotal: 0 } };
  },

  // Save to localStorage — compresses by only keeping unsolved + recently solved
  save() {
    if (!this._data) return;
    this._updateStats();
    try {
      // Only persist unsolved samples + solved samples from last 5 iterations (for reference)
      const toSave = {
        samples: this._data.samples,
        stats: this._data.stats
      };
      localStorage.setItem(this._key, JSON.stringify(toSave));
    } catch (e) {
      // localStorage full — prune oldest solved samples and retry
      this._data.samples = this._data.samples.filter(s => s.status === 'unsolved');
      this._updateStats();
      try { localStorage.setItem(this._key, JSON.stringify(this._data)); } catch (e2) {}
    }
  },

  // Add misclassified samples as unsolved
  // Each sample: {features: number[128], actual: string, predicted: string, status: 'unsolved', addedAt: timestamp}
  addUnsolved(items) {
    this.load();
    for (const item of items) {
      if (this._data.samples.length >= this._maxSamples) {
        // At cap — remove oldest solved first, then oldest unsolved
        const solvedIdx = this._data.samples.findIndex(s => s.status === 'solved');
        if (solvedIdx >= 0) {
          this._data.samples.splice(solvedIdx, 1);
        } else {
          this._data.samples.shift(); // remove oldest unsolved
        }
      }
      this._data.samples.push({
        features: Array.from(item.features),
        actual: item.actual,
        predicted: item.predicted,
        status: 'unsolved',
        addedAt: Date.now(),
        fc: FEATURE_COUNT
      });
    }
    this._data.stats.addedTotal += items.length;
    this._updateStats();
  },

  // During training: test unsolved samples against the current model
  // Returns {solved: number, tested: number, remaining: number, solvedSamples: []}
  testAndSolve(model) {
    this.load();
    if (!model || !model.trained) return { solved: 0, tested: 0, remaining: this.getUnsolvedCount() };
    
    let solved = 0, tested = 0;
    const solvedSamples = [];
    
    for (const sample of this._data.samples) {
      if (sample.status !== 'unsolved') continue;
      if (sample.fc !== FEATURE_COUNT) continue;
      
      tested++;
      const features = new Float64Array(sample.features);
      const pred = model.predict(features);
      
      // Solved if the model now correctly identifies the actual type
      if (pred.cls === sample.actual && pred.confidence > 0.6) {
        sample.status = 'solved';
        sample.solvedAt = Date.now();
        sample.solvedConfidence = pred.confidence;
        solved++;
        solvedSamples.push({ actual: sample.actual, predicted: sample.predicted, confidence: pred.confidence });
        
        // Track which types are getting solved
        if (!this._data.stats.solvedByType[sample.actual]) this._data.stats.solvedByType[sample.actual] = 0;
        this._data.stats.solvedByType[sample.actual]++;
      }
    }
    
    this._data.stats.solvedTotal += solved;
    this._updateStats();
    return { solved, tested, remaining: this.getUnsolvedCount(), solvedSamples };
  },

  // Get unsolved samples for training reinforcement (returns features + labels)
  getUnsolved(maxPerType = 500) {
    this.load();
    const byType = {};
    const unsolved = this._data.samples.filter(s => s.status === 'unsolved' && s.fc === FEATURE_COUNT);
    
    // Stratify by actual type
    for (const s of unsolved) {
      if (!byType[s.actual]) byType[s.actual] = [];
      if (byType[s.actual].length < maxPerType) byType[s.actual].push(s);
    }
    
    const selected = Object.values(byType).flat();
    return {
      X: selected.map(s => new Float64Array(s.features)),
      Y: selected.map(s => s.actual),
      count: selected.length,
      byType: Object.fromEntries(Object.entries(byType).map(([k, v]) => [k, v.length]))
    };
  },

  getUnsolvedCount() {
    this.load();
    return this._data.samples.filter(s => s.status === 'unsolved').length;
  },

  getSolvedCount() {
    this.load();
    return this._data.samples.filter(s => s.status === 'solved').length;
  },

  getStats() {
    this.load();
    this._updateStats();
    return { ...this._data.stats };
  },

  _updateStats() {
    if (!this._data) return;
    const samples = this._data.samples;
    this._data.stats.total = samples.length;
    this._data.stats.unsolved = samples.filter(s => s.status === 'unsolved').length;
    this._data.stats.solved = samples.filter(s => s.status === 'solved').length;
  },

  // Export unsolved samples as downloadable JSON
  exportJSON() {
    this.load();
    const unsolved = this._data.samples.filter(s => s.status === 'unsolved' && s.fc === FEATURE_COUNT);
    return JSON.stringify({
      version: 1,
      fc: FEATURE_COUNT,
      exported: new Date().toISOString(),
      count: unsolved.length,
      stats: this._data.stats,
      samples: unsolved.map(s => ({
        features: s.features,
        actual: s.actual,
        predicted: s.predicted,
        addedAt: s.addedAt
      }))
    }, null, 2);
  },

  // Import unsolved samples from JSON file
  importJSON(jsonString) {
    try {
      const data = JSON.parse(jsonString);
      if (data.fc !== FEATURE_COUNT) return { success: false, reason: 'Feature count mismatch: expected ' + FEATURE_COUNT + ', got ' + data.fc };
      if (!data.samples || !data.samples.length) return { success: false, reason: 'No samples in file' };
      
      this.load();
      let imported = 0;
      for (const s of data.samples) {
        if (this._data.samples.length >= this._maxSamples) break;
        this._data.samples.push({
          features: s.features,
          actual: s.actual,
          predicted: s.predicted,
          status: 'unsolved',
          addedAt: s.addedAt || Date.now(),
          fc: FEATURE_COUNT
        });
        imported++;
      }
      this._updateStats();
      this.save();
      return { success: true, imported, total: this._data.samples.length };
    } catch (e) { return { success: false, reason: e.message }; }
  },

  // Purge all solved samples to free space
  purgeSolved() {
    this.load();
    const before = this._data.samples.length;
    this._data.samples = this._data.samples.filter(s => s.status === 'unsolved');
    this._updateStats();
    this.save();
    return before - this._data.samples.length;
  },

  reset() { this._data = this._createEmpty(); this.save(); }
};
