/**
 * CipherLab - Storage Management Module
 * 
 * This module handles all persistent storage for CipherLab using modern web APIs.
 * It manages training sample storage using IndexedDB for large datasets and OPFS
 * (Origin Private File System) for smaller configuration data.
 * 
 * Key features:
 * - Binary-chunked IndexedDB storage for scalable training sample management
 * - Stratified sampling with confusion-matrix weighted oversampling
 * - Centroid profile calculation using Welford's online algorithm
 * - User correction and interaction tracking
 * - OPFS storage for models, knowledge base, and configuration data
 * 
 * Dependencies: ml.js (FEATURE_COUNT constant)
 */

/**
 * OPFS STORAGE HELPER
 * Provides a simple key-value interface over the Origin Private File System API
 * for storing small configuration files and model data.
 */
//  parsed JSON; writes serialize to JSON and flush atomically via a
//  writable stream. Falls back gracefully if OPFS isn't available.
// ═══════════════════════════════════════════════════════════════════════

const OPFS = {
  _root: null,
  _supported: typeof navigator !== 'undefined' && !!navigator.storage && !!navigator.storage.getDirectory,

  async _getRoot() {
    if (this._root) return this._root;
    if (!this._supported) return null;
    try {
      this._root = await navigator.storage.getDirectory();
      return this._root;
    } catch (e) {
      console.warn('[OPFS] Could not get storage root:', e.message);
      this._supported = false;
      return null;
    }
  },

  // Read a JSON value from OPFS and returns parsed object or null if missing
  async get(key) {
    const root = await this._getRoot();
    if (!root) return null;
    try {
      const fileHandle = await root.getFileHandle(key + '.json');
      const file = await fileHandle.getFile();
      const text = await file.text();
      return JSON.parse(text);
    } catch (e) {
      // File doesn't exist yet
      return null;
    }
  },

  // Write a JSON value to OPFS atomically
  async set(key, value) {
    const root = await this._getRoot();
    if (!root) return false;
    try {
      const fileHandle = await root.getFileHandle(key + '.json', { create: true });
      const writable = await fileHandle.createWritable();
      await writable.write(JSON.stringify(value));
      await writable.close();
      return true;
    } catch (e) {
      console.warn('[OPFS] Write failed for key "' + key + '":', e.message);
      return false;
    }
  },

  // Delete a file from OPFS which silently ignores missing files
  async remove(key) {
    const root = await this._getRoot();
    if (!root) return;
    try {
      await root.removeEntry(key + '.json');
    } catch (e) {}
  },

  // Wipe a list of OPFS keys at once
  async wipeAll(keys) {
    for (const k of keys) await this.remove(k);
  }
};

// ═══════════════════════════════════════════════════════════════════════
//  MODEL STORE: saves/loads the trained Decision Forest via OPFS
// ═══════════════════════════════════════════════════════════════════════

const ModelStore = {
  _key: 'cipherlab_ml',

  async save(model) {
    try {
      const ok = await OPFS.set(this._key, model.save());
      if (!ok) console.warn('[ModelStore] Save failed — OPFS unavailable.');
    } catch (e) { console.warn('[ModelStore] Save failed:', e.message); }
  },

  async load(model) {
    try {
      const saved = await OPFS.get(this._key);
      if (saved) {
        // OPFS.get parses JSON, but model.load() expects the raw serialized string
        const raw = typeof saved === 'string' ? saved : JSON.stringify(saved);
        const ok = model.load(raw);
        if (!ok) { await this.wipeAll(); return false; }
        return true;
      }
    } catch (e) {}
    return false;
  },

  async wipeAll() {
    await OPFS.wipeAll([
      'cipherlab_ml', 'cipherlab_datastore', 'cipherlab_confusion',
      'cipherlab_calibration', 'cipherlab_acc_history', 'cipherlab_kb',
      'cipherlab_centroids', 'cipherlab_unsolved'
    ]);
    try { indexedDB.deleteDatabase('cipherlab_v3'); } catch (e) {}
    console.warn('[CipherLab] Wiped all learning data.');
  }
};

// ═══════════════════════════════════════════════════════════════════════
//  SAMPLE DB: binary-chunked IndexedDB for millions of training samples
// ═══════════════════════════════════════════════════════════════════════

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

  // Stratified loading — balance the dataset with oversampling for confused types
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

  async getCount() {
    if (this._totalCached !== null) return this._totalCached;
    if (!this._db) return this._fbCount();
    return new Promise((resolve) => { const tx = this._db.transaction(this._chunkStore, 'readonly'); const req = tx.objectStore(this._chunkStore).getAll();
      req.onsuccess = () => { let t = 0; for (const c of req.result) if (c.fc === FEATURE_COUNT) t += c.count; this._totalCached = t; resolve(t); }; req.onerror = () => resolve(0); });
  },

  async getStats() {
    if (!this._db) return this._fbStats();
    return new Promise((resolve) => { const tx = this._db.transaction(this._chunkStore, 'readonly'); const req = tx.objectStore(this._chunkStore).getAll();
      req.onsuccess = () => { const byType = {}; let total = 0; for (const c of req.result) { if (c.fc !== FEATURE_COUNT) continue; total += c.count; for (const l of c.labels) byType[l] = (byType[l] || 0) + 1; } this._totalCached = total; resolve({ total, byType }); };
      req.onerror = () => resolve({ total: 0, byType: {} }); });
  },

  async clear() {
    this._totalCached = null;
    if (!this._db) { await OPFS.remove('cipherlab_datastore'); return; }
    return new Promise((resolve) => { const tx = this._db.transaction([this._chunkStore, this._userStore], 'readwrite'); tx.objectStore(this._chunkStore).clear(); tx.objectStore(this._userStore).clear(); tx.oncomplete = () => resolve(); tx.onerror = () => resolve(); });
  },

  async setMeta(key, value) { if (!this._db) return; return new Promise((resolve) => { const tx = this._db.transaction(this._metaStore, 'readwrite'); tx.objectStore(this._metaStore).put({ key, value }); tx.oncomplete = () => resolve(); tx.onerror = () => resolve(); }); },
  async getMeta(key) { if (!this._db) return null; return new Promise((resolve) => { const tx = this._db.transaction(this._metaStore, 'readonly'); const req = tx.objectStore(this._metaStore).get(key); req.onsuccess = () => resolve(req.result ? req.result.value : null); req.onerror = () => resolve(null); }); },

  // User-submitted samples from corrections and encrypt captures
  async addUserSample(text, type, features, source) {
    if (!this._db) return;
    return new Promise((resolve) => { const tx = this._db.transaction(this._userStore, 'readwrite');
      tx.objectStore(this._userStore).add({ text, type, source, features: Array.from(features), fc: FEATURE_COUNT, timestamp: Date.now() });
      tx.oncomplete = () => resolve(true); tx.onerror = () => resolve(false); });
  },
  async loadUserSamples() {
    if (!this._db) return { X: [], Y: [], count: 0, sources: [] };
    return new Promise((resolve) => { const tx = this._db.transaction(this._userStore, 'readonly'); const req = tx.objectStore(this._userStore).getAll();
      req.onsuccess = () => { const recs = req.result.filter(r => r.fc === FEATURE_COUNT); resolve({ X: recs.map(r => new Float64Array(r.features)), Y: recs.map(r => r.type), count: recs.length, sources: recs.map(r => r.source) }); };
      req.onerror = () => resolve({ X: [], Y: [], count: 0, sources: [] }); });
  },
  async getUserSampleCount() {
    if (!this._db) return 0;
    return new Promise((resolve) => { const tx = this._db.transaction(this._userStore, 'readonly'); const req = tx.objectStore(this._userStore).count(); req.onsuccess = () => resolve(req.result); req.onerror = () => resolve(0); });
  },

  // Store samples the model got wrong — high-value training reinforcement data
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

  // Load misclassified samples capped at maxPerType per actual type, preferring most recent
  async loadMisclassified(maxPerType=200) {
    if (!this._db) return { X: [], Y: [], count: 0 };
    return new Promise((resolve) => {
      const tx = this._db.transaction(this._missStore, 'readonly');
      const req = tx.objectStore(this._missStore).getAll();
      req.onsuccess = () => {
        const recs = req.result.filter(r => r.fc === FEATURE_COUNT);
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

  // OPFS-based fallback for when IndexedDB isn't available
  async _fbSave(X, Y) {
    const max = 8000; const s = Math.max(0, X.length - max);
    await OPFS.set('cipherlab_datastore', { X: X.slice(s).map(x => Array.from(x)), Y: Y.slice(s), fc: FEATURE_COUNT });
  },
  async _fbLoad() {
    const d = await OPFS.get('cipherlab_datastore');
    if (d) {
      if (d.X && d.X.length > 0 && d.X[0].length !== FEATURE_COUNT) { await OPFS.remove('cipherlab_datastore'); return { X: [], Y: [], count: 0 }; }
      return { X: d.X.map(x => new Float64Array(x)), Y: d.Y, count: d.Y.length };
    }
    return { X: [], Y: [], count: 0 };
  },
  async _fbCount() {
    const d = await OPFS.get('cipherlab_datastore');
    return d ? d.Y.length : 0;
  },
  async _fbStats() {
    const d = await OPFS.get('cipherlab_datastore');
    if (d) { const c = {}; for (const y of d.Y) c[y] = (c[y] || 0) + 1; return { total: d.Y.length, byType: c }; }
    return { total: 0, byType: {} };
  }
};

SampleDB.init().then(ok => {
  if (ok) SampleDB.getCount().then(n => console.log('[CipherLab] IndexedDB ready — ' + n.toLocaleString() + ' samples'));
  else console.log('[CipherLab] Using OPFS fallback for sample storage');
});

// DataStore wrapper: single interface over SampleDB
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
  loadSync() { return { X: [], Y: [], count: 0 }; }, // sync path removed — use async load()
  getStatsSync() { return { total: 0, byType: {} }; }
};

/**
 * CENTROID STORAGE SYSTEM
 * Maintains statistical profiles for each cipher type including mean values
 * and variance calculations. This provides fast nearest-centroid classification
 * as an alternative to the full decision forest approach.
 */

const CentroidStore = {
  _key: 'cipherlab_centroids', _profiles: {},

  // Pull profiles from OPFS on startup
  async load() {
    try {
      const d = await OPFS.get(this._key);
      if (d) {
        this._profiles = {};
        for (const type in d) this._profiles[type] = { count: d[type].count, mean: new Float64Array(d[type].mean), m2: new Float64Array(d[type].m2) };
      }
    } catch (e) { this._profiles = {}; }
  },

  // Persist profiles back to OPFS
  async save() {
    const d = {};
    for (const type in this._profiles) { const p = this._profiles[type]; d[type] = { count: p.count, mean: Array.from(p.mean), m2: Array.from(p.m2) }; }
    await OPFS.set(this._key, d);
  },

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
  async reset() { this._profiles = {}; await this.save(); }
};
// CentroidStore.load() is called at startup via Promise.all in kb.js

// ═══════════════════════════════════════════════════════════════════════
//  CONFUSION, CALIBRATION, ACCURACY HISTORY, KB STORE
//  All four previously used localStorage — now using OPFS so data
//  actually survives across sessions without bumping into a size cap.
// ═══════════════════════════════════════════════════════════════════════

const ConfusionTracker = {
  _key: 'cipherlab_confusion', matrix: {},

  async load() {
    try { const d = await OPFS.get(this._key); this.matrix = d || {}; } catch (e) { this.matrix = {}; }
  },
  async save() { await OPFS.set(this._key, this.matrix); },
  record(actual, predicted) { if (!this.matrix[actual]) this.matrix[actual] = {}; this.matrix[actual][predicted] = (this.matrix[actual][predicted] || 0) + 1; this.save(); },
  recordBatch(actual, predicted) { if (!this.matrix[actual]) this.matrix[actual] = {}; this.matrix[actual][predicted] = (this.matrix[actual][predicted] || 0) + 1; },
  getConfusedPairs(minConfusion) { const pairs = []; for (const [a, preds] of Object.entries(this.matrix)) { const t = Object.values(preds).reduce((s, v) => s + v, 0); for (const [p, c] of Object.entries(preds)) if (p !== a && c >= (minConfusion||5)) pairs.push({ actual: a, predicted: p, count: c, rate: c / t }); } pairs.sort((a, b) => b.rate - a.rate); return pairs; },
  getAccuracyByType() { const r = {}; for (const [a, preds] of Object.entries(this.matrix)) { const t = Object.values(preds).reduce((s, v) => s + v, 0); r[a] = { total: t, correct: preds[a] || 0, accuracy: t ? (preds[a] || 0) / t : 0 }; } return r; },
  async reset() { this.matrix = {}; await this.save(); }
};
// ConfusionTracker.load() is called at startup via Promise.all in kb.js

const CalibrationTracker = {
  _key: 'cipherlab_calibration', buckets: {},

  async load() {
    try { const d = await OPFS.get(this._key); this.buckets = d || {}; } catch (e) { this.buckets = {}; }
  },
  async save() { await OPFS.set(this._key, this.buckets); },
  record(confidence, correct) { const k = (Math.floor(confidence * 10) / 10).toFixed(1); if (!this.buckets[k]) this.buckets[k] = { total: 0, correct: 0 }; this.buckets[k].total++; if (correct) this.buckets[k].correct++; this.save(); },
  recordBatch(confidence, correct) { const k = (Math.floor(confidence * 10) / 10).toFixed(1); if (!this.buckets[k]) this.buckets[k] = { total: 0, correct: 0 }; this.buckets[k].total++; if (correct) this.buckets[k].correct++; },
  getCalibration() { const r = []; for (const [k, d] of Object.entries(this.buckets)) r.push({ confidence: +k, total: d.total, correct: d.correct, accuracy: d.total ? d.correct / d.total : 0 }); r.sort((a, b) => a.confidence - b.confidence); return r; },
  getCalibratedConfidence(raw) { const d = this.buckets[(Math.floor(raw * 10) / 10).toFixed(1)]; if (d && d.total >= 10) return d.correct / d.total; return raw; },
  async reset() { this.buckets = {}; await this.save(); }
};
// CalibrationTracker.load() is called at startup via Promise.all in kb.js

const AccuracyHistory = {
  _key: 'cipherlab_acc_history',

  async load() {
    try { const d = await OPFS.get(this._key); return d || []; } catch (e) { return []; }
  },
  async save(h) { await OPFS.set(this._key, h.slice(-500)); },
  async record(accuracy, samples, iteration) {
    const h = await this.load();
    h.push({ accuracy, samples, iteration, timestamp: Date.now() });
    await this.save(h);
  }
};

const KBStore = {
  _key: 'cipherlab_kb',

  async load() { try { return await OPFS.get(this._key) || {}; } catch (e) { return {}; } },
  async save(kb) { try { await OPFS.set(this._key, kb); } catch (e) {} },
  async clear() { await OPFS.remove(this._key); }
};

// ═══════════════════════════════════════════════════════════════════════
//  UNSOLVED STORE: tracks samples the model couldn't classify correctly
//  Stores up to 100,000 misclassified samples. Each is marked 'unsolved'
//  until a future training iteration gets it right, then 'solved'.
// ═══════════════════════════════════════════════════════════════════════

const UnsolvedStore = {
  _key: 'cipherlab_unsolved',
  _maxSamples: 100000,
  _data: null,

  // Pull from OPFS on startup (or initialize empty on first run)
  async load() {
    if (this._data) return this._data;
    try {
      const raw = await OPFS.get(this._key);
      if (raw) {
        this._data = raw;
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

  // Persist to OPFS and prunes solved samples if the write fails
  async save() {
    if (!this._data) return;
    this._updateStats();
    try {
      const ok = await OPFS.set(this._key, { samples: this._data.samples, stats: this._data.stats });
      if (!ok) {
        // Write failed — prune solved samples and try once more
        this._data.samples = this._data.samples.filter(s => s.status === 'unsolved');
        this._updateStats();
        await OPFS.set(this._key, this._data);
      }
    } catch (e) {}
  },

  // Add misclassified samples as unsolved
  async addUnsolved(items) {
    await this.load();
    for (const item of items) {
      if (this._data.samples.length >= this._maxSamples) {
        const solvedIdx = this._data.samples.findIndex(s => s.status === 'solved');
        if (solvedIdx >= 0) this._data.samples.splice(solvedIdx, 1);
        else this._data.samples.shift();
      }
      this._data.samples.push({ features: Array.from(item.features), actual: item.actual, predicted: item.predicted, status: 'unsolved', addedAt: Date.now(), fc: FEATURE_COUNT });
    }
    this._data.stats.addedTotal += items.length;
    this._updateStats();
  },

  // Test unsolved samples against the current model and mark any that are now correct
  async testAndSolve(model) {
    await this.load();
    if (!model || !model.trained) return { solved: 0, tested: 0, remaining: await this.getUnsolvedCount() };
    let solved = 0, tested = 0;
    const solvedSamples = [];
    for (const sample of this._data.samples) {
      if (sample.status !== 'unsolved' || sample.fc !== FEATURE_COUNT) continue;
      tested++;
      const features = new Float64Array(sample.features);
      const pred = model.predict(features);
      if (pred.cls === sample.actual && pred.confidence > 0.6) {
        sample.status = 'solved'; sample.solvedAt = Date.now(); sample.solvedConfidence = pred.confidence;
        solved++;
        solvedSamples.push({ actual: sample.actual, predicted: sample.predicted, confidence: pred.confidence });
        if (!this._data.stats.solvedByType[sample.actual]) this._data.stats.solvedByType[sample.actual] = 0;
        this._data.stats.solvedByType[sample.actual]++;
      }
    }
    this._data.stats.solvedTotal += solved;
    this._updateStats();
    return { solved, tested, remaining: this._data.samples.filter(s => s.status === 'unsolved').length, solvedSamples };
  },

  // Get unsolved samples for training reinforcement
  async getUnsolved(maxPerType = 500) {
    await this.load();
    const byType = {};
    const unsolved = this._data.samples.filter(s => s.status === 'unsolved' && s.fc === FEATURE_COUNT);
    for (const s of unsolved) {
      if (!byType[s.actual]) byType[s.actual] = [];
      if (byType[s.actual].length < maxPerType) byType[s.actual].push(s);
    }
    const selected = Object.values(byType).flat();
    return { X: selected.map(s => new Float64Array(s.features)), Y: selected.map(s => s.actual), count: selected.length, byType: Object.fromEntries(Object.entries(byType).map(([k, v]) => [k, v.length])) };
  },

  async getUnsolvedCount() { await this.load(); return this._data.samples.filter(s => s.status === 'unsolved').length; },
  async getSolvedCount() { await this.load(); return this._data.samples.filter(s => s.status === 'solved').length; },
  async getStats() { await this.load(); this._updateStats(); return { ...this._data.stats }; },

  _updateStats() {
    if (!this._data) return;
    const samples = this._data.samples;
    this._data.stats.total = samples.length;
    this._data.stats.unsolved = samples.filter(s => s.status === 'unsolved').length;
    this._data.stats.solved = samples.filter(s => s.status === 'solved').length;
  },

  async exportJSON() {
    await this.load();
    const unsolved = this._data.samples.filter(s => s.status === 'unsolved' && s.fc === FEATURE_COUNT);
    return JSON.stringify({ version: 1, fc: FEATURE_COUNT, exported: new Date().toISOString(), count: unsolved.length, stats: this._data.stats, samples: unsolved.map(s => ({ features: s.features, actual: s.actual, predicted: s.predicted, addedAt: s.addedAt })) }, null, 2);
  },

  async importJSON(jsonString) {
    try {
      const data = JSON.parse(jsonString);
      if (data.fc !== FEATURE_COUNT) return { success: false, reason: 'Feature count mismatch: expected ' + FEATURE_COUNT + ', got ' + data.fc };
      if (!data.samples || !data.samples.length) return { success: false, reason: 'No samples in file' };
      await this.load();
      let imported = 0;
      for (const s of data.samples) {
        if (this._data.samples.length >= this._maxSamples) break;
        this._data.samples.push({ features: s.features, actual: s.actual, predicted: s.predicted, status: 'unsolved', addedAt: s.addedAt || Date.now(), fc: FEATURE_COUNT });
        imported++;
      }
      this._updateStats();
      await this.save();
      return { success: true, imported, total: this._data.samples.length };
    } catch (e) { return { success: false, reason: e.message }; }
  },

  async purgeSolved() {
    await this.load();
    const before = this._data.samples.length;
    this._data.samples = this._data.samples.filter(s => s.status === 'unsolved');
    this._updateStats();
    await this.save();
    return before - this._data.samples.length;
  },

  async reset() { this._data = this._createEmpty(); await this.save(); }
};
