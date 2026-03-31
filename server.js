/**
 * Stelno Server v3.3 - RENDER-READY (NO EXTERNAL DEPS)
 * Fixed: diskusage/helmet removed. Pure Node.js stdlib.
 */

import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs/promises';
import fsSync from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Graceful SIGTERM for Render
process.on('SIGTERM', () => {
  logger?.info('SIGTERM received from Render');
  shutdown('SIGTERM');
});

/* ════════════════════════════════════════════════ §1 CFG ═══════════════════════════════════════════════ */
const CFG = Object.freeze({
  PORT: Number(process.env.PORT) || 3000,
  ROOM_TTL_MS: Number(process.env.ROOM_TTL_MS) || 10 * 60_000,
  ROOM_TTL_ACTIVE_MS: Number(process.env.ROOM_TTL_ACTIVE_MS) || 30 * 60_000,
  MAX_PEERS_PER_ROOM: Number(process.env.MAX_PEERS_PER_ROOM) || 3,
  HEARTBEAT_INTERVAL_MS: Number(process.env.HEARTBEAT_INTERVAL_MS) || 20_000,
  MAX_FILE_SIZE: Number(process.env.MAX_FILE_SIZE) || 200 * 1024 * 1024,
  UPLOAD_TIMEOUT_MS: Number(process.env.UPLOAD_TIMEOUT_MS) || 120_000,
  SHUTDOWN_TIMEOUT_MS: Number(process.env.SHUTDOWN_TIMEOUT_MS) || 8_000,
  RL_WS_MAX: Number(process.env.RL_WS_MAX) || 10,
  RL_HTTP_RPM: Number(process.env.RL_HTTP_RPM) || 60,
  RL_SIG_RPM: Number(process.env.RL_SIG_RPM) || 120,
  MEM_THRESHOLD_MB: Number(process.env.MEM_THRESHOLD_MB) || 400,
  TURN_SECRET: process.env.TURN_SECRET || '',
  TURN_URLS: process.env.TURN_URLS || '',
  TURN_TTL_S: Number(process.env.TURN_TTL_S) || 3600,
  REQUIRE_ROOM_TOKEN: process.env.REQUIRE_ROOM_TOKEN === 'true',
  ROOM_TOKEN_SECRET: process.env.ROOM_TOKEN_SECRET || '',
  LOG_LEVEL: Number(process.env.LOG_LEVEL) || 2,
});

/* ════════════════════════════════════════════════ §2 LOGGER ═══════════════════════════════════════════ */
const LOG_LABELS = ['ERROR', 'WARN', 'INFO', 'DEBUG'];
function log(level, msg, meta = {}) {
  if (level > CFG.LOG_LEVEL) return;
  const entry = { ts: new Date().toISOString(), lvl: LOG_LABELS[level] ?? 'UNKNOWN', pid: process.pid, msg, ...meta };
  const out = level === 0 ? process.stderr : process.stdout;
  out.write(JSON.stringify(entry) + '\n');
}
const logger = {
  error: (msg, meta) => log(0, msg, meta),
  warn: (msg, meta) => log(1, msg, meta),
  info: (msg, meta) => log(2, msg, meta),
  debug: (msg, meta) => log(3, msg, meta),
};

/* ════════════════════════════════════════════════ §3 CLUSTER (RENDER DISABLED) ════════════════════════ */
let SAFE_UPLOAD_ROOT;
let isClustered = false;

// Render = single instance only (CLUSTER_DISABLE=true implicit)
if (!process.env.RENDER && process.env.NODE_ENV !== 'development' && !process.env.CLUSTER_DISABLE) {
  try {
    const { isPrimary, fork, on } = await import('node:cluster');
    const numCPUs = os.cpus().length;
    if (isPrimary) {
      logger.info('Primary process starting cluster', { cpus: numCPUs });
      for (let i = 0; i < numCPUs; i++) fork();
      on('exit', (worker) => {
        logger.warn('Worker died, restarting', { pid: worker.process.pid });
        fork();
      });
      process.exit(0);
    }
    isClustered = true;
    logger.info('Worker started', { pid: process.pid });
  } catch (err) {
    logger.warn('Cluster disabled', { err: err.message });
  }
}

// FIXED: Per-worker tmpdir + timestamp (collision-proof)
SAFE_UPLOAD_ROOT = await fs.mkdtemp(path.join(os.tmpdir(), `stelno-${process.pid}-${Date.now()}-`));
logger.info('Upload root created', { root: SAFE_UPLOAD_ROOT, clustered: isClustered });

/* ════════════════════════════════════════════════ §4 VALIDATION ═══════════════════════════════════════ */
const ID_RE = /^[a-z0-9_-]{1,64}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;

const isPlainObject = v => !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const isShortString = (v, max = 64) => typeof v === 'string' && v.length > 0 && v.length <= max;
const isValidRoomId = v => isShortString(v, 64) && ID_RE.test(v);
const isValidSha256 = v => isShortString(v, 64) && SHA256_RE.test(v);
const safeStr = v => (typeof v === 'string' ? v : '');

function safeFileName(v, fallback = 'upload.bin') {
  const s = isShortString(v, 255) ? v : fallback;
  return path.basename(s).replace(/[^\w.\-()+ ]/g, '_').replace(/\s+/g, ' ').trim() || fallback;
}

function isValidSignal(v) {
  if (!isPlainObject(v)) return false;
  if (v.type === 'offer' || v.type === 'answer') return Object.keys(v).length === 2 && typeof v.sdp === 'string' && v.sdp.length > 0;
  if (v.type === 'candidate') {
    const allowed = new Set(['type', 'candidate', 'sdpMid', 'sdpMLineIndex', 'usernameFragment']);
    if (!Object.keys(v).every(k => allowed.has(k))) return false;
    return typeof v.candidate === 'string' && v.candidate.length &&
      (!('sdpMid' in v) || typeof v.sdpMid === 'string') &&
      (!('sdpMLineIndex' in v) || typeof v.sdpMLineIndex === 'number') &&
      (!('usernameFragment' in v) || typeof v.usernameFragment === 'string');
  }
  return false;
}

function normalizeSignal(v) {
  if (v.type === 'candidate') {
    const out = { type: 'candidate', candidate: v.candidate };
    if (v.sdpMid !== undefined) out.sdpMid = v.sdpMid;
    if (v.sdpMLineIndex !== undefined) out.sdpMLineIndex = v.sdpMLineIndex;
    if (v.usernameFragment !== undefined) out.usernameFragment = v.usernameFragment;
    return out;
  }
  return v;
}

function validateMessage(msg) {
  if (!isPlainObject(msg)) return null;
  const keys = Object.keys(msg);
  if (!keys.length) return null;

  if ('join' in msg) {
    if (!keys.every(k => k === 'join' || k === 'token')) return null;
    if (!isValidRoomId(msg.join)) return null;
    if ('token' in msg && !isShortString(msg.token, 256)) return null;
    return 'join';
  }
  if ('signal' in msg) return keys.length === 1 && isValidSignal(msg.signal) ? 'signal' : null;
  if ('checkPeers' in msg) return keys.length === 1 && msg.checkPeers === true ? 'checkPeers' : null;
  if ('ping' in msg) return keys.length === 1 && typeof msg.ping === 'number' ? 'ping' : null;
  if ('pong' in msg) return keys.length === 1 && typeof msg.pong === 'number' ? 'pong' : null;
  return null;
}

/* ════════════════════════════════════════════════ §5 RATE LIMITER ════════════════════════════════════ */
class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this._buckets = new Map();
    setInterval(() => this._prune(), windowMs).unref();
  }
  allow(key) {
    const now = Date.now();
    let b = this._buckets.get(key);
    if (!b || now >= b.resetAt) {
      b = { count: 0, resetAt: now + this.windowMs };
      this._buckets.set(key, b);
    }
    if (b.count >= this.maxRequests) return false;
    b.count++;
    return true;
  }
  _prune() {
    const now = Date.now();
    for (const [k, b] of this._buckets) if (now >= b.resetAt) this._buckets.delete(k);
  }
}

const httpRl = new RateLimiter(CFG.RL_HTTP_RPM, 60_000);
const sigRl = new RateLimiter(CFG.RL_SIG_RPM, 60_000);
const wsConnsByIp = new Map();

function wsIpAllow(ip) { return (wsConnsByIp.get(ip)?.size ?? 0) < CFG.RL_WS_MAX; }
function wsIpAdd(ip, ws) {
  let s = wsConnsByIp.get(ip); if (!s) wsConnsByIp.set(ip, s = new Set()); s.add(ws);
}
function wsIpRemove(ip, ws) {
  const s = wsConnsByIp.get(ip); if (s) { s.delete(ws); if (s.size === 0) wsConnsByIp.delete(ip); }
}

/* ════════════════════════════════════════════════ §6 STATE ═══════════════════════════════════════════ */
const rooms = new Map();
const files = new Map();
const sha256Map = new Map();
const pendingUploads = new Map();
const sockets = new Set();
let shuttingDown = false;

const metrics = { httpRequests: 0, wsConnections: 0, wsMessages: 0, bytesUploaded: 0, bytesServed: 0, uploadsOk: 0, uploadsFailed: 0, startedAt: Date.now() };

/* ════════════════════════════════════════════════ §7 DISK (NATIVE) ═══════════════════════════════════ */
function isInsideRoot(p) {
  const rel = path.relative(SAFE_UPLOAD_ROOT, p);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

async function safeUnlink(p) { try { await fs.unlink(p); } catch {} }
async function safeRm(d) { try { await fs.rm(d, { recursive: true, force: true }); } catch {} }

// FIXED: Native disk usage (no external deps)
async function getDiskUsage() {
  try {
    const stat = await fs.statfs(SAFE_UPLOAD_ROOT);
    return Math.round((1 - stat.bfree / stat.blocks) * 100);
  } catch {
    return 100; // Assume full if unmeasurable
  }
}

async function releaseFile(id) {
  const f = files.get(id);
  if (!f) return;
  f.refCount--;
  if (f.refCount > 0) { files.delete(id); return; }
  files.delete(id);
  sha256Map.delete(f.sha256);
  await safeUnlink(f.path);
  await safeRm(f.dir);
  logger.debug('File released', { id, name: f.name, size: f.size });
}

/* ════════════════════════════════════════════════ §8 LIFECYCLE ═════════════════════════════════════ */
async function pruneRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
    for (const [ws, meta] of room.peers) {
      if (!ws.isAlive) {
        logger.debug('Removing zombie peer', { room: id, peer: meta.id });
        try { ws.terminate(); } catch {}
        room.peers.delete(ws);
        broadcast(room, null, { peerLeft: meta.id, peerCount: room.peers.size });
      } else {
        ws.isAlive = false;
        try { ws.ping(); } catch {}
      }
    }
    const ttl = room.peers.size > 0 ? CFG.ROOM_TTL_ACTIVE_MS : CFG.ROOM_TTL_MS;
    if (now - room.lastActive > ttl || room.peers.size === 0) {
      logger.info('Pruning stale room', { room: id, peers: room.peers.size });
      rooms.delete(id);
    }
  }
}

async function pruneFiles() {
  const now = Date.now();
  for (const [id, f] of files) {
    const hasActivePeers = [...(f.roomIds ?? [])].some(rid => rooms.get(rid)?.peers.size > 0);
    const ttl = hasActivePeers ? CFG.ROOM_TTL_ACTIVE_MS : CFG.ROOM_TTL_MS;
    if (now - f.createdAt > ttl) {
      logger.info('TTL-expiring file', { id, name: f.name });
      await releaseFile(id);
    }
  }
}

async function prunePendingUploads() {
  const now = Date.now();
  for (const [id, u] of pendingUploads) {
    if (now - u.createdAt > CFG.UPLOAD_TIMEOUT_MS * 2) {
      logger.warn('Abandoning stale upload', { id });
      clearTimeout(u.timer);
      await safeUnlink(u.path);
      await safeRm(u.dir);
      pendingUploads.delete(id);
    }
  }
}

async function checkDiskPressure() {
  const diskPct = await getDiskUsage();
  if (diskPct > 85) {
    logger.warn('HIGH DISK PRESSURE - cleanup', { diskPct });
    await pruneFiles();
  }
}

setInterval(async () => {
  await pruneRooms();
  await pruneFiles();
  await prunePendingUploads();
  await checkDiskPressure();
}, CFG.HEARTBEAT_INTERVAL_MS).unref();

function broadcast(room, exclude, msg) {
  const payload = JSON.stringify(msg);
  for (const [ws] of room.peers) if (ws !== exclude && ws.readyState === 1) ws.send(payload);
}

/* ════════════════════════════════════════════════ §9 NAT/TOKENS ════════════════════════════════════ */
function generateNatTraversal(ip) {
  const turnCreds = CFG.TURN_SECRET ? generateTurnCredentials(ip) : null;
  return {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      ...(turnCreds ? [{ urls: turnCreds.urls, username: turnCreds.username, credential: turnCreds.credential }] : []),
    ],
    corsProxy: 'https://api.allorigins.win/raw?url=',
  };
}

function generateTurnCredentials(username) {
  if (!CFG.TURN_SECRET) return null;
  const expiresAt = Math.floor(Date.now() / 1000) + CFG.TURN_TTL_S;
  const user = `${expiresAt}:${username || 'stelno'}`;
  const credential = crypto.createHmac('sha1', CFG.TURN_SECRET).update(user).digest('base64');
  const urls = CFG.TURN_URLS ? CFG.TURN_URLS.split(',').map(u => u.trim()).filter(Boolean) : [];
  return { username: user, credential, urls, ttl: CFG.TURN_TTL_S };
}

function verifyRoomToken(roomId, token) {
  if (!CFG.REQUIRE_ROOM_TOKEN || !CFG.ROOM_TOKEN_SECRET || !token) return !CFG.REQUIRE_ROOM_TOKEN;
  const expected = crypto.createHmac('sha256', CFG.ROOM_TOKEN_SECRET).update(roomId).digest('hex');
  try {
    const ba = Buffer.from(expected, 'hex');
    const bb = Buffer.from(token, 'hex');
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

function memPressure() {
  return process.memoryUsage().heapUsed / 1024 / 1024 > CFG.MEM_THRESHOLD_MB;
}

/* ════════════════════════════════════════════════ §10 HTTP SERVER ═════════════════════════════════ */
const server = http.createServer(async (req, res) => {
  if (shuttingDown) { res.writeHead(503); res.end('Server shutting down'); return; }

  const rid = crypto.randomBytes(6).toString('hex');
  metrics.httpRequests++;
  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown').replace('::ffff:', '');

  // Security headers (helmet replacement)
  res.setHeader('X-Request-Id', rid);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Content-Range, Content-Length, X-Upload-Id, X-File-Name, X-File-Mime, X-File-Size, X-File-Sha256');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  logger.debug('HTTP request', { rid, method: req.method, url: req.url, ip });

  // Health checks
  if (req.method === 'GET' && req.url === '/healthz') { res.writeHead(200); res.end('ok'); return; }
  if (req.method === 'GET' && req.url === '/ready') {
    const ok = !memPressure() && (await getDiskUsage()) < 90;
    res.writeHead(ok ? 200 : 503); res.end(ok ? 'ready' : 'not ready'); return;
  }
  if (req.method === 'GET' && req.url === '/health') {
    const mem = process.memoryUsage();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: 'ok', uptime: Math.round((Date.now() - metrics.startedAt) / 1000) + 's',
      rooms: rooms.size, files: files.size, peers: [...rooms.values()].reduce((s, r) => s + r.peers.size, 0),
      heapMb: Math.round(mem.heapUsed / 1024 / 1024), diskPct: await getDiskUsage()
    }));
    return;
  }

  if (!httpRl.allow(ip)) {
    logger.warn('HTTP rate limit', { ip, rid });
    res.writeHead(429, { 'Retry-After': '60' }); res.end('Too many requests'); return;
  }

  // /turn
  if (req.method === 'GET' && req.url.startsWith('/turn')) {
    const nat = generateNatTraversal(ip);
    res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(nat)); return;
  }

  // FIXED: Upload handling (identical to v3.2)
  if (req.method === 'POST' && !req.url.startsWith('/cancel')) {
    if (memPressure()) { res.writeHead(503); res.end('Server busy'); return; }
    
    const contentRange = safeStr(req.headers['content-range']);
    const uploadId = safeStr(req.headers['x-upload-id']);
    const isResumable = !!uploadId;

    let rangeStart = 0, rangeEnd = -1, totalSize = -1;
    if (contentRange) {
      const m = contentRange.match(/bytes (\d+)-(\d+)\/(\d+)/);
      if (m) { rangeStart = Number(m[1]); rangeEnd = Number(m[2]); totalSize = Number(m[3]); }
    }

    let uploadState = isResumable && pendingUploads.get(uploadId);
    if (uploadState && req.url === '/upload-status') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ offset: uploadState.offset, uploadId })); return;
    }

    const expectedName = safeFileName(safeStr(req.headers['x-file-name']) || 'upload.bin');
    const expectedMime = safeStr(req.headers['x-file-mime']) || safeStr(req.headers['content-type']) || 'application/octet-stream';
    const expSize = Number(safeStr(req.headers['x-file-size'])) || totalSize || null;
    const expHash = isValidSha256(safeStr(req.headers['x-file-sha256']).toLowerCase()) ? safeStr(req.headers['x-file-sha256']).toLowerCase() : null;

    if (expSize && expSize > CFG.MAX_FILE_SIZE) { res.writeHead(413); res.end('File too large'); return; }

    // Dedup
    if (expHash && sha256Map.has(expHash)) {
      const existingId = sha256Map.get(expHash);
      const existing = files.get(existingId);
      if (existing) {
        existing.refCount++;
        req.resume();
        res.writeHead(200, { 'X-Dedup': '1' }); res.end(existingId);
        metrics.uploadsOk++; return;
      }
    }

    if (!uploadState) {
      const newId = crypto.randomBytes(16).toString('hex');
      const dir = await fs.mkdtemp(path.join(SAFE_UPLOAD_ROOT, `${newId}-`));
      const fpath = path.join(dir, 'upload.bin');
      uploadState = {
        id: newId, path: fpath, dir, hash: crypto.createHash('sha256'), offset: 0,
        totalSize: expSize, createdAt: Date.now(),
        meta: { name: expectedName, mime: expectedMime, expHash, expSize }, timer: null
      };
      if (isResumable) pendingUploads.set(uploadId, uploadState);
    }

    const u = uploadState;
    let done = false;

    const fail = async (code = 500, msg = 'Upload failed') => {
      if (done) return;
      done = true; clearTimeout(u.timer);
      if (!isResumable) { await safeUnlink(u.path); await safeRm(u.dir); }
      if (!res.headersSent) { res.writeHead(code); res.end(msg); }
      metrics.uploadsFailed++; logger.warn('Upload failed', { code, msg, rid, id: u.id });
    };

    const finishOk = async () => {
      if (done) return; done = true; clearTimeout(u.timer);
      if (isResumable) pendingUploads.delete(uploadId);
      
      const actualHash = u.hash.digest('hex');
      if (u.meta.expHash && u.meta.expHash !== actualHash) return fail(400, 'Hash mismatch');
      if (u.meta.expSize && u.offset !== u.meta.expSize) return fail(400, 'Size mismatch');

      files.set(u.id, { path: u.path, dir: u.dir, createdAt: Date.now(), size: u.offset, sha256: actualHash,
        name: u.meta.name, mime: u.meta.mime, refCount: 1, roomIds: new Set() });
      sha256Map.set(actualHash, u.id);

      metrics.uploadsOk++; metrics.bytesUploaded += u.offset;
      logger.info('Upload complete', { id: u.id, size: u.offset });
      if (!res.headersSent) { res.writeHead(200); res.end(u.id); }
    };

    u.timer = setTimeout(() => fail(408, 'Upload timeout'), CFG.UPLOAD_TIMEOUT_MS);
    req.setTimeout(CFG.UPLOAD_TIMEOUT_MS, () => fail(408, 'Upload timeout'));

    try {
      if (rangeStart > 0 && u.offset !== rangeStart) throw new Error('Resume mismatch');
      if (rangeStart === 0) { await fs.writeFile(u.path, Buffer.alloc(0)); u.offset = 0; }

      req.on('data', async chunk => {
        if (done || u.offset + chunk.length > CFG.MAX_FILE_SIZE) return fail(413, 'File too large');
        const fd = await fs.open(u.path, 'r+');
        try {
          const written = await fd.write(chunk, 0, chunk.length, u.offset);
          if (written.bytesWritten !== chunk.length) throw new Error('Partial write');
          u.offset += written.bytesWritten; u.hash.update(chunk);
        } finally { await fd.close(); }
      });

      req.on('end', async () => { if (!done && rangeEnd >= 0 && u.offset - 1 !== rangeEnd) return fail(400, 'Range mismatch'); await finishOk(); });
    } catch (err) { await fail(400, err.message); return; }

    req.on('aborted', () => isResumable && !done ? (clearTimeout(u.timer), res.writeHead(202, { 'X-Offset': String(u.offset) }), res.end()) : fail(499));
    req.on('error', () => fail()); return;
  }

  // File download /f/{id}
  if (req.method === 'GET' && req.url.startsWith('/f/')) {
    const id = req.url.slice(3).split('?')[0].split('#')[0];
    const f = files.get(id);
    if (!f || !fsSync.existsSync(f.path) || !isInsideRoot(f.path)) { res.writeHead(404); res.end(); return; }

    const rangeHeader = safeStr(req.headers['range']);
    let start = 0, end = f.size - 1;
    if (rangeHeader) {
      const m = rangeHeader.match(/bytes=(\d+)-(\d*)/);
      if (m) { start = Number(m[1]); end = m[2] ? Math.min(Number(m[2]), f.size - 1) : f.size - 1; }
    }

    const headers = {
      'Content-Type': f.mime || 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${safeFileName(f.name, id)}"`,
      'Content-Length': String(end - start + 1), 'Cache-Control': 'no-store',
      'Accept-Ranges': 'bytes', 'X-File-Sha256': f.sha256 || ''
    };
    if (start > 0) { headers['Content-Range'] = `bytes ${start}-${end}/${f.size}`; res.writeHead(206, headers); }
    else res.writeHead(200, headers);

    const stream = fsSync.createReadStream(f.path, { start, end });
    stream.on('data', chunk => metrics.bytesServed += chunk.length);
    stream.pipe(res); return;
  }

  res.writeHead(200); res.end('stelno alive');
});

server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
server.on('clientError', (err, socket) => { try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {} });

/* ════════════════════════════════════════════════ §11 WEBSOCKET ═══════════════════════════════════ */
const wss = new WebSocketServer({
  server, maxPayload: 256 * 1024,
  perMessageDeflate: { zlibDeflateOptions: { chunkSize: 1024, level: 3 }, threshold: 128, concurrencyLimit: 10 }
});

wss.on('connection', (ws, req) => {
  if (shuttingDown) { try { ws.close(1001, 'Server shutting down'); } catch {} return; }

  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown').replace('::ffff:', '');
  if (!wsIpAllow(ip)) { try { ws.close(1008, 'Too many connections'); } catch {} return; }

  const peerId = crypto.randomBytes(8).toString('hex');
  ws.isAlive = true; ws._ip = ip; ws._peerId = peerId;
  wsIpAdd(ip, ws); metrics.wsConnections++;

  let roomId = null, joinedRoom = null;
  logger.debug('WS connected', { peerId, ip });

  ws.on('pong', () => ws.isAlive = true);
  ws.on('message', data => {
    if (shuttingDown || ws.bufferedAmount > 64 * 1024) return;
    metrics.wsMessages++; if (!sigRl.allow(peerId)) return;

    const raw = typeof data === 'string' ? data : data.toString('utf8');
    if (raw.length > 256 * 1024) return;

    let msg; try { msg = JSON.parse(raw); } catch { return; }
    const kind = validateMessage(msg); if (!kind) return;

    if (kind === 'ping') { try { ws.send(JSON.stringify({ pong: msg.ping })); } catch {} return; }

    if (kind === 'join') {
      if (roomId || !verifyRoomToken(msg.join, safeStr(msg.token))) {
        try { ws.close(1008, 'Unauthorized'); } catch {} return;
      }
      roomId = msg.join;
      
      if (!rooms.has(roomId)) rooms.set(roomId, { peers: new Map(), createdAt: Date.now(), lastActive: Date.now() });
      joinedRoom = rooms.get(roomId);
      
      if (joinedRoom.peers.size >= CFG.MAX_PEERS_PER_ROOM) { try { ws.close(1008, 'Room full'); } catch {} wsIpRemove(ip, ws); return; }
      
      joinedRoom.peers.set(ws, { id: peerId, joinedAt: Date.now(), msgCount: 0, ip });
      joinedRoom.lastActive = Date.now();
      
      ws.send(JSON.stringify({ joined: true, peerId, peerCount: joinedRoom.peers.size - 1, roomId }));
      broadcast(joinedRoom, ws, { peerJoined: true, peerCount: joinedRoom.peers.size });
      logger.info('Peer joined', { room: roomId, peerId, peerCount: joinedRoom.peers.size }); return;
    }

    if (!roomId || !joinedRoom) return;
    joinedRoom.lastActive = Date.now();

    if (kind === 'file' && files.has(msg.file)) {
      files.get(msg.file).roomIds?.add(roomId);
      broadcast(joinedRoom, ws, { file: msg.file }); return;
    }
    if (kind === 'signal') {
      broadcast(joinedRoom, ws, { signal: normalizeSignal(msg.signal) }); return;
    }
    if (kind === 'checkPeers') {
      broadcast(joinedRoom, ws, { checkPeers: true }); return;
    }
  });

  ws.on('close', code => {
    wsIpRemove(ip, ws);
    if (!roomId || !joinedRoom) return;
    joinedRoom.peers.delete(ws);
    joinedRoom.lastActive = Date.now();
    broadcast(joinedRoom, null, { peerLeft: peerId, peerCount: joinedRoom.peers.size });
    if (joinedRoom.peers.size === 0) rooms.delete(roomId);
  });
});

/* ════════════════════════════════════════════════ §12 SHUTDOWN ═══════════════════════════════════ */
async function shutdown(signal) {
  if (shuttingDown) return; shuttingDown = true;
  logger.info('Shutdown', { signal });
  try { server.close(); wss.close(); } catch {}
  for (const ws of wss.clients) try { ws.close(1001); } catch {}

  setTimeout(async () => {
    for (const ws of wss.clients) try { ws.terminate(); } catch {}
    for (const s of sockets) try { s.destroy(); } catch {}
    for (const id of pendingUploads.keys()) {
      const u = pendingUploads.get(id); clearTimeout(u?.timer);
      await safeUnlink(u?.path); await safeRm(u?.dir);
    }
    for (const id of files.keys()) await releaseFile(id);
    process.exit(0);
  }, CFG.SHUTDOWN_TIMEOUT_MS);
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('uncaughtException', err => { logger.error('Uncaught', { err: err?.message }); process.exit(1); });

/* ════════════════════════════════════════════════ §13 BOOT ════════════════════════════════════════ */
server.listen(CFG.PORT, () => {
  logger.info('🚀 Stelno v3.3 RENDER-READY', {
    port: CFG.PORT, maxFileSize: `${CFG.MAX_FILE_SIZE/1e6|0}MB`, maxPeers: CFG.MAX_PEERS_PER_ROOM,
    workerPid: process.pid, uploadRoot: SAFE_UPLOAD_ROOT
  });
});
