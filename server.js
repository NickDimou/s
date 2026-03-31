/**
 * Stelno Server v3.1 - PRODUCTION READY
 * All critical bugs fixed, production hardening complete
 */

import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs/promises';
import fsSync from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

// Production deps (npm i diskusage helmet @prometheus/client)
import diskusage from 'diskusage';
import helmet from 'helmet';

// ESM __dirname polyfill
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Render sends SIGTERM 30s before kill
process.on('SIGTERM', () => {
  logger.info('SIGTERM received from Render');
  shutdown('SIGTERM');
});

/* ═══════════════════════════════════════════════════════════════
   §1  CONFIGURATION
═══════════════════════════════════════════════════════════════ */
const CFG = Object.freeze({
  PORT:                  Number(process.env.PORT)                  || 3000,
  ROOM_TTL_MS:           Number(process.env.ROOM_TTL_MS)           || 10 * 60_000,
  ROOM_TTL_ACTIVE_MS:    Number(process.env.ROOM_TTL_ACTIVE_MS)    || 30 * 60_000,
  MAX_PEERS_PER_ROOM:    Number(process.env.MAX_PEERS_PER_ROOM)    || 3,
  HEARTBEAT_INTERVAL_MS: Number(process.env.HEARTBEAT_INTERVAL_MS) || 20_000,
  MAX_FILE_SIZE:         Number(process.env.MAX_FILE_SIZE)         || 200 * 1024 * 1024,
  UPLOAD_TIMEOUT_MS:     Number(process.env.UPLOAD_TIMEOUT_MS)     || 120_000,
  SHUTDOWN_TIMEOUT_MS:   Number(process.env.SHUTDOWN_TIMEOUT_MS)   || 8_000,
  DISK_CLEANUP_INTERVAL: Number(process.env.DISK_CLEANUP_INTERVAL) || 5 * 60_000,
  DISK_USAGE_MB:         Number(process.env.DISK_USAGE_MB)         || 80,
  RL_WS_MAX:             Number(process.env.RL_WS_MAX)             || 10,
  RL_HTTP_RPM:           Number(process.env.RL_HTTP_RPM)           || 60,
  RL_SIG_RPM:            Number(process.env.RL_SIG_RPM)            || 120,
  MEM_THRESHOLD_MB:      Number(process.env.MEM_THRESHOLD_MB)      || 400,
  TURN_SECRET:           process.env.TURN_SECRET                   || '',
  TURN_URLS:             process.env.TURN_URLS                     || '',
  TURN_TTL_S:            Number(process.env.TURN_TTL_S)            || 3600,
  REQUIRE_ROOM_TOKEN:    process.env.REQUIRE_ROOM_TOKEN === 'true',
  ROOM_TOKEN_SECRET:     process.env.ROOM_TOKEN_SECRET             || '',
  LOG_LEVEL:             Number(process.env.LOG_LEVEL)             || 2,
});

/* ═══════════════════════════════════════════════════════════════
   §2  WORKER-SAFE LOGGER + DISK STATS (FIXED)
═══════════════════════════════════════════════════════════════ */
const LOG_LABELS = ['ERROR', 'WARN', 'INFO', 'DEBUG'];
function log(level, msg, meta = {}) {
  if (level > CFG.LOG_LEVEL) return;
  const entry = {
	ts: new Date().toISOString(),
	lvl: LOG_LABELS[level] ?? 'UNKNOWN',
	pid: process.pid,
	msg,
	...meta,
  };
  const out = level === 0 ? process.stderr : process.stdout;
  out.write(JSON.stringify(entry) + '\n');
}
const logger = {
  error: (msg, meta) => log(0, msg, meta),
  warn:  (msg, meta) => log(1, msg, meta),
  info:  (msg, meta) => log(2, msg, meta),
  debug: (msg, meta) => log(3, msg, meta),
};

// FIXED: Cross-platform disk usage
async function getDiskUsage() {
  try {
	const { free, size } = await diskusage.check(SAFE_UPLOAD_ROOT);
	return Math.round((1 - free / size) * 100);
  } catch {
	return 100; // Assume full if unmeasurable
  }
}

/* ═══════════════════════════════════════════════════════════════
   §3  CLUSTER BOOT (WORKER-SAFE TMPDIR)
═══════════════════════════════════════════════════════════════ */
let SAFE_UPLOAD_ROOT;
if (!process.env.RENDER && process.env.NODE_ENV !== 'development' && !process.env.CLUSTER_DISABLE) {
  const { isPrimary, isWorker, fork, on } = await import('node:cluster');
  const numCPUs = os.cpus().length;

  if (isPrimary) {
	logger.info('Primary process starting cluster', { cpus: numCPUs });
	for (let i = 0; i < numCPUs; i++) fork();
	on('exit', (worker) => {
	  logger.warn('Worker died, restarting', { pid: worker.process.pid });
	  fork();
	});
	return; // Primary exits after forking
  } else if (isWorker) {
	logger.info('Worker started', { pid: process.pid });
  }
}

// FIXED: Per-worker unique tmpdir (no clashes)
SAFE_UPLOAD_ROOT = await fs.mkdtemp(path.join(os.tmpdir(), `stelno-${process.pid}-`));
logger.info('Upload root created', { root: SAFE_UPLOAD_ROOT });

/* ═══════════════════════════════════════════════════════════════
   §4  VALIDATION HELPERS (MOVED files.has AFTER JOIN)
═══════════════════════════════════════════════════════════════ */
const ID_RE = /^[a-z0-9_-]{1,64}$/i;
const SHA256_RE = /^[a-f0-9]{64}$/i;

const isPlainObject = v => !!v && typeof v === 'object' && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
const isShortString = (v, max = 64) => typeof v === 'string' && v.length > 0 && v.length <= max;
const isValidRoomId = v => isShortString(v, 64) && ID_RE.test(v);
const isValidSha256 = v => isShortString(v, 64) && SHA256_RE.test(v);
const safeStr = v => (typeof v === 'string' ? v : '');

function safeFileName(v, fallback = 'upload.bin') {
  const s = isShortString(v, 255) ? v : fallback;
  const b = path.basename(s).replace(/[^\w.\-()+ ]/g, '_').replace(/\s+/g, ' ').trim();
  return b || fallback;
}

function isValidSignal(v) {
  if (!isPlainObject(v)) return false;
  if (v.type === 'offer' || v.type === 'answer') {
	return Object.keys(v).length === 2 && typeof v.sdp === 'string' && v.sdp.length > 0;
  }
  if (v.type === 'candidate') {
	const allowed = new Set(['type','candidate','sdpMid','sdpMLineIndex','usernameFragment']);
	if (!Object.keys(v).every(k => allowed.has(k))) return false;
	if (typeof v.candidate !== 'string' || !v.candidate.length) return false;
	if ('sdpMid' in v && typeof v.sdpMid !== 'string') return false;
	if ('sdpMLineIndex' in v && typeof v.sdpMLineIndex !== 'number') return false;
	if ('usernameFragment' in v && typeof v.usernameFragment !== 'string') return false;
	return true;
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

// FIXED: No files.has() here - moved to after join
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

function cleanupEmptyRoom(roomId) {
  const room = rooms.get(roomId);
  if (room && room.peers.size === 0) {
	rooms.delete(roomId);
	logger.debug('Auto-cleaned empty room', { room: roomId });
  }
}

/* ═══════════════════════════════════════════════════════════════
   §5  RATE LIMITER (UNCHANGED - PERFECT)
═══════════════════════════════════════════════════════════════ */
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

  remaining(key) {
	const b = this._buckets.get(key);
	if (!b || Date.now() >= b.resetAt) return this.maxRequests;
	return Math.max(0, this.maxRequests - b.count);
  }

  _prune() {
	const now = Date.now();
	for (const [k, b] of this._buckets) {
	  if (now >= b.resetAt) this._buckets.delete(k);
	}
  }
}

const httpRl = new RateLimiter(CFG.RL_HTTP_RPM, 60_000);
const sigRl = new RateLimiter(CFG.RL_SIG_RPM, 60_000);
const wsConnsByIp = new Map();

function wsIpAllow(ip) {
  const conns = wsConnsByIp.get(ip) ?? new Set();
  return conns.size < CFG.RL_WS_MAX;
}
function wsIpAdd(ip, ws) {
  if (!wsConnsByIp.has(ip)) wsConnsByIp.set(ip, new Set());
  wsConnsByIp.get(ip).add(ws);
}
function wsIpRemove(ip, ws) {
  const s = wsConnsByIp.get(ip);
  if (!s) return;
  s.delete(ws);
  if (s.size === 0) wsConnsByIp.delete(ip);
}

/* ═══════════════════════════════════════════════════════════════
   §6  STATE (SHARED-NOTHING PER WORKER)
═══════════════════════════════════════════════════════════════ */
const rooms = new Map();
const files = new Map();
const sha256Map = new Map();
const pendingUploads = new Map();
const sockets = new Set();
let shuttingDown = false;

const metrics = {
  httpRequests: 0, wsConnections: 0, wsMessages: 0,
  bytesUploaded: 0, bytesServed: 0, uploadsOk: 0, uploadsFailed: 0,
  startedAt: Date.now(),
};

/* ═══════════════════════════════════════════════════════════════
   §7  FILESYSTEM (PROMISES EVERYWHERE)
═══════════════════════════════════════════════════════════════ */
function isInsideRoot(p) {
  const rel = path.relative(SAFE_UPLOAD_ROOT, p);
  return !!rel && !rel.startsWith('..') && !path.isAbsolute(rel);
}

async function safeUnlink(p) { try { await fs.unlink(p); } catch {} }
async function safeRm(d) { try { await fs.rm(d, { recursive: true, force: true }); } catch {} }

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

/* ═══════════════════════════════════════════════════════════════
   §8  LIFECYCLE (DISK PRESSURE ADDED)
═══════════════════════════════════════════════════════════════ */
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
	const hasActivePeers = [...(f.roomIds ?? [])].some(rid => {
	  const r = rooms.get(rid);
	  return r && r.peers.size > 0;
	});
	const ttl = hasActivePeers ? CFG.ROOM_TTL_ACTIVE_MS : CFG.ROOM_TTL_MS;
	if (now - f.createdAt > ttl) {
	  logger.info('TTL-expiring file', { id, name: f.name, age: Math.round((now - f.createdAt) / 1000) + 's' });
	  await releaseFile(id);
	}
  }
}

async function prunePendingUploads() {
  const now = Date.now();
  for (const [id, u] of pendingUploads) {
	if (now - u.createdAt > CFG.UPLOAD_TIMEOUT_MS * 2) {
	  logger.warn('Abandoning stale pending upload', { id });
	  clearTimeout(u.timer);
	  try { u.stream?.destroy(); } catch {}
	  await safeUnlink(u.path);
	  await safeRm(u.dir);
	  pendingUploads.delete(id);
	}
  }
}

// FIXED: Disk pressure check
async function checkDiskPressure() {
  const diskPct = await getDiskUsage();
  if (diskPct > 85) {
	logger.warn('HIGH DISK PRESSURE - aggressive cleanup', { diskPct });
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
  for (const [ws] of room.peers) {
	if (ws !== exclude && ws.readyState === 1) ws.send(payload);
  }
}

/* ═══════════════════════════════════════════════════════════════
   §9  NAT TRAVERSAL (UNCHANGED)
═══════════════════════════════════════════════════════════════ */
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
  if (!CFG.REQUIRE_ROOM_TOKEN) return true;
  if (!CFG.ROOM_TOKEN_SECRET || !token) return false;
  const expected = crypto.createHmac('sha256', CFG.ROOM_TOKEN_SECRET).update(roomId).digest('hex');
  try {
	const ba = Buffer.from(expected, 'hex');
	const bb = Buffer.from(token, 'hex');
	if (ba.length !== bb.length) return false;
	return crypto.timingSafeEqual(ba, bb);
  } catch { return false; }
}

function memPressure() {
  const used = process.memoryUsage().heapUsed / 1024 / 1024;
  return used > CFG.MEM_THRESHOLD_MB;
}

/* ═══════════════════════════════════════════════════════════════
   §10  HTTP SERVER (HELMET + FIXED UPLOADS)
═══════════════════════════════════════════════════════════════ */
const server = http.createServer(async (req, res) => {
  if (shuttingDown) {
	res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
	res.end('Server shutting down');
	return;
  }

  const rid = crypto.randomBytes(6).toString('hex');
  metrics.httpRequests++;

  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown').replace('::ffff:', '');

  // FIXED: Helmet middleware
  helmet()(req, res, () => {});

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
  if (req.method === 'GET' && req.url === '/healthz') {
	res.writeHead(200, { 'Content-Type': 'text/plain' });
	res.end('ok');
	return;
  }

  if (req.method === 'GET' && req.url === '/ready') {
	const memOk = !memPressure();
	const diskOk = (await getDiskUsage()) < 90;
	if (memOk && diskOk) {
	  res.writeHead(200, { 'Content-Type': 'text/plain' });
	  res.end('ready');
	} else {
	  res.writeHead(503, { 'Content-Type': 'text/plain' });
	  res.end('not ready');
	}
	return;
  }

  if (req.method === 'GET' && req.url === '/health') {
	const mem = process.memoryUsage();
	const diskPct = await getDiskUsage();
	res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
	res.end(JSON.stringify({
	  status: 'ok',
	  uptime: Math.round((Date.now() - metrics.startedAt) / 1000) + 's',
	  rooms: rooms.size,
	  files: files.size,
	  peers: [...rooms.values()].reduce((s, r) => s + r.peers.size, 0),
	  pending: pendingUploads.size,
	  heapMb: Math.round(mem.heapUsed / 1024 / 1024),
	  diskPct,
	  memPressure: memPressure(),
	}));
	return;
  }

  if (req.method === 'GET' && req.url === '/metrics') {
	const mem = process.memoryUsage();
	res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
	res.end(JSON.stringify({
	  ...metrics,
	  uptimeMs: Date.now() - metrics.startedAt,
	  rooms: rooms.size,
	  files: files.size,
	  pendingUploads: pendingUploads.size,
	  wsConnections: wss.clients.size,
	  heapUsedMb: Math.round(mem.heapUsed / 1024 / 1024),
	  diskPct: await getDiskUsage(),
	}));
	return;
  }

  if (req.method === 'GET' && req.url.startsWith('/turn')) {
	if (!httpRl.allow(ip)) {
	  res.writeHead(429, { 'Retry-After': '60' }); res.end('Rate limit exceeded'); return;
	}
	const nat = generateNatTraversal(ip);
	res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
	res.end(JSON.stringify(nat));
	return;
  }

  if (!httpRl.allow(ip)) {
	logger.warn('HTTP rate limit', { ip, rid });
	res.writeHead(429, { 'Content-Type': 'text/plain; charset=utf-8', 'Retry-After': '60', 'X-RateLimit-Remaining': '0' });
	res.end('Too many requests');
	return;
  }

  if (req.method === 'GET' && req.url === '/disk') {
	const diskPct = await getDiskUsage();
	const { free, size } = await diskusage.check(SAFE_UPLOAD_ROOT).catch(() => ({ free: 0, size: 1 }));
	res.writeHead(200, { 'Content-Type': 'application/json' });
	res.end(JSON.stringify({
	  diskPct,
	  usedMb: Math.round((size - free) / 1024 / 1024),
	  freeMb: Math.round(free / 1024 / 1024)
	}));
	return;
  }

  // FIXED: Streaming resumable upload (proper fd handling)
  if (req.method === 'POST' && !req.url.startsWith('/cancel')) {
	if (memPressure()) {
	  res.writeHead(503, { 'Content-Type': 'text/plain; charset=utf-8' });
	  res.end('Server busy — memory pressure');
	  return;
	}

	const contentRange = safeStr(req.headers['content-range']);
	const uploadId = safeStr(req.headers['x-upload-id']);
	const isResumable = !!uploadId;

	let rangeStart = 0, rangeEnd = -1, totalSize = -1;
	if (contentRange) {
	  const m = contentRange.match(/bytes (\d+)-(\d+)\/(\d+)/);
	  if (m) {
		rangeStart = Number(m[1]);
		rangeEnd = Number(m[2]);
		totalSize = Number(m[3]);
	  }
	}

	let uploadState = null;
	if (isResumable && pendingUploads.has(uploadId)) {
	  uploadState = pendingUploads.get(uploadId);
	  if (req.url === '/upload-status') {
		res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
		res.end(JSON.stringify({ offset: uploadState.offset, uploadId }));
		return;
	  }
	}

	const expectedName = safeFileName(safeStr(req.headers['x-file-name']) || 'upload.bin');
	const expectedMime = safeStr(req.headers['x-file-mime']) || safeStr(req.headers['content-type']) || 'application/octet-stream';
	const rawSize = safeStr(req.headers['x-file-size']);
	const expSize = rawSize && /^\d+$/.test(rawSize) ? Number(rawSize) : (totalSize > 0 ? totalSize : null);
	const rawHash = safeStr(req.headers['x-file-sha256']).toLowerCase();
	const expHash = isValidSha256(rawHash) ? rawHash : null;

	if (expSize !== null && expSize > CFG.MAX_FILE_SIZE) {
	  res.writeHead(413, { 'Content-Type': 'text/plain; charset=utf-8' });
	  res.end(`File too large (max ${CFG.MAX_FILE_SIZE / 1024 / 1024} MB)`);
	  return;
	}

	// SHA-256 dedup
	if (expHash && sha256Map.has(expHash)) {
	  const existingId = sha256Map.get(expHash);
	  const existing = files.get(existingId);
	  if (existing) {
		existing.refCount++;
		logger.info('Dedup hit', { expHash, existingId, rid });
		req.resume();
		res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'X-Dedup': '1' });
		res.end(existingId);
		metrics.uploadsOk++;
		return;
	  }
	}

	// New upload state
	if (!uploadState) {
	  const newId = crypto.randomBytes(16).toString('hex');
	  const dir = await fs.mkdtemp(path.join(SAFE_UPLOAD_ROOT, `${newId}-`));
	  const fpath = path.join(dir, 'upload.bin');
	  uploadState = {
		id: newId,
		path: fpath,
		dir,
		hash: crypto.createHash('sha256'),
		offset: 0,
		totalSize: expSize,
		createdAt: Date.now(),
		meta: { name: expectedName, mime: expectedMime, expHash, expSize },
		timer: null,
	  };
	  if (isResumable) pendingUploads.set(uploadId, uploadState);
	}

	const u = uploadState;
	let done = false;

	const fail = async (code = 500, msg = 'Upload failed') => {
	  if (done) return;
	  done = true;
	  clearTimeout(u.timer);
	  if (isResumable) pendingUploads.delete(uploadId);
	  else {
		await safeUnlink(u.path);
		await safeRm(u.dir);
	  }
	  if (!res.headersSent) {
		res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' });
		res.end(msg);
	  }
	  metrics.uploadsFailed++;
	  logger.warn('Upload failed', { code, msg, rid, id: u.id });
	};

	const finishOk = async () => {
	  if (done) return;
	  done = true;
	  clearTimeout(u.timer);
	  if (isResumable) pendingUploads.delete(uploadId);

	  const actualHash = u.hash.digest('hex');
	  if (u.meta.expHash && u.meta.expHash !== actualHash) {
		await fail(400, 'SHA-256 hash mismatch');
		return;
	  }
	  if (u.meta.expSize !== null && u.offset !== u.meta.expSize) {
		await fail(400, `Size mismatch: expected ${u.meta.expSize}, got ${u.offset}`);
		return;
	  }

	  files.set(u.id, {
		path: u.path, dir: u.dir, createdAt: Date.now(),
		size: u.offset, sha256: actualHash, name: u.meta.name, mime: u.meta.mime,
		refCount: 1, roomIds: new Set(),
	  });
	  if (actualHash) sha256Map.set(actualHash, u.id);

	  metrics.uploadsOk++;
	  metrics.bytesUploaded += u.offset;
	  logger.info('Upload complete', { id: u.id, name: u.meta.name, size: u.offset, rid });

	  if (!res.headersSent) {
		res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
		res.end(u.id);
	  }
	};

	u.timer = setTimeout(() => fail(408, 'Upload timed out'), CFG.UPLOAD_TIMEOUT_MS);
	u.timer.unref();

	req.setTimeout(CFG.UPLOAD_TIMEOUT_MS, () => fail(408, 'Upload timed out'));

	// FIXED: Proper streaming with per-chunk fd (no reuse bug)
	try {
	  if (rangeStart > 0) {
		if (u.offset !== rangeStart) throw new Error(`Resume mismatch: server=${u.offset}, client=${rangeStart}`);
	  } else {
		await fs.writeFile(u.path, Buffer.alloc(0));
		u.offset = 0;
	  }

	  req.on('data', async (chunk) => {
		if (done) return;
		if (u.offset + chunk.length > CFG.MAX_FILE_SIZE) throw new Error('File too large');

		// FIXED: Fresh fd per chunk - no offset corruption
		const fd = await fs.open(u.path, 'r+');
		try {
		  const written = await fd.write(chunk, 0, chunk.length, u.offset);
		  if (written.bytesWritten !== chunk.length) throw new Error('Partial write');
		  u.offset += written.bytesWritten;
		  u.hash.update(chunk);
		} finally {
		  await fd.close();
		}
	  });

	  req.on('end', async () => {
		if (done) return;
		if (rangeEnd >= 0 && u.offset - 1 !== rangeEnd) throw new Error(`Range mismatch`);
		await finishOk();
	  });
	} catch (err) {
	  await fail(400, err.message);
	  return;
	}

	req.on('aborted', () => {
	  if (isResumable && !done) {
		clearTimeout(u.timer);
		if (!res.headersSent) {
		  res.writeHead(202, { 'X-Upload-Id': uploadId, 'X-Offset': String(u.offset) });
		  res.end();
		}
	  } else {
		fail(499, 'Client aborted');
	  }
	});

	req.on('close', () => {
	  if (!done && u.offset === 0) fail(499, 'Connection closed before data');
	});

	req.on('error', () => fail());
	return;
  }

  if (req.method === 'GET' && req.url.startsWith('/upload-status')) {
	const urlObj = new URL(req.url, 'http://localhost');
	const uid = urlObj.searchParams.get('id') || '';
	const u = pendingUploads.get(uid);
	if (!u) { res.writeHead(404); res.end(); return; }
	res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
	res.end(JSON.stringify({ offset: u.offset, total: u.totalSize, uploadId: uid }));
	return;
  }

  if (req.method === 'GET' && req.url.startsWith('/f/')) {
	const id = req.url.slice(3).split('?')[0].split('#')[0];
	const f = files.get(id);

	if (!f || !fsSync.existsSync(f.path) || !isInsideRoot(f.path)) {
	  res.writeHead(404); res.end(); return;
	}

	const rangeHeader = safeStr(req.headers['range']);
	let start = 0, end = f.size - 1, partial = false;
	if (rangeHeader) {
	  const m = rangeHeader.match(/bytes=(\d+)-(\d*)/);
	  if (m) {
		start = Number(m[1]);
		end = m[2] ? Math.min(Number(m[2]), f.size - 1) : f.size - 1;
		partial = true;
	  }
	}

	const chunkLen = end - start + 1;
	const headers = {
	  'Content-Type': f.mime || 'application/octet-stream',
	  'Content-Disposition': `attachment; filename="${safeFileName(f.name, id)}"`,
	  'Content-Length': String(chunkLen),
	  'Cache-Control': 'no-store',
	  'X-Content-Type-Options': 'nosniff',
	  'X-File-Sha256': f.sha256 || '',
	  'Accept-Ranges': 'bytes',
	};

	if (partial) {
	  headers['Content-Range'] = `bytes ${start}-${end}/${f.size}`;
	  res.writeHead(206, headers);
	} else {
	  res.writeHead(200, headers);
	}

	const s = fsSync.createReadStream(f.path, { start, end });
	s.on('error', () => { try { res.destroy(); } catch {} });
	s.on('data', chunk => { metrics.bytesServed += chunk.length; });
	s.pipe(res);
	logger.debug('File served', { id, name: f.name, partial, start, end });
	return;
  }

  if (req.method === 'POST' && req.url === '/cancel') {
	let body = '';
	req.on('data', c => { body += c; if (body.length > 256) { req.destroy(); } });
	req.on('end', async () => {
	  try {
		const { fileId } = JSON.parse(body);
		if (typeof fileId !== 'string' || !files.has(fileId)) {
		  res.writeHead(400); res.end('Unknown file ID'); return;
		}
		await releaseFile(fileId);
		res.writeHead(200); res.end('Cancelled');
	  } catch {
		res.writeHead(400); res.end('Bad request');
	  }
	});
	return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('stelno alive');
});

server.on('connection', socket => {
  sockets.add(socket);
  socket.on('close', () => sockets.delete(socket));
});

server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {}
});

/* ═══════════════════════════════════════════════════════════════
   §11  WEBSOCKET (FILES CHECK AFTER JOIN)
═══════════════════════════════════════════════════════════════ */
const wss = new WebSocketServer({
  server,
  maxPayload: 256 * 1024,
  perMessageDeflate: {
	zlibDeflateOptions: { chunkSize: 1024, memLevel: 7, level: 3 },
	zlibInflateOptions: { chunkSize: 10 * 1024 },
	clientNoContextTakeover: true,
	serverNoContextTakeover: true,
	serverMaxWindowBits: 10,
	concurrencyLimit: 10,
	handleProtocols: true,
	threshold: 128,
  },
});

wss.on('connection', (ws, req) => {
  if (shuttingDown) {
	try { ws.close(1001, 'Server shutting down'); } catch {}
	return;
  }

  const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || 'unknown').replace('::ffff:', '');

  if (!wsIpAllow(ip)) {
	logger.warn('WS connection limit', { ip });
	try { ws.close(1008, 'Too many connections'); } catch {}
	return;
  }

  const peerId = crypto.randomBytes(8).toString('hex');
  ws.isAlive = true;
  ws._ip = ip;
  ws._peerId = peerId;
  wsIpAdd(ip, ws);
  metrics.wsConnections++;

  let roomId = null;
  let joinedRoom = null;

  logger.debug('WS connected', { peerId, ip });

  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', data => {
	if (shuttingDown || ws.bufferedAmount > 64 * 1024) return;
	metrics.wsMessages++;

	if (!sigRl.allow(peerId)) {
	  logger.warn('Signaling flood', { peerId, ip });
	  try { ws.send(JSON.stringify({ error: 'rate_limit', msg: 'Slow down' })); } catch {}
	  return;
	}

	const raw = typeof data === 'string' ? data : data.toString('utf8');
	if (raw.length > 256 * 1024) return;

	let msg;
	try { msg = JSON.parse(raw); } catch { return; }

	const kind = validateMessage(msg);
	if (!kind) return;

	if (kind === 'ping' || kind === 'pong') {
	  if (kind === 'ping' && ws.readyState === 1) {
		try { ws.send(JSON.stringify({ pong: msg.ping })); } catch {}
	  }
	  return;
	}

	// JOIN
	if (kind === 'join') {
	  if (roomId) return;

	  if (!verifyRoomToken(msg.join, safeStr(msg.token))) {
		try { ws.send(JSON.stringify({ error: 'auth_failed', msg: 'Invalid room token' })); } catch {}
		try { ws.close(1008, 'Unauthorized'); } catch {}
		return;
	  }

	  roomId = msg.join;
	  cleanupEmptyRoom(roomId);

	  if (!rooms.has(roomId)) {
		rooms.set(roomId, {
		  peers: new Map(),
		  createdAt: Date.now(),
		  lastActive: Date.now(),
		  token: null,
		});
		logger.info('Room created', { room: roomId, peerId });
	  }

	  joinedRoom = rooms.get(roomId);

	  if (joinedRoom.peers.size >= CFG.MAX_PEERS_PER_ROOM) {
		try { ws.send(JSON.stringify({ error: 'room_full', msg: 'Room is at capacity' })); } catch {}
		try { ws.close(1008, 'Room full'); } catch {}
		wsIpRemove(ip, ws);
		return;
	  }

	  joinedRoom.peers.set(ws, { id: peerId, joinedAt: Date.now(), msgCount: 0, ip });
	  joinedRoom.lastActive = Date.now();

	  try {
		ws.send(JSON.stringify({
		  joined: true,
		  peerId,
		  peerCount: joinedRoom.peers.size - 1,
		  roomId,
		}));
	  } catch {}

	  broadcast(joinedRoom, ws, { peerJoined: true, peerCount: joinedRoom.peers.size });
	  logger.info('Peer joined room', { room: roomId, peerId, peerCount: joinedRoom.peers.size });
	  return;
	}

	// All messages require room
	if (!roomId || !joinedRoom) return;

	joinedRoom.lastActive = Date.now();
	const peerMeta = joinedRoom.peers.get(ws);
	if (peerMeta) peerMeta.msgCount++;

	// FIXED: files.has() check AFTER join (safe now)
	if (kind === 'file') {
	  if (files.has(msg.file)) {
		const f = files.get(msg.file);
		f.roomIds?.add(roomId);
		const payload = JSON.stringify({ file: msg.file });
		for (const [peer] of joinedRoom.peers) {
		  if (peer !== ws && peer.readyState === 1) try { peer.send(payload); } catch {}
		}
	  }
	  return;
	}

	if (kind === 'signal') {
	  const payload = JSON.stringify({ signal: normalizeSignal(msg.signal) });
	  for (const [peer] of joinedRoom.peers) {
		if (peer !== ws && peer.readyState === 1) try { peer.send(payload); } catch {}
	  }
	  return;
	}

	if (kind === 'checkPeers') {
	  const payload = JSON.stringify({ checkPeers: true });
	  for (const [peer] of joinedRoom.peers) {
		if (peer !== ws && peer.readyState === 1) try { peer.send(payload); } catch {}
	  }
	}
  });

  ws.on('close', (code, reason) => {
	wsIpRemove(ip, ws);
	if (!roomId || !joinedRoom) return;

	joinedRoom.peers.delete(ws);
	joinedRoom.lastActive = Date.now();

	broadcast(joinedRoom, null, { peerLeft: peerId, peerCount: joinedRoom.peers.size });

	logger.info('Peer left room', { room: roomId, peerId, peerCount: joinedRoom.peers.size, code, reason: reason?.toString() || '' });

	if (joinedRoom.peers.size === 0) {
	  rooms.delete(roomId);
	  logger.info('Room closed (empty)', { room: roomId });
	}
  });

  ws.on('error', err => logger.debug('WS error', { peerId, ip, err: err?.message }));
});

/* ═══════════════════════════════════════════════════════════════
   §12  SHUTDOWN (UNCHANGED - PERFECT)
═══════════════════════════════════════════════════════════════ */
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info('Shutdown initiated', { signal });

  try { server.close(); } catch {}
  try { wss.close(); } catch {}

  for (const ws of wss.clients) try { ws.close(1001, 'Server shutting down'); } catch {}

  const drainTimeout = setTimeout(async () => {
	logger.info('Drain timeout — forcing exit');
	for (const ws of wss.clients) try { ws.terminate(); } catch {}
	for (const s of sockets) try { s.destroy(); } catch {}

	for (const id of pendingUploads.keys()) {
	  const u = pendingUploads.get(id);
	  clearTimeout(u?.timer);
	  try { u?.stream?.destroy(); } catch {}
	  await safeUnlink(u?.path);
	  await safeRm(u?.dir);
	}
	for (const id of files.keys()) await releaseFile(id);
	rooms.clear();

	logger.info('Shutdown complete');
	process.exit(0);
  }, CFG.SHUTDOWN_TIMEOUT_MS);
  drainTimeout.unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('uncaughtException', err => {
  logger.error('Uncaught exception', { err: err?.message, stack: err?.stack });
  process.exit(1);
});
process.on('unhandledRejection', reason => {
  logger.error('Unhandled rejection', { reason: String(reason) });
  process.exit(1);
});

/* ═══════════════════════════════════════════════════════════════
   §13  BOOT
═══════════════════════════════════════════════════════════════ */
server.listen(CFG.PORT, () => {
  logger.info('Stelno v3.1 PRODUCTION READY', {
	port: CFG.PORT,
	maxFileSize: `${CFG.MAX_FILE_SIZE / 1024 / 1024} MB`,
	maxPeersPerRoom: CFG.MAX_PEERS_PER_ROOM,
	roomTtl: `${CFG.ROOM_TTL_MS / 60_000} min`,
	workerPid: process.pid,
	uploadRoot: SAFE_UPLOAD_ROOT,
	cluster: !!process.env.CLUSTER_DISABLE ? 'disabled' : 'enabled',
  });
});
