/* hybrid server: signaling + temp file relay with lifecycle control */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';

const port = process.env.PORT || 3000;

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const ROOM_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_PEERS_PER_ROOM = 3;
const HEARTBEAT_INTERVAL = 30000; /* 30 sec */
const MAX_FILE_SIZE = 100 * 1024 * 1024; /* 100MB */
const UPLOAD_TIMEOUT = 30000; /* 30 sec */

const ID_RE = /^[a-z0-9_-]{1,64}$/i;
const FILE_ID_RE = /^[a-f0-9]{32}$/i;
const SAFE_UPLOAD_ROOT = fs.mkdtempSync(path.join(os.tmpdir(), 'stelno-'));

const rooms = new Map(); /* roomId => { peers: Set(ws), lastActive: timestamp } */
const files = new Map(); /* fileId => { path, dir, createdAt, size } */

/* ─────────────────────────────────────────────
   HELPERS
───────────────────────────────────────────── */
function makeId() {
  return crypto.randomBytes(16).toString('hex');
}

function isShortString(v, max = 64) {
  return typeof v === 'string' && v.length > 0 && v.length <= max;
}

function isValidRoomId(v) {
  return isShortString(v, 64) && ID_RE.test(v);
}

function isValidFileId(v) {
  return isShortString(v, 64) && FILE_ID_RE.test(v) && files.has(v);
}

function isValidSignal(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
  if (v.type === 'offer' || v.type === 'answer') return true;
  return typeof v.candidate === 'string' && v.candidate.length > 0;
}

function validateMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return null;

  const keys = Object.keys(msg);
  if (!keys.length) return null;

  const allowed = ['join', 'signal', 'file', 'checkPeers'];
  if (!keys.every(k => allowed.includes(k))) return null;

  if (Object.prototype.hasOwnProperty.call(msg, 'join')) {
    return isValidRoomId(msg.join) ? 'join' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'signal')) {
    return isValidSignal(msg.signal) ? 'signal' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'file')) {
    return isValidFileId(msg.file) ? 'file' : null;
  }

  if (msg.checkPeers === true) {
    return 'checkPeers';
  }

  return null;
}

function safeUnlink(p) {
  try {
    if (p && fs.existsSync(p)) fs.unlinkSync(p);
  } catch {}
}

function safeRm(d) {
  try {
    if (d && fs.existsSync(d)) fs.rmSync(d, { recursive: true, force: true });
  } catch {}
}

function cleanupUpload(id) {
  const f = files.get(id);
  if (!f) return;
  safeUnlink(f.path);
  safeRm(f.dir);
  files.delete(id);
}

function cleanupRooms() {
  const now = Date.now();

  for (const [id, room] of rooms) {
    for (const peer of [...room.peers]) {
      if (peer.isAlive === false) {
        try { peer.terminate(); } catch {}
        room.peers.delete(peer);
      } else {
        peer.isAlive = false;
        try { peer.ping(); } catch {}
      }
    }

    if (now - room.lastActive > ROOM_TTL || room.peers.size === 0) {
      rooms.delete(id);
      console.log('Deleted stale room:', id);
    }
  }
}

function cleanupFiles() {
  const now = Date.now();
  for (const [id, f] of files) {
    if (now - f.createdAt > ROOM_TTL) cleanupUpload(id);
  }
}

setInterval(cleanupRooms, HEARTBEAT_INTERVAL).unref();
setInterval(cleanupFiles, HEARTBEAT_INTERVAL).unref();

/* ─────────────────────────────────────────────
   HTTP + WS SERVER
───────────────────────────────────────────── */
const server = http.createServer((req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  /* ── Fallback upload ── */
  if (req.method === 'POST') {
    const id = makeId();
    const dir = fs.mkdtempSync(path.join(SAFE_UPLOAD_ROOT, `${id}-`));
    const filePath = path.join(dir, 'upload.bin');
    const stream = fs.createWriteStream(filePath, { flags: 'w' });

    let size = 0;
    let done = false;

    const cleanup = () => {
      try { stream.destroy(); } catch {}
      try { req.destroy(); } catch {}
      safeUnlink(filePath);
      safeRm(dir);
    };

    const finishOk = () => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      files.set(id, {
        path: filePath,
        dir,
        createdAt: Date.now(),
        size
      });
      try {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(id);
      } catch {}
    };

    const fail = (code = 500, msg = 'Upload failed') => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      cleanup();
      try {
        if (!res.headersSent) res.writeHead(code, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(msg);
      } catch {}
    };

    const timer = setTimeout(() => {
      fail(408, 'Upload timeout');
    }, UPLOAD_TIMEOUT);
    timer.unref();

    req.setTimeout(UPLOAD_TIMEOUT, () => {
      fail(408, 'Upload timeout');
    });

    req.on('data', chunk => {
      if (done) return;

      size += chunk.length;
      if (size > MAX_FILE_SIZE) {
        fail(413, 'File too large');
        return;
      }

      if (!stream.write(chunk)) {
        req.pause();
      }
    });

    stream.on('drain', () => {
      if (done) return;
      try { req.resume(); } catch {}
    });

    req.on('end', () => {
      if (done) return;
      stream.end(() => finishOk());
    });

    req.on('aborted', () => {
      fail(499, 'Client aborted');
    });

    req.on('close', () => {
      if (!done && size > 0) fail(499, 'Client closed');
    });

    req.on('error', () => {
      fail();
    });

    stream.on('error', () => {
      fail();
    });

    return;
  }

  /* ── Fallback download ── */
  if (req.method === 'GET' && req.url.startsWith('/f/')) {
    const id = req.url.split('/f/')[1];
    const f = files.get(id);

    if (!f || !fs.existsSync(f.path) || !f.path.startsWith(SAFE_UPLOAD_ROOT)) {
      res.writeHead(404);
      res.end();
      return;
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${id}"`);
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');

    const s = fs.createReadStream(f.path);
    s.on('error', () => {
      try { res.destroy(); } catch {}
    });
    s.pipe(res);
    return;
  }

  res.end('stelno alive');
});

server.on('clientError', (err, socket) => {
  try {
    socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  } catch {}
});

const wss = new WebSocketServer({ server });

/* ─────────────────────────────────────────────
   CONNECTION HANDLER
───────────────────────────────────────────── */
wss.on('connection', ws => {
  let roomId = null;
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', data => {
    let msg;
    try {
      msg = JSON.parse(typeof data === 'string' ? data : data.toString());
    } catch {
      return;
    }

    const kind = validateMessage(msg);
    if (!kind) return;

    if (kind === 'join') {
      roomId = msg.join;

      if (!rooms.has(roomId)) {
        rooms.set(roomId, { peers: new Set(), lastActive: Date.now() });
      }

      const room = rooms.get(roomId);

      if (room.peers.size >= MAX_PEERS_PER_ROOM) {
        try { ws.send(JSON.stringify({ error: 'Room full' })); } catch {}
        try { ws.close(); } catch {}
        return;
      }

      room.peers.add(ws);
      room.lastActive = Date.now();

      room.peers.forEach(peer => {
        if (peer !== ws && peer.readyState === 1) {
          try { peer.send(JSON.stringify({ peerJoined: true })); } catch {}
        }
      });

      return;
    }

    if (!roomId || !rooms.has(roomId)) return;

    const room = rooms.get(roomId);
    room.lastActive = Date.now();

    if (kind === 'signal' || kind === 'file' || kind === 'checkPeers') {
      room.peers.forEach(peer => {
        if (peer !== ws && peer.readyState === 1) {
          try {
            peer.send(JSON.stringify(msg));
          } catch {}
        }
      });
    }
  });

  ws.on('close', () => {
    if (!roomId) return;
    const room = rooms.get(roomId);
    if (!room) return;

    room.peers.delete(ws);
    room.lastActive = Date.now();

    if (room.peers.size === 0) rooms.delete(roomId);
  });

  ws.on('error', () => {});
});

server.listen(port, () => {
  console.log('WebSocket server running on port', port);
});
