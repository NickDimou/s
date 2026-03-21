/* hybrid server: signaling + temp file relay with lifecycle control */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';

const port = process.env.PORT || 3000;

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const ROOM_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_PEERS_PER_ROOM = 3;
const HEARTBEAT_INTERVAL = 30000; /* 30 sec */
const rooms = new Map(); /* roomId => { peers: Set(ws), lastActive: timestamp } */
const files = new Map(); /* fileId => metadata, if you wire upload fallback later */

/* ─────────────────────────────────────────────
   SERVER
───────────────────────────────────────────── */
const wss = new WebSocketServer({ port });

function isShortString(v, max = 64) {
  return typeof v === 'string' && v.length > 0 && v.length <= max;
}

function isValidSignal(v) {
  if (!v || typeof v !== 'object') return false;

  /* WebRTC offer/answer */
  if (v.type === 'offer' || v.type === 'answer') return true;

  /* ICE candidate object */
  return typeof v.candidate === 'string' && v.candidate.length > 0;
}

function isKnownFileId(v) {
  if (!isShortString(v, 128)) return false;

  /* if you later populate files from fallback upload, this becomes strict */
  return files.size === 0 || files.has(v);
}

function validateMessage(msg) {
  if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return null;

  const keys = Object.keys(msg);
  if (!keys.length) return null;

  const allowed = ['join', 'signal', 'file', 'checkPeers'];
  if (!keys.every(k => allowed.includes(k))) return null;

  if (Object.prototype.hasOwnProperty.call(msg, 'join')) {
    return isShortString(msg.join, 64) ? 'join' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'signal')) {
    return isValidSignal(msg.signal) ? 'signal' : null;
  }

  if (Object.prototype.hasOwnProperty.call(msg, 'file')) {
    return isKnownFileId(msg.file) ? 'file' : null;
  }

  if (msg.checkPeers === true) {
    return 'checkPeers';
  }

  return null;
}

function cleanupRooms() {
  const now = Date.now();

  for (const [id, room] of rooms) {
    for (const peer of room.peers) {
      /* remove dead sockets */
      if (peer.isAlive === false) {
        peer.terminate();
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

setInterval(cleanupRooms, HEARTBEAT_INTERVAL);

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

      /* notify others */
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

    /* relay signals & files */
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

console.log('WebSocket server running on port', port);
