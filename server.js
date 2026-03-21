/* hybrid server: signaling + temp file relay with lifecycle control */
import { WebSocketServer } from 'ws';
import http from 'http';
import fs from 'fs';

const port = process.env.PORT || 3000;

/* ─────────────────────────────────────────────
   CONFIG
───────────────────────────────────────────── */
const ROOM_TTL = 1000 * 60 * 10; /* 10 min */
const MAX_PEERS_PER_ROOM = 3;     /* 3 */
const rooms = new Map();           /* roomId => { peers: Set(ws), lastActive: timestamp } */

/* ─────────────────────────────────────────────
   SERVER
───────────────────────────────────────────── */
const wss = new WebSocketServer({ port });

function validateMessage(msg) {
  if (typeof msg !== 'object' || msg === null) return false;
  const keys = Object.keys(msg);
  return keys.every(k =>
	['join', 'signal', 'file', 'checkPeers'].includes(k)
  );
}

function cleanupRooms() {
  const now = Date.now();
  for (const [id, room] of rooms) {
	if (now - room.lastActive > ROOM_TTL || room.peers.size === 0) {
	  rooms.delete(id);
	  console.log('Deleted stale room:', id);
	}
  }
}

setInterval(cleanupRooms, 60 * 1000); /* every minute */

wss.on('connection', ws => {
  let roomId = null;

  ws.on('message', data => {
	let msg;
	try { msg = JSON.parse(data); } catch { return; }
	if (!validateMessage(msg)) return; /* basic validation */

	if (msg.join) {
	  roomId = msg.join;
	  if (!rooms.has(roomId)) rooms.set(roomId, { peers: new Set(), lastActive: Date.now() });
	  const room = rooms.get(roomId);

	  if (room.peers.size >= MAX_PEERS_PER_ROOM) {
		ws.send(JSON.stringify({ error: 'Room full' }));
		ws.close();
		return;
	  }

	  room.peers.add(ws);
	  room.lastActive = Date.now();

	  /* notify others */
	  room.peers.forEach(peer => {
		if (peer !== ws && peer.readyState === 1) peer.send(JSON.stringify({ peerJoined: true }));
	  });
	}

	if (roomId && rooms.has(roomId)) {
	  const room = rooms.get(roomId);
	  room.lastActive = Date.now();

	  /* relay signals & files */
	  if (msg.signal || msg.file || msg.checkPeers) {
		room.peers.forEach(peer => {
		  if (peer !== ws && peer.readyState === 1) {
			peer.send(JSON.stringify(msg));
		  }
		});
	  }
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
});

console.log('WebSocket server running on port', port);
