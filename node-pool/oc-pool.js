#!/usr/bin/env node
'use strict';

// OmegaCases mining pool server - single file, zero dependencies (Node
// built-ins only). Run with `node oc-pool.js`, or `./oc-pool.js` on Linux
// after `chmod +x`. Designed for a plain SSH session on a VPS: answer a few
// questions once, then it registers the pool with OmegaCases and stays
// running in the foreground, ready to be wrapped in tmux/screen/systemd.
//
// Implements:
//   - the operator side of /developer/docs/mining-pools (answers OmegaCases's
//     raw "PING" liveness probe with "PONG", polls for new blocks, calls
//     submit-block when the pool solves one)
//   - the OC-Miner Pool Protocol v1 (newline-delimited JSON) so oc-miner-gpu
//     and oc-miner-cpu (or anything else that speaks it) can connect, get
//     work, and submit shares.

const fs = require('fs');
const net = require('net');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const readline = require('readline');
const { URL } = require('url');

const CONFIG_PATH = path.join(__dirname, 'oc-pool-config.json');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function short(s) {
  return s && s.length > 12 ? s.slice(0, 12) : s;
}

function httpJson(method, urlStr, body, headers) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const data = body ? JSON.stringify(body) : null;
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method,
      headers: Object.assign(
        { 'Content-Type': 'application/json' },
        data ? { 'Content-Length': Buffer.byteLength(data) } : {},
        headers || {}
      ),
    };
    const req = https.request(options, (res) => {
      let raw = '';
      res.on('data', (c) => (raw += c));
      res.on('end', () => {
        let parsed;
        try {
          parsed = raw ? JSON.parse(raw) : {};
        } catch (e) {
          parsed = { raw };
        }
        resolve({ status: res.statusCode, body: parsed });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function easierTarget(targetHex, factor) {
  const max = (1n << 256n) - 1n;
  let t = BigInt('0x' + targetHex) * BigInt(factor);
  if (t > max) t = max;
  return t.toString(16).padStart(64, '0');
}

function hashFor(previousHash, idClean, nonce) {
  return crypto.createHash('sha256').update(previousHash).update(idClean).update(String(nonce)).digest('hex');
}

// ---------------------------------------------------------------------------
// Interactive setup

function ask(rl, question, defaultValue) {
  return new Promise((resolve) => {
    const suffix = defaultValue ? ` (${defaultValue})` : '';
    rl.question(`${question}${suffix}: `, (answer) => {
      answer = answer.trim();
      resolve(answer || defaultValue || '');
    });
  });
}

async function detectPublicIP() {
  try {
    const { status, body } = await httpJson('GET', 'https://api.ipify.org?format=json');
    if (status === 200 && body.ip) return body.ip;
  } catch (e) {
    // ignore - fall back to manual entry
  }
  return '';
}

async function promptSetup() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  console.log('=== OmegaCases Pool Setup ===');
  console.log(`This only runs once; your config is then saved to ${CONFIG_PATH}\n`);

  const api = (await ask(rl, 'OmegaCases API URL', 'https://omegacases.com')).replace(/\/+$/, '');
  const name = await ask(rl, 'What is the pool name?', 'My Pool');
  const ownerID = await ask(rl, 'Your OmegaCases user id (pool owner)');
  const port = parseInt(await ask(rl, 'What port do you want to put it on?', '3333'), 10);
  console.log('Detecting this machine\'s public IP...');
  const detectedIP = await detectPublicIP();
  const host = await ask(rl, 'Public host/IP miners and OmegaCases will reach this pool at', detectedIP);
  const shareFactor = parseInt(
    await ask(rl, 'Share difficulty factor (higher = easier/more frequent shares)', '4096'),
    10
  );
  const description = await ask(rl, 'Pool description', 'GPU/CPU mining pool');

  rl.close();

  if (!ownerID || !host) {
    console.error('\nOwner user id and host are both required. Re-run and fill them in.');
    process.exit(1);
  }

  return { api, name, ownerID, port, host, shareFactor, description };
}

async function registerPool(config) {
  console.log('\nRegistering pool with OmegaCases...');
  const { status, body } = await httpJson('POST', `${config.api}/api/mining/pools`, {
    owner_id: config.ownerID,
    name: config.name,
    host: config.host,
    port: config.port,
    ip_version: 'auto',
    description: config.description,
  });

  if (status !== 200 || !body.success) {
    console.error('Registration failed:', JSON.stringify(body));
    process.exit(1);
  }

  console.log(`Pool registered! id=${body.pool.id} status=${body.pool.status}`);
  console.log('Your API key has been saved to the config file - treat it like a password.');

  config.poolId = body.pool.id;
  config.apiKey = body.api_key;
  return config;
}

// ---------------------------------------------------------------------------
// Mining round state + block watcher

const round = {
  previousHash: '',
  networkTarget: 'f'.repeat(64),
  shareTarget: 'f'.repeat(64),
  shares: new Map(),
};

const clients = new Set();

function broadcastJob(config) {
  const line =
    JSON.stringify({
      type: 'job',
      pool_id: config.poolId,
      previous_hash: round.previousHash,
      target: round.shareTarget,
    }) + '\n';
  for (const socket of clients) {
    socket.write(line);
  }
}

async function watchBlocks(config) {
  for (;;) {
    try {
      const { status, body } = await httpJson('GET', `${config.api}/api/mining`);
      if (status === 200 && body.previous_hash && body.previous_hash !== round.previousHash) {
        round.previousHash = body.previous_hash;
        round.networkTarget = body.target;
        round.shareTarget = easierTarget(body.target, config.shareFactor);
        round.shares = new Map();
        console.log(
          `[job] new block prev=${short(round.previousHash)} network_target=${short(
            round.networkTarget
          )} share_target=${short(round.shareTarget)}`
        );
        broadcastJob(config);
      }
    } catch (e) {
      console.error('[job] fetch error:', e.message);
    }
    await sleep(5000);
  }
}

async function submitBlock(config, nonce, hash, sharesMap) {
  const shares = Array.from(sharesMap.entries()).map(([user_id, n]) => ({ user_id, shares: n }));
  try {
    const { status, body } = await httpJson(
      'POST',
      `${config.api}/api/mining/pools/${config.poolId}/submit-block`,
      { nonce, hash, shares },
      { Authorization: `Bearer ${config.apiKey}` }
    );
    console.log(`[block] submit-block response (${status}):`, JSON.stringify(body));
  } catch (e) {
    console.error('[block] submit-block FAILED:', e.message);
  }
}

// ---------------------------------------------------------------------------
// TCP server: OmegaCases's raw PING/PONG liveness check, plus the
// newline-delimited JSON OC-Miner Pool Protocol v1 for everything else.

function handleHello(config, socket, msg) {
  socket.userId = msg.user_id;
  socket.idClean = String(msg.user_id || '').replace(/-/g, '');
  clients.add(socket);
  console.log(`[conn] miner joined: ${socket.userId}`);
  if (round.previousHash) {
    socket.write(
      JSON.stringify({
        type: 'job',
        pool_id: config.poolId,
        previous_hash: round.previousHash,
        target: round.shareTarget,
      }) + '\n'
    );
  }
}

function handleShare(config, socket, msg) {
  const nonce = msg.nonce;
  const hash = msg.hash;
  const expected = hashFor(round.previousHash, socket.idClean, nonce);

  let accepted = false;
  let message = 'does not meet share target';
  let foundBlock = false;
  let sharesSnapshot = null;

  if (expected !== hash) {
    message = 'hash does not match nonce';
  } else if (hash < round.shareTarget) {
    const n = (round.shares.get(socket.userId) || 0) + 1;
    round.shares.set(socket.userId, n);
    accepted = true;
    message = `share #${n}`;
    if (hash < round.networkTarget) {
      foundBlock = true;
      sharesSnapshot = new Map(round.shares);
    }
  }

  socket.write(JSON.stringify({ type: 'share_result', accepted, message }) + '\n');

  if (foundBlock) {
    console.log(`[block] SOLVED by pool! nonce=${nonce} hash=${hash}`);
    submitBlock(config, nonce, hash, sharesSnapshot);
  }
}

function startServer(config) {
  const server = net.createServer((socket) => {
    socket.setNoDelay(true);
    let buffer = '';
    let firstLineSeen = false;

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');

      if (!firstLineSeen && buffer.indexOf('\n') === -1 && buffer.trim() === 'PING') {
        // OmegaCases's own liveness probe: raw "PING" -> raw "PONG"
        socket.end('PONG');
        firstLineSeen = true;
        return;
      }

      let idx;
      while ((idx = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, idx).trim();
        buffer = buffer.slice(idx + 1);
        if (!firstLineSeen && line === 'PING') {
          socket.end('PONG');
          firstLineSeen = true;
          return;
        }
        firstLineSeen = true;
        if (!line) continue;
        let msg;
        try {
          msg = JSON.parse(line);
        } catch (e) {
          continue;
        }
        if (msg.type === 'hello') handleHello(config, socket, msg);
        else if (msg.type === 'share') handleShare(config, socket, msg);
      }
    });

    socket.on('close', () => {
      if (clients.has(socket)) {
        clients.delete(socket);
        console.log(`[conn] miner left: ${socket.userId}`);
      }
    });
    socket.on('error', () => {});
  });

  server.listen(config.port, '0.0.0.0', () => {
    console.log(`\nOC pool server listening on 0.0.0.0:${config.port}`);
    console.log('Leave this running (tmux/screen/systemd) - Ctrl+C stops it.\n');
  });

  return server;
}

// ---------------------------------------------------------------------------

async function main() {
  let config;
  if (fs.existsSync(CONFIG_PATH)) {
    config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    console.log(`Loaded existing pool config "${config.name}" (id=${config.poolId}) from ${CONFIG_PATH}`);
    startServer(config);
  } else {
    config = await promptSetup();
    // Start listening BEFORE registering, so OmegaCases's liveness probe
    // never hits a closed port during the registration window.
    startServer(config);
    await registerPool(config);
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2), { mode: 0o600 });
    console.log('Config saved to', CONFIG_PATH);
  }

  watchBlocks(config);
}

main().catch((e) => {
  console.error('Fatal error:', e);
  process.exit(1);
});
