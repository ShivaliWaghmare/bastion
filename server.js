'use strict';
const http = require('http');
const config = require('./src/config');
const db = require('./src/db');
const { createApp } = require('./src/app');

const [major, minor] = process.versions.node.split('.').map(Number);
if (major < 18 || (major === 18 && minor < 18)) {
  console.error(`Bastion needs Node.js 18.18 or newer (you have ${process.versions.node}). Install the LTS from https://nodejs.org`);
  process.exit(1);
}

const handler = createApp().handler();
const MAX_PORT_TRIES = 10;

function start(port, attempt = 0) {
  const server = http.createServer(handler);
  // Slowloris-style protection
  server.headersTimeout = 15_000;
  server.requestTimeout = 30_000;
  server.keepAliveTimeout = 5_000;

  server.on('listening', () => {
    const url = `http://localhost:${port}`;
    console.log('');
    console.log('  \x1b[1m🛡  Bastion — secure notes vault\x1b[0m');
    console.log('  ─────────────────────────────────────────');
    console.log(`  \x1b[32m➜\x1b[0m  Open:   \x1b[36m${url}\x1b[0m`);
    console.log(`  \x1b[32m➜\x1b[0m  Mode:   ${config.isProd ? 'production' : 'development'} (listening on ${config.HOST} only)`);
    console.log(`  \x1b[32m➜\x1b[0m  Data:   ${config.DATA_DIR}`);
    if (db.users.count() === 0) console.log('  \x1b[33m★\x1b[0m  First run — the first account you register becomes the admin.');
    console.log('\n  Press Ctrl+C to stop.\n');
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE' && attempt < MAX_PORT_TRIES) {
      console.log(`  Port ${port} is busy, trying ${port + 1}…`);
      return start(port + 1, attempt + 1);
    }
    console.error('Failed to start server:', err.message);
    return process.exit(1);
  });

  server.listen(port, config.HOST);

  const shutdown = () => {
    console.log('\n  Shutting down…');
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 1500).unref();
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}

start(config.PORT);
