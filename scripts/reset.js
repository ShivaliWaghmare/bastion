'use strict';
// Wipes all local data (users, notes, audit log, generated secrets) for a fresh start.
const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'data');
fs.rmSync(dataDir, { recursive: true, force: true });
console.log('✓ data/ cleared — new secrets will be generated on next start.');
