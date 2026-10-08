'use strict';
/**
 * Minimal QR Code encoder (ISO/IEC 18004) — byte mode, error-correction level M,
 * versions 1–10 (up to 213 bytes; an otpauth:// URL needs ~150). Outputs SVG.
 * Algorithm structure follows Project Nayuki's reference implementation (MIT).
 * Used only to render the 2FA enrolment QR code, so no third-party package is needed.
 */

// Index = version (1..10). Error-correction level M.
const ECC_PER_BLOCK = [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26];
const NUM_BLOCKS = [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5];
const FORMAT_ECL_BITS_M = 0;

const getBit = (x, i) => ((x >>> i) & 1) !== 0;

function numRawDataModules(ver) {
  let result = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    const numAlign = Math.floor(ver / 7) + 2;
    result -= (25 * numAlign - 10) * numAlign - 55;
    if (ver >= 7) result -= 36;
  }
  return result;
}

const numDataCodewords = (ver) => Math.floor(numRawDataModules(ver) / 8) - ECC_PER_BLOCK[ver] * NUM_BLOCKS[ver];

// ---- Reed–Solomon over GF(2^8), primitive polynomial 0x11D -----------------------
function rsMultiply(x, y) {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function rsDivisor(degree) {
  const result = new Array(degree).fill(0);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < result.length; j++) {
      result[j] = rsMultiply(result[j], root);
      if (j + 1 < result.length) result[j] ^= result[j + 1];
    }
    root = rsMultiply(root, 0x02);
  }
  return result;
}

function rsRemainder(data, divisor) {
  const result = divisor.map(() => 0);
  for (const b of data) {
    const factor = b ^ result.shift();
    result.push(0);
    divisor.forEach((coef, i) => {
      result[i] ^= rsMultiply(coef, factor);
    });
  }
  return result;
}

// ---- Encoding --------------------------------------------------------------------
function encodeData(bytes) {
  let ver = 1;
  for (; ver <= 10; ver++) {
    const ccBits = ver <= 9 ? 8 : 16;
    if (4 + ccBits + bytes.length * 8 <= numDataCodewords(ver) * 8) break;
  }
  if (ver > 10) throw new Error('Data too long for QR encoder');

  const bits = [];
  const append = (val, len) => {
    for (let i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  };
  append(0b0100, 4); // byte mode
  append(bytes.length, ver <= 9 ? 8 : 16);
  for (const b of bytes) append(b, 8);

  const capacityBits = numDataCodewords(ver) * 8;
  append(0, Math.min(4, capacityBits - bits.length)); // terminator
  append(0, (8 - (bits.length % 8)) % 8);
  for (let pad = 0xec; bits.length < capacityBits; pad ^= 0xec ^ 0x11) append(pad, 8);

  const codewords = [];
  for (let i = 0; i < bits.length; i += 8) codewords.push(parseInt(bits.slice(i, i + 8).join(''), 2));
  return { ver, codewords };
}

function addEccAndInterleave(ver, data) {
  const numBlocks = NUM_BLOCKS[ver];
  const eccLen = ECC_PER_BLOCK[ver];
  const rawCodewords = Math.floor(numRawDataModules(ver) / 8);
  const numShort = numBlocks - (rawCodewords % numBlocks);
  const shortLen = Math.floor(rawCodewords / numBlocks);
  const divisor = rsDivisor(eccLen);

  const blocks = [];
  for (let i = 0, k = 0; i < numBlocks; i++) {
    const dat = data.slice(k, k + shortLen - eccLen + (i < numShort ? 0 : 1));
    k += dat.length;
    const ecc = rsRemainder(dat, divisor);
    if (i < numShort) dat.push(0);
    blocks.push(dat.concat(ecc));
  }
  const result = [];
  for (let i = 0; i < blocks[0].length; i++) {
    blocks.forEach((block, j) => {
      if (i !== shortLen - eccLen || j >= numShort) result.push(block[i]);
    });
  }
  return result;
}

// ---- Matrix construction --------------------------------------------------------
class Matrix {
  constructor(ver) {
    this.ver = ver;
    this.size = ver * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
    this.isFunction = Array.from({ length: this.size }, () => new Array(this.size).fill(false));
  }

  setFn(x, y, dark) {
    this.modules[y][x] = dark;
    this.isFunction[y][x] = true;
  }

  alignmentPositions() {
    if (this.ver === 1) return [];
    const numAlign = Math.floor(this.ver / 7) + 2;
    const step = Math.ceil((this.ver * 4 + 4) / (numAlign * 2 - 2)) * 2;
    const result = [6];
    for (let pos = this.size - 7; result.length < numAlign; pos -= step) result.splice(1, 0, pos);
    return result;
  }

  drawFunctionPatterns() {
    for (let i = 0; i < this.size; i++) {
      this.setFn(6, i, i % 2 === 0);
      this.setFn(i, 6, i % 2 === 0);
    }
    const finder = (cx, cy) => {
      for (let dy = -4; dy <= 4; dy++) {
        for (let dx = -4; dx <= 4; dx++) {
          const dist = Math.max(Math.abs(dx), Math.abs(dy));
          const x = cx + dx;
          const y = cy + dy;
          if (x >= 0 && x < this.size && y >= 0 && y < this.size) this.setFn(x, y, dist !== 2 && dist !== 4);
        }
      }
    };
    finder(3, 3);
    finder(this.size - 4, 3);
    finder(3, this.size - 4);

    const pos = this.alignmentPositions();
    const n = pos.length;
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        if ((i === 0 && j === 0) || (i === 0 && j === n - 1) || (i === n - 1 && j === 0)) continue;
        for (let dy = -2; dy <= 2; dy++) {
          for (let dx = -2; dx <= 2; dx++) this.setFn(pos[i] + dx, pos[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
        }
      }
    }
    this.drawFormatBits(0); // reserve area; real value drawn after masking
    this.drawVersion();
  }

  drawFormatBits(mask) {
    const data = (FORMAT_ECL_BITS_M << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    const bits = ((data << 10) | rem) ^ 0x5412;
    for (let i = 0; i <= 5; i++) this.setFn(8, i, getBit(bits, i));
    this.setFn(8, 7, getBit(bits, 6));
    this.setFn(8, 8, getBit(bits, 7));
    this.setFn(7, 8, getBit(bits, 8));
    for (let i = 9; i < 15; i++) this.setFn(14 - i, 8, getBit(bits, i));
    for (let i = 0; i < 8; i++) this.setFn(this.size - 1 - i, 8, getBit(bits, i));
    for (let i = 8; i < 15; i++) this.setFn(8, this.size - 15 + i, getBit(bits, i));
    this.setFn(8, this.size - 8, true); // dark module
  }

  drawVersion() {
    if (this.ver < 7) return;
    let rem = this.ver;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.ver << 12) | rem;
    for (let i = 0; i < 18; i++) {
      const bit = getBit(bits, i);
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.setFn(a, b, bit);
      this.setFn(b, a, bit);
    }
  }

  drawCodewords(data) {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < this.size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.isFunction[y][x] && i < data.length * 8) {
            this.modules[y][x] = getBit(data[i >>> 3], 7 - (i & 7));
            i++;
          }
        }
      }
    }
  }

  applyMask(mask) {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        let invert;
        switch (mask) {
          case 0: invert = (x + y) % 2 === 0; break;
          case 1: invert = y % 2 === 0; break;
          case 2: invert = x % 3 === 0; break;
          case 3: invert = (x + y) % 3 === 0; break;
          case 4: invert = (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0; break;
          case 5: invert = ((x * y) % 2) + ((x * y) % 3) === 0; break;
          case 6: invert = (((x * y) % 2) + ((x * y) % 3)) % 2 === 0; break;
          default: invert = (((x + y) % 2) + ((x * y) % 3)) % 2 === 0;
        }
        if (!this.isFunction[y][x] && invert) this.modules[y][x] = !this.modules[y][x];
      }
    }
  }

  /** Simplified ISO penalty score (rules 1–4) used to pick the most readable mask. */
  penalty() {
    const n = this.size;
    const m = this.modules;
    let score = 0;
    const lines = [];
    for (let y = 0; y < n; y++) lines.push(m[y].map((v) => (v ? 1 : 0)).join(''));
    for (let x = 0; x < n; x++) lines.push(m.map((row) => (row[x] ? 1 : 0)).join(''));
    for (const line of lines) {
      for (const run of line.match(/0+|1+/g)) if (run.length >= 5) score += run.length - 2; // rule 1
      const padded = `0000${line}0000`;
      for (const pat of ['10111010000', '00001011101']) {
        for (let i = padded.indexOf(pat); i !== -1; i = padded.indexOf(pat, i + 1)) score += 40; // rule 3
      }
    }
    let dark = 0;
    for (let y = 0; y < n; y++) {
      for (let x = 0; x < n; x++) {
        if (m[y][x]) dark++;
        if (x < n - 1 && y < n - 1 && m[y][x] === m[y][x + 1] && m[y][x] === m[y + 1][x] && m[y][x] === m[y + 1][x + 1]) score += 3; // rule 2
      }
    }
    const total = n * n;
    score += (Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10; // rule 4
    return score;
  }
}

function encode(text) {
  const { ver, codewords } = encodeData(Buffer.from(String(text), 'utf8'));
  const allCodewords = addEccAndInterleave(ver, codewords);
  const qr = new Matrix(ver);
  qr.drawFunctionPatterns();
  qr.drawCodewords(allCodewords);

  let best = -1;
  let bestPenalty = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    qr.applyMask(mask);
    qr.drawFormatBits(mask);
    const p = qr.penalty();
    if (p < bestPenalty) {
      best = mask;
      bestPenalty = p;
    }
    qr.applyMask(mask); // XOR again to undo
  }
  qr.applyMask(best);
  qr.drawFormatBits(best);
  return qr.modules;
}

function toSvg(text, { border = 4, dark = '#000000', light = '#ffffff' } = {}) {
  const modules = encode(text);
  const size = modules.length + border * 2;
  const parts = [];
  modules.forEach((row, y) => row.forEach((on, x) => on && parts.push(`M${x + border},${y + border}h1v1h-1z`)));
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" shape-rendering="crispEdges">`
    + `<rect width="${size}" height="${size}" fill="${light}"/><path d="${parts.join('')}" fill="${dark}"/></svg>`;
}

const toDataUrl = (text, opts) => `data:image/svg+xml;base64,${Buffer.from(toSvg(text, opts)).toString('base64')}`;

module.exports = { encode, toSvg, toDataUrl };
