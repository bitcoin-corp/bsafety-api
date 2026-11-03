// Image hashing for the denylist: sha256 of the bytes, and a 64-bit difference hash (dHash) of the pixels so a
// re-encoded, resized or lightly edited copy still matches. Pure JS: a small PNG codec on node:zlib, and jpeg-js
// (pure JS, MIT) for JPEG. Nothing here keeps pixels: decode, hash, drop.
import { createHash } from 'node:crypto';
import { crc32, deflateSync, inflateSync } from 'node:zlib';
import jpeg from 'jpeg-js';

export const MAX_PIXELS = 60_000_000; // decompression-bomb guard (60 MP)
export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

export class ImageError extends Error {}

const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
export const isPng = (b) => b.length > 8 && b.subarray(0, 8).equals(PNG_SIG);
export const isJpeg = (b) => b.length > 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff;

/** Decode a PNG to { width, height, data: RGBA Uint8Array }. Non-interlaced, any colour type, bit depth 1-16. */
export function decodePng(buf) {
  if (!isPng(buf)) throw new ImageError('Not a PNG.');
  let off = 8, ihdr = null, palette = null, trns = null;
  const idat = [];
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off), type = buf.toString('latin1', off + 4, off + 8);
    const body = buf.subarray(off + 8, off + 8 + len);
    if (body.length !== len) throw new ImageError('PNG is truncated.');
    if (type === 'IHDR') ihdr = { w: body.readUInt32BE(0), h: body.readUInt32BE(4), depth: body[8], ctype: body[9], interlace: body[12] };
    else if (type === 'PLTE') palette = body;
    else if (type === 'tRNS') trns = body;
    else if (type === 'IDAT') idat.push(body);
    else if (type === 'IEND') break;
    off += 12 + len;
  }
  if (!ihdr || !idat.length) throw new ImageError('PNG has no image data.');
  const { w, h, depth, ctype, interlace } = ihdr;
  if (!w || !h || w * h > MAX_PIXELS) throw new ImageError('Image is too large to hash.');
  if (interlace) throw new ImageError('Interlaced PNGs are not supported.');
  const channels = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 }[ctype];
  if (!channels || ![1, 2, 4, 8, 16].includes(depth)) throw new ImageError('Unsupported PNG format.');
  const bpp = Math.max(1, (channels * depth) >> 3); // bytes per pixel for filtering
  const stride = Math.ceil((w * channels * depth) / 8);
  let raw;
  try { raw = inflateSync(Buffer.concat(idat), { maxOutputLength: (stride + 1) * h }); } catch { throw new ImageError('PNG data is corrupt.'); }
  if (raw.length < (stride + 1) * h) throw new ImageError('PNG data is short.');
  // Undo the per-row filters.
  const px = new Uint8Array(stride * h);
  for (let y = 0; y < h; y++) {
    const f = raw[y * (stride + 1)], src = y * (stride + 1) + 1, dst = y * stride;
    for (let x = 0; x < stride; x++) {
      const a = x >= bpp ? px[dst + x - bpp] : 0, b = y ? px[dst - stride + x] : 0, c = x >= bpp && y ? px[dst - stride + x - bpp] : 0;
      let v = raw[src + x];
      if (f === 1) v += a;
      else if (f === 2) v += b;
      else if (f === 3) v += (a + b) >> 1;
      else if (f === 4) { const p = a + b - c, pa = Math.abs(p - a), pb = Math.abs(p - b), pc = Math.abs(p - c); v += pa <= pb && pa <= pc ? a : pb <= pc ? b : c; }
      else if (f !== 0) throw new ImageError('PNG filter is invalid.');
      px[dst + x] = v & 255;
    }
  }
  // Read sample i of row y, scaled to 0-255.
  const max = (1 << depth) - 1;
  const sample = (y, i) => {
    const row = y * stride;
    if (depth === 8) return px[row + i];
    if (depth === 16) return px[row + i * 2];
    const bit = i * depth, byte = px[row + (bit >> 3)], shift = 8 - depth - (bit & 7);
    return (byte >> shift) & max;
  };
  const scale = (v) => (depth < 8 ? Math.round((v * 255) / max) : v);
  const out = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const o = (y * w + x) * 4, i = x * channels;
      let r, g, b, a = 255;
      if (ctype === 0) { r = g = b = scale(sample(y, i)); }
      else if (ctype === 2) { r = sample(y, i); g = sample(y, i + 1); b = sample(y, i + 2); }
      else if (ctype === 3) {
        const k = sample(y, i);
        if (!palette || k * 3 + 2 >= palette.length) throw new ImageError('PNG palette index out of range.');
        r = palette[k * 3]; g = palette[k * 3 + 1]; b = palette[k * 3 + 2];
        if (trns && k < trns.length) a = trns[k];
      } else if (ctype === 4) { r = g = b = sample(y, i); a = sample(y, i + 1); }
      else { r = sample(y, i); g = sample(y, i + 1); b = sample(y, i + 2); a = sample(y, i + 3); }
      out[o] = r; out[o + 1] = g; out[o + 2] = b; out[o + 3] = a;
    }
  }
  return { width: w, height: h, data: out };
}

/** Encode RGBA pixels as a PNG (filter 0). Used for the synthetic test images and the dev placeholders. */
export function encodePng(width, height, rgba) {
  const stride = width * 4, raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) Buffer.from(rgba.buffer, rgba.byteOffset + y * stride, stride).copy(raw, y * (stride + 1) + 1);
  const chunk = (type, body) => {
    const head = Buffer.alloc(8);
    head.writeUInt32BE(body.length, 0);
    head.write(type, 4, 'latin1');
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), body])), 0);
    return Buffer.concat([head, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 6; // 8-bit RGBA
  return Buffer.concat([PNG_SIG, chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}

/** A solid-colour PNG (dev placeholders). */
export function solidPng(width, height, [r, g, b]) {
  const px = new Uint8Array(width * height * 4);
  for (let i = 0; i < px.length; i += 4) { px[i] = r; px[i + 1] = g; px[i + 2] = b; px[i + 3] = 255; }
  return encodePng(width, height, px);
}

/** Decode PNG or JPEG bytes to RGBA. */
export function decodeImage(buf) {
  if (isPng(buf)) return decodePng(buf);
  if (isJpeg(buf)) {
    try {
      const img = jpeg.decode(buf, { useTArray: true, formatAsRGBA: true, maxResolutionInMP: MAX_PIXELS / 1e6, maxMemoryUsageInMB: 1024 });
      return { width: img.width, height: img.height, data: img.data };
    } catch (e) { throw new ImageError(`JPEG could not be read: ${e.message}`); }
  }
  throw new ImageError('Only PNG and JPEG can be hashed for now.');
}

/**
 * dHash: greyscale, area-average down to 9x8, then one bit per pair of horizontal neighbours (left brighter = 1).
 * Returns 16 hex characters. One pass over the pixels, no resampling library.
 */
export function dHashPixels({ width: w, height: h, data }) {
  const W = 9, Hh = 8, sum = new Float64Array(W * Hh), cnt = new Float64Array(W * Hh);
  for (let y = 0; y < h; y++) {
    const cy = Math.min(Hh - 1, Math.floor((y * Hh) / h));
    for (let x = 0; x < w; x++) {
      const o = (y * w + x) * 4, a = data[o + 3] / 255;
      // composite over white so transparent areas hash the same however the encoder stored them
      const lum = (0.299 * data[o] + 0.587 * data[o + 1] + 0.114 * data[o + 2]) * a + 255 * (1 - a);
      const c = cy * W + Math.min(W - 1, Math.floor((x * W) / w));
      sum[c] += lum; cnt[c]++;
    }
  }
  const g = Array.from(sum, (s, i) => (cnt[i] ? s / cnt[i] : 0));
  let bits = 0n;
  for (let y = 0; y < Hh; y++) for (let x = 0; x < W - 1; x++) bits = (bits << 1n) | (g[y * W + x] > g[y * W + x + 1] ? 1n : 0n);
  return bits.toString(16).padStart(16, '0');
}

export const dHash = (buf) => dHashPixels(decodeImage(buf));

export function hamming(a, b) {
  let x = BigInt('0x' + a) ^ BigInt('0x' + b), n = 0;
  while (x) { n += Number(x & 1n); x >>= 1n; }
  return n;
}

/**
 * A hash with almost every bit the same (a flat colour, a plain left-to-right gradient) says nothing about the
 * picture: any flat image would "match" it. Those are never used for perceptual matching; sha256 still applies.
 */
export function degenerate(hex) {
  const ones = hamming(hex, '0000000000000000');
  return ones <= 4 || ones >= 60;
}
