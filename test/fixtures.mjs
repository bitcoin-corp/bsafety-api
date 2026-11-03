// Synthetic test images only: solid colours and smooth mathematical patterns. No photographs, nothing depicting
// anyone or anything.
import jpeg from 'jpeg-js';
import { encodePng, solidPng } from '../src/image.js';

/** A smooth interference pattern. Same params at another size or brightness = a near-duplicate. */
export function patternRgba(w, h, { fx = 3, fy = 2, phase = 0, bright = 0, tint = [1, 0.8, 0.6] } = {}) {
  const px = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const v = 128 + 90 * Math.sin(2 * Math.PI * (fx * x / w + phase)) * Math.cos(2 * Math.PI * fy * y / h) + 20 * Math.sin(2 * Math.PI * (x + y) / (w + h) * 5) + bright;
      const o = (y * w + x) * 4;
      for (let c = 0; c < 3; c++) px[o + c] = Math.max(0, Math.min(255, Math.round(v * tint[c] + (1 - tint[c]) * 128)));
      px[o + 3] = 255;
    }
  }
  return px;
}
export const patternPng = (w, h, opts) => encodePng(w, h, patternRgba(w, h, opts));
export function patternJpeg(w, h, opts, quality = 80) {
  return Buffer.from(jpeg.encode({ data: patternRgba(w, h, opts), width: w, height: h }, quality).data);
}
/** The same pattern with a handful of pixels scribbled over (a light edit). */
export function patternEditedPng(w, h, opts) {
  const px = patternRgba(w, h, opts);
  for (let i = 0; i < 40; i++) { const o = ((i * 7919) % (w * h)) * 4; px[o] = 255 - px[o]; }
  return encodePng(w, h, px);
}
export { solidPng };
