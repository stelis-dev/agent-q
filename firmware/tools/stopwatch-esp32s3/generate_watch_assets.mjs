#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { inflateSync } from "node:zlib";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../..");
const assetDir = path.join(repoRoot, "firmware/src/stopwatch-esp32s3/overlay/main/assets/watch");
const headerPath = path.join(assetDir, "watch_assets_generated.h");
const outputSize = 466;
const paletteSize = 256;
const faceInputName = "clock_1_face.png";
const faceOutputName = "clock_1_face.i8.bin";
const opaqueBackground = [0x05, 0x06, 0x07];

function readU32BE(buffer, offset) {
  return buffer.readUInt32BE(offset);
}

function parsePng(filePath) {
  const png = fs.readFileSync(filePath);
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (!png.subarray(0, 8).equals(signature)) {
    throw new Error(`${filePath} is not a PNG file`);
  }

  let offset = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  let interlace = 0;
  const idat = [];

  while (offset < png.length) {
    const length = readU32BE(png, offset);
    const type = png.toString("ascii", offset + 4, offset + 8);
    const dataStart = offset + 8;
    const dataEnd = dataStart + length;
    const data = png.subarray(dataStart, dataEnd);

    if (type === "IHDR") {
      width = readU32BE(data, 0);
      height = readU32BE(data, 4);
      bitDepth = data[8];
      colorType = data[9];
      interlace = data[12];
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      break;
    }

    offset = dataEnd + 4;
  }

  if (bitDepth !== 8 || colorType !== 6 || interlace !== 0) {
    throw new Error(`${filePath} must be 8-bit non-interlaced RGBA PNG`);
  }

  const inflated = inflateSync(Buffer.concat(idat));
  const bytesPerPixel = 4;
  const stride = width * bytesPerPixel;
  const rgba = Buffer.alloc(width * height * bytesPerPixel);
  let inputOffset = 0;
  let previousRow = Buffer.alloc(stride);

  for (let y = 0; y < height; y += 1) {
    const filter = inflated[inputOffset];
    inputOffset += 1;
    const row = Buffer.from(inflated.subarray(inputOffset, inputOffset + stride));
    inputOffset += stride;
    const decoded = Buffer.alloc(stride);

    for (let x = 0; x < stride; x += 1) {
      const left = x >= bytesPerPixel ? decoded[x - bytesPerPixel] : 0;
      const up = previousRow[x];
      const upLeft = x >= bytesPerPixel ? previousRow[x - bytesPerPixel] : 0;
      let predictor = 0;

      if (filter === 1) {
        predictor = left;
      } else if (filter === 2) {
        predictor = up;
      } else if (filter === 3) {
        predictor = Math.floor((left + up) / 2);
      } else if (filter === 4) {
        const p = left + up - upLeft;
        const pa = Math.abs(p - left);
        const pb = Math.abs(p - up);
        const pc = Math.abs(p - upLeft);
        predictor = pa <= pb && pa <= pc ? left : pb <= pc ? up : upLeft;
      } else if (filter !== 0) {
        throw new Error(`${filePath} uses unsupported PNG filter ${filter}`);
      }

      decoded[x] = (row[x] + predictor) & 0xff;
    }

    decoded.copy(rgba, y * stride);
    previousRow = decoded;
  }

  return { width, height, rgba };
}

function sampleBilinear(image, x, y, targetWidth = outputSize, targetHeight = outputSize) {
  const sourceX = (x + 0.5) * image.width / targetWidth - 0.5;
  const sourceY = (y + 0.5) * image.height / targetHeight - 0.5;
  const x0 = Math.max(0, Math.min(image.width - 1, Math.floor(sourceX)));
  const y0 = Math.max(0, Math.min(image.height - 1, Math.floor(sourceY)));
  const x1 = Math.max(0, Math.min(image.width - 1, x0 + 1));
  const y1 = Math.max(0, Math.min(image.height - 1, y0 + 1));
  const tx = sourceX - x0;
  const ty = sourceY - y0;

  const sample = (sx, sy, channel) => image.rgba[(sy * image.width + sx) * 4 + channel];
  const points = [
    { x: x0, y: y0, weight: (1 - tx) * (1 - ty) },
    { x: x1, y: y0, weight: tx * (1 - ty) },
    { x: x0, y: y1, weight: (1 - tx) * ty },
    { x: x1, y: y1, weight: tx * ty },
  ];
  let alpha = 0;
  let red = 0;
  let green = 0;
  let blue = 0;
  let weight = 0;
  for (const point of points) {
    const sampleAlpha = sample(point.x, point.y, 3) / 255;
    alpha += sampleAlpha * point.weight;
    red += sample(point.x, point.y, 0) * sampleAlpha * point.weight;
    green += sample(point.x, point.y, 1) * sampleAlpha * point.weight;
    blue += sample(point.x, point.y, 2) * sampleAlpha * point.weight;
    weight += point.weight;
  }
  if (alpha <= 0) {
    return [0, 0, 0, 0];
  }
  return [
    Math.max(0, Math.min(255, Math.round(red / alpha))),
    Math.max(0, Math.min(255, Math.round(green / alpha))),
    Math.max(0, Math.min(255, Math.round(blue / alpha))),
    Math.max(0, Math.min(255, Math.round((alpha / weight) * 255))),
  ];
}

function resampleToOutputSize(image) {
  const rgba = Buffer.alloc(outputSize * outputSize * 4);
  for (let y = 0; y < outputSize; y += 1) {
    for (let x = 0; x < outputSize; x += 1) {
      const [r, g, b, a] = sampleBilinear(image, x, y);
      const offset = (y * outputSize + x) * 4;
      rgba[offset] = r;
      rgba[offset + 1] = g;
      rgba[offset + 2] = b;
      rgba[offset + 3] = a;
    }
  }
  return { width: outputSize, height: outputSize, rgba };
}

function flattenOpaque(image) {
  const rgba = Buffer.alloc(image.width * image.height * 4);
  for (let index = 0; index < image.rgba.length; index += 4) {
    const alpha = image.rgba[index + 3] / 255;
    rgba[index] = Math.round(image.rgba[index] * alpha + opaqueBackground[0] * (1 - alpha));
    rgba[index + 1] = Math.round(image.rgba[index + 1] * alpha + opaqueBackground[1] * (1 - alpha));
    rgba[index + 2] = Math.round(image.rgba[index + 2] * alpha + opaqueBackground[2] * (1 - alpha));
    rgba[index + 3] = 255;
  }
  return { width: image.width, height: image.height, rgba };
}

function quantizedKey(r, g, b, a) {
  const red = r >> 3;
  const green = g >> 2;
  const blue = b >> 3;
  return (red << 11) | (green << 5) | blue;
}

function keyToRgba(key) {
  const red = ((key >> 11) & 0x1f) * 255 / 31;
  const green = ((key >> 5) & 0x3f) * 255 / 63;
  const blue = (key & 0x1f) * 255 / 31;
  return [red, green, blue, 255];
}

function colorDistanceSquared(left, right) {
  const dr = left[0] - right[0];
  const dg = left[1] - right[1];
  const db = left[2] - right[2];
  return dr * dr * 3 + dg * dg * 6 + db * db * 2;
}

function buildWeightedColors(image) {
  const counts = new Map();
  for (let index = 0; index < image.rgba.length; index += 4) {
    const key = quantizedKey(
      image.rgba[index],
      image.rgba[index + 1],
      image.rgba[index + 2],
      image.rgba[index + 3]);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries()).map(([key, count]) => ({
    color: keyToRgba(key),
    count,
  }));
}

function makeBox(colors) {
  const mins = [255, 255, 255, 255];
  const maxes = [0, 0, 0, 0];
  let count = 0;
  for (const entry of colors) {
    count += entry.count;
    for (let channel = 0; channel < 4; channel += 1) {
      mins[channel] = Math.min(mins[channel], entry.color[channel]);
      maxes[channel] = Math.max(maxes[channel], entry.color[channel]);
    }
  }
  return { colors, mins, maxes, count };
}

function splitLargestBox(boxes) {
  let splitIndex = -1;
  let splitScore = -1;
  for (let index = 0; index < boxes.length; index += 1) {
    const box = boxes[index];
    if (box.colors.length <= 1) {
      continue;
    }
    const ranges = box.maxes.map((max, channel) => max - box.mins[channel]);
    const score = Math.max(...ranges) * Math.sqrt(box.count);
    if (score > splitScore) {
      splitScore = score;
      splitIndex = index;
    }
  }
  if (splitIndex < 0) {
    return false;
  }

  const box = boxes.splice(splitIndex, 1)[0];
  const channel = box.maxes
    .map((max, index) => ({ index, range: max - box.mins[index] }))
    .sort((left, right) => right.range - left.range)[0].index;
  const sorted = [...box.colors].sort((left, right) => left.color[channel] - right.color[channel]);
  const half = box.count / 2;
  let running = 0;
  let splitAt = 1;
  for (; splitAt < sorted.length; splitAt += 1) {
    running += sorted[splitAt - 1].count;
    if (running >= half) {
      break;
    }
  }

  boxes.push(makeBox(sorted.slice(0, splitAt)));
  boxes.push(makeBox(sorted.slice(splitAt)));
  return true;
}

function centroid(box) {
  const weighted = [0, 0, 0, 0];
  let count = 0;
  for (const entry of box.colors) {
    count += entry.count;
    for (let channel = 0; channel < 4; channel += 1) {
      weighted[channel] += entry.color[channel] * entry.count;
    }
  }
  if (count === 0) {
    return [0, 0, 0, 0];
  }
  return weighted.map((value) => Math.max(0, Math.min(255, Math.round(value / count))));
}

function buildPalette(image) {
  const colors = buildWeightedColors(image);
  const boxes = [makeBox(colors)];
  while (boxes.length < paletteSize && splitLargestBox(boxes)) {
    // Keep splitting until the palette is full or no useful split remains.
  }
  const palette = boxes.map(centroid);
  while (palette.length < paletteSize) {
    palette.push([0, 0, 0, 255]);
  }
  return palette;
}

function nearestPaletteIndex(color, palette) {
  let bestIndex = 0;
  let bestDistance = Number.POSITIVE_INFINITY;
  for (let index = 0; index < palette.length; index += 1) {
    const distance = colorDistanceSquared(color, palette[index]);
    if (distance < bestDistance) {
      bestDistance = distance;
      bestIndex = index;
    }
  }
  return bestIndex;
}

function convertToI8(image) {
  const palette = buildPalette(image);
  const pixelCount = image.width * image.height;
  const output = Buffer.alloc(paletteSize * 4 + pixelCount);
  for (let index = 0; index < palette.length; index += 1) {
    const [r, g, b, a] = palette[index];
    const offset = index * 4;
    output[offset] = b;
    output[offset + 1] = g;
    output[offset + 2] = r;
    output[offset + 3] = 255;
  }
  for (let index = 0; index < pixelCount; index += 1) {
    const offset = index * 4;
    const color = [
      image.rgba[offset],
      image.rgba[offset + 1],
      image.rgba[offset + 2],
      image.rgba[offset + 3],
    ];
    output[paletteSize * 4 + index] = nearestPaletteIndex(color, palette);
  }
  return output;
}

const image = parsePng(path.join(assetDir, faceInputName));
const resampled = resampleToOutputSize(image);
const opaque = flattenOpaque(resampled);
const output = convertToI8(opaque);
fs.writeFileSync(path.join(assetDir, faceOutputName), output);

const rgb565a8Bytes = outputSize * outputSize * 3;
console.log(
  `${faceInputName} -> ${faceOutputName}: ${image.width}x${image.height} to ` +
  `${outputSize}x${outputSize}, indexed 256-color, ${output.length} bytes ` +
  `(RGB565A8 would be ${rgb565a8Bytes} bytes)`);

const header = `#pragma once

#include <stdint.h>

namespace stopwatch_target {

constexpr int kWatchFaceImageX = 0;
constexpr int kWatchFaceImageY = 0;
constexpr int kWatchFaceImageWidth = ${outputSize};
constexpr int kWatchFaceImageHeight = ${outputSize};
constexpr int kWatchFaceImageStride = ${outputSize};
constexpr int kWatchFaceImageBytes = ${output.length};

}  // namespace stopwatch_target
`;

fs.writeFileSync(headerPath, header);
console.log(`generated ${path.relative(repoRoot, headerPath)}`);
