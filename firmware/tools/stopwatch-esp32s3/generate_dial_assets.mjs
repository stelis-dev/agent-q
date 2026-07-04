#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { deflateSync, inflateSync } from "node:zlib";

const repoRoot = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../../..");
const assetDir = path.join(repoRoot, "firmware/src/stopwatch-esp32s3/overlay/main/assets/dial");
const headerPath = path.join(assetDir, "dial_assets_generated.h");
const outputSize = 466;
const frameStepDegrees = 6;
const frameMaxDegrees = 342;
const motionBlurSampleDegrees = 1.4;
const frameOutputName = "2_dial_frames.idx8.deflate.bin";
const paletteSize = 256;

function paletteWeight(count) {
  return Math.sqrt(count);
}

function colorDistanceSquared(left, right) {
  const dr = left[0] - right[0];
  const dg = left[1] - right[1];
  const db = left[2] - right[2];
  return dr * dr * 3 + dg * dg * 6 + db * db * 2;
}

const inputs = [
  {
    inputName: "1_baseplate.png",
    outputName: "1_baseplate.rgb565a8.bin",
    constantPrefix: "DialBaseplate",
    cropAlpha: false,
  },
];

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

function toRgb565(r, g, b) {
  return ((r & 0xf8) << 8) | ((g & 0xfc) << 3) | (b >> 3);
}

function fromRgb565(value) {
  return [
    ((value >> 11) & 0x1f) * 255 / 31,
    ((value >> 5) & 0x3f) * 255 / 63,
    (value & 0x1f) * 255 / 31,
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

function findAlphaBounds(image) {
  let minX = image.width;
  let minY = image.height;
  let maxX = -1;
  let maxY = -1;
  for (let y = 0; y < image.height; y += 1) {
    for (let x = 0; x < image.width; x += 1) {
      const alpha = image.rgba[(y * image.width + x) * 4 + 3];
      if (alpha === 0) {
        continue;
      }
      minX = Math.min(minX, x);
      minY = Math.min(minY, y);
      maxX = Math.max(maxX, x);
      maxY = Math.max(maxY, y);
    }
  }
  if (maxX < minX || maxY < minY) {
    return { x: 0, y: 0, width: 1, height: 1 };
  }
  return { x: minX, y: minY, width: maxX - minX + 1, height: maxY - minY + 1 };
}

function convertToRgb565A8(image, rect) {
  const pixelCount = rect.width * rect.height;
  const output = Buffer.alloc(pixelCount * 3);
  const alphaOffset = pixelCount * 2;

  for (let y = 0; y < rect.height; y += 1) {
    for (let x = 0; x < rect.width; x += 1) {
      const sourceOffset = ((rect.y + y) * image.width + rect.x + x) * 4;
      const r = image.rgba[sourceOffset];
      const g = image.rgba[sourceOffset + 1];
      const b = image.rgba[sourceOffset + 2];
      const a = image.rgba[sourceOffset + 3];
      const pixelIndex = y * rect.width + x;
      const rgb565 = toRgb565(r, g, b);
      output[pixelIndex * 2] = rgb565 & 0xff;
      output[pixelIndex * 2 + 1] = rgb565 >> 8;
      output[alphaOffset + pixelIndex] = a;
    }
  }

  return output;
}

function sampleImageBilinear(image, sourceX, sourceY) {
  if (sourceX < 0 || sourceY < 0 || sourceX >= image.width || sourceY >= image.height) {
    return [0, 0, 0, 0];
  }
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

function pixelAt(image, x, y) {
  const offset = (y * image.width + x) * 4;
  return [
    image.rgba[offset],
    image.rgba[offset + 1],
    image.rgba[offset + 2],
    image.rgba[offset + 3],
  ];
}

function blendOver(base, overlay) {
  const alpha = overlay[3] / 255;
  if (alpha <= 0) {
    return base;
  }
  if (alpha >= 1) {
    return [overlay[0], overlay[1], overlay[2], 255];
  }
  return [
    Math.round(overlay[0] * alpha + base[0] * (1 - alpha)),
    Math.round(overlay[1] * alpha + base[1] * (1 - alpha)),
    Math.round(overlay[2] * alpha + base[2] * (1 - alpha)),
    255,
  ];
}

function blendAdd(base, overlay) {
  const alpha = overlay[3] / 255;
  if (alpha <= 0) {
    return base;
  }
  return [
    Math.min(255, Math.round(base[0] + overlay[0] * alpha)),
    Math.min(255, Math.round(base[1] + overlay[1] * alpha)),
    Math.min(255, Math.round(base[2] + overlay[2] * alpha)),
    255,
  ];
}

function sampleRotatedImage(image, displayX, displayY, degrees) {
  const radians = degrees * Math.PI / 180;
  const cosine = Math.cos(radians);
  const sine = Math.sin(radians);
  const center = outputSize / 2;
  const dx = displayX + 0.5 - center;
  const dy = displayY + 0.5 - center;
  const sourceX = dx * cosine + dy * sine + center - 0.5;
  const sourceY = -dx * sine + dy * cosine + center - 0.5;
  return sampleImageBilinear(image, sourceX, sourceY);
}

function sampleMotionBlurredDial(dialImage, displayX, displayY, degrees) {
  if (degrees === 0) {
    return sampleRotatedImage(dialImage, displayX, displayY, degrees);
  }
  const samples = [
    { weight: 1, color: sampleRotatedImage(dialImage, displayX, displayY, degrees - motionBlurSampleDegrees) },
    { weight: 2, color: sampleRotatedImage(dialImage, displayX, displayY, degrees) },
    { weight: 1, color: sampleRotatedImage(dialImage, displayX, displayY, degrees + motionBlurSampleDegrees) },
  ];
  let alpha = 0;
  let red = 0;
  let green = 0;
  let blue = 0;
  let weight = 0;
  for (const sample of samples) {
    const sampleAlpha = sample.color[3] / 255;
    alpha += sampleAlpha * sample.weight;
    red += sample.color[0] * sampleAlpha * sample.weight;
    green += sample.color[1] * sampleAlpha * sample.weight;
    blue += sample.color[2] * sampleAlpha * sample.weight;
    weight += sample.weight;
  }
  if (alpha <= 0) {
    return [0, 0, 0, 0];
  }
  return [
    Math.round(red / alpha),
    Math.round(green / alpha),
    Math.round(blue / alpha),
    Math.round(Math.max(0, Math.min(255, (alpha / weight) * 255))),
  ];
}

function renderCompositeFrame(baseImage, dialImage, glossImage, stopImage, rect, degrees) {
  const output = new Uint16Array(rect.width * rect.height);

  for (let y = 0; y < rect.height; y += 1) {
    for (let x = 0; x < rect.width; x += 1) {
      const displayX = rect.x + x;
      const displayY = rect.y + y;
      let color = pixelAt(baseImage, displayX, displayY);
      const dialSample = sampleMotionBlurredDial(dialImage, displayX, displayY, degrees);
      color = blendOver(color, dialSample);
      const dialMaskSample = sampleRotatedImage(dialImage, displayX, displayY, degrees);
      const glossSample = pixelAt(glossImage, displayX, displayY);
      if (dialMaskSample[3] === 0) {
        glossSample[3] = 0;
      }
      color = blendAdd(color, glossSample);
      color = blendOver(color, pixelAt(stopImage, displayX, displayY));

      const rgb565 = toRgb565(color[0], color[1], color[2]);
      output[y * rect.width + x] = rgb565;
    }
  }

  return output;
}

function buildPalette(frames) {
  const histogram = new Uint32Array(65536);
  for (const frame of frames) {
    for (const color of frame) {
      histogram[color] += 1;
    }
  }

  const colors = [];
  for (let value = 0; value < histogram.length; value += 1) {
    const weight = histogram[value];
    if (weight === 0) {
      continue;
    }
    const [r, g, b] = fromRgb565(value);
    colors.push({ value, count: weight, weight: paletteWeight(weight), r, g, b });
  }

  const boxStats = (list) => {
    let minR = Infinity;
    let minG = Infinity;
    let minB = Infinity;
    let maxR = -Infinity;
    let maxG = -Infinity;
    let maxB = -Infinity;
    let weight = 0;
    for (const color of list) {
      minR = Math.min(minR, color.r);
      minG = Math.min(minG, color.g);
      minB = Math.min(minB, color.b);
      maxR = Math.max(maxR, color.r);
      maxG = Math.max(maxG, color.g);
      maxB = Math.max(maxB, color.b);
      weight += color.weight;
    }
    return {
      list,
      minR,
      minG,
      minB,
      maxR,
      maxG,
      maxB,
      weight,
      score: Math.max(maxR - minR, maxG - minG, maxB - minB) * weight,
    };
  };

  const boxes = [boxStats(colors)];
  while (boxes.length < paletteSize) {
    boxes.sort((left, right) => right.score - left.score);
    const box = boxes.shift();
    if (!box || box.list.length <= 1) {
      if (box) {
        boxes.push(box);
      }
      break;
    }

    const rangeR = box.maxR - box.minR;
    const rangeG = box.maxG - box.minG;
    const rangeB = box.maxB - box.minB;
    const channel = rangeR >= rangeG && rangeR >= rangeB ? "r" : rangeG >= rangeB ? "g" : "b";
    box.list.sort((left, right) => left[channel] - right[channel]);

    const halfWeight = box.weight / 2;
    let accumulatedWeight = 0;
    let splitIndex = 0;
    for (; splitIndex < box.list.length - 1; splitIndex += 1) {
      accumulatedWeight += box.list[splitIndex].weight;
      if (accumulatedWeight >= halfWeight) {
        break;
      }
    }

    boxes.push(
      boxStats(box.list.slice(0, splitIndex + 1)),
      boxStats(box.list.slice(splitIndex + 1)));
  }

  let palette = boxes.map((box) => {
    let r = 0;
    let g = 0;
    let b = 0;
    let weight = 0;
    for (const color of box.list) {
      r += color.r * color.weight;
      g += color.g * color.weight;
      b += color.b * color.weight;
      weight += color.weight;
    }
    return toRgb565(
      Math.round(r / weight),
      Math.round(g / weight),
      Math.round(b / weight));
  });

  while (palette.length < paletteSize) {
    palette.push(0);
  }

  for (let iteration = 0; iteration < 2; iteration += 1) {
    const sums = Array.from({ length: paletteSize }, () => ({ r: 0, g: 0, b: 0, weight: 0 }));
    for (const color of colors) {
      const rgb = [color.r, color.g, color.b];
      let bestIndex = 0;
      let bestDistance = Infinity;
      for (let index = 0; index < palette.length; index += 1) {
        const distance = colorDistanceSquared(rgb, fromRgb565(palette[index]));
        if (distance < bestDistance) {
          bestDistance = distance;
          bestIndex = index;
        }
      }
      const sum = sums[bestIndex];
      sum.r += color.r * color.weight;
      sum.g += color.g * color.weight;
      sum.b += color.b * color.weight;
      sum.weight += color.weight;
    }
    palette = palette.map((entry, index) => {
      const sum = sums[index];
      if (sum.weight <= 0) {
        return entry;
      }
      return toRgb565(
        Math.round(sum.r / sum.weight),
        Math.round(sum.g / sum.weight),
        Math.round(sum.b / sum.weight));
    });
  }

  const colorMap = new Uint8Array(65536);
  for (let value = 0; value < histogram.length; value += 1) {
    if (histogram[value] === 0) {
      continue;
    }
    const [r, g, b] = fromRgb565(value);
    let bestIndex = 0;
    let bestDistance = Infinity;
    for (let index = 0; index < palette.length; index += 1) {
      const distance = colorDistanceSquared([r, g, b], fromRgb565(palette[index]));
      if (distance < bestDistance) {
        bestDistance = distance;
        bestIndex = index;
      }
    }
    colorMap[value] = bestIndex;
  }

  return { palette, colorMap };
}

function generateDialFrames() {
  const baseImage = resampleToOutputSize(parsePng(path.join(assetDir, "1_baseplate.png")));
  const dialImage = resampleToOutputSize(parsePng(path.join(assetDir, "2_dial.png")));
  const glossImage = resampleToOutputSize(parsePng(path.join(assetDir, "4_gloss.png")));
  const stopImage = resampleToOutputSize(parsePng(path.join(assetDir, "3_finger_stop.png")));
  const frameRect = findAlphaBounds(dialImage);
  const frames = [];
  for (let degrees = 0; degrees <= frameMaxDegrees; degrees += frameStepDegrees) {
    frames.push(renderCompositeFrame(baseImage, dialImage, glossImage, stopImage, frameRect, degrees));
  }

  const { palette, colorMap } = buildPalette(frames);
  const frameOffsets = [];
  const frameSizes = [];
  const chunks = [];

  for (const frame of frames) {
    const indexedFrame = Buffer.alloc(frame.length);
    for (let index = 0; index < frame.length; index += 1) {
      indexedFrame[index] = colorMap[frame[index]];
    }
    const compressed = deflateSync(indexedFrame, { level: 6 });
    frameOffsets.push(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
    frameSizes.push(compressed.length);
    chunks.push(compressed);
  }

  const output = Buffer.concat(chunks);
  fs.writeFileSync(path.join(assetDir, frameOutputName), output);
  console.log(
    `dial frames -> ${frameOutputName}: ${frameOffsets.length} frames ` +
    `${frameRect.width}x${frameRect.height}, indexed 256-color, ${output.length} compressed bytes`);
  generated.push({
    constantPrefix: "DialFrame",
    ...frameRect,
    bytes: output.length,
    frameCount: frameOffsets.length,
    frameOffsets,
    frameSizes,
    palette,
  });
}

const generated = [];

for (const input of inputs) {
  const { inputName, outputName, constantPrefix, cropAlpha } = input;
  const image = parsePng(path.join(assetDir, inputName));
  const resampled = resampleToOutputSize(image);
  const rect = cropAlpha
    ? findAlphaBounds(resampled)
    : { x: 0, y: 0, width: outputSize, height: outputSize };
  const output = convertToRgb565A8(resampled, rect);
  fs.writeFileSync(path.join(assetDir, outputName), output);
  generated.push({ constantPrefix, ...rect, bytes: output.length });
  const cropText = cropAlpha ? ` crop ${rect.x},${rect.y} ${rect.width}x${rect.height}` : "";
  console.log(`${inputName} -> ${outputName}: ${image.width}x${image.height} to ${rect.width}x${rect.height}${cropText}, ${output.length} bytes`);
}

generateDialFrames();

const header = `#pragma once

#include <stdint.h>

namespace stopwatch_target {

${generated.map((asset) => `constexpr int k${asset.constantPrefix}ImageX = ${asset.x};
constexpr int k${asset.constantPrefix}ImageY = ${asset.y};
constexpr int k${asset.constantPrefix}ImageWidth = ${asset.width};
constexpr int k${asset.constantPrefix}ImageHeight = ${asset.height};
constexpr int k${asset.constantPrefix}ImageStride = ${asset.width * 2};
${asset.frameCount ? `constexpr int k${asset.constantPrefix}StepDegrees = ${frameStepDegrees};
constexpr int k${asset.constantPrefix}MaxDegrees = ${frameMaxDegrees};
constexpr int k${asset.constantPrefix}Count = ${asset.frameCount};
constexpr uint32_t k${asset.constantPrefix}Offsets[k${asset.constantPrefix}Count] = {
${asset.frameOffsets.map((offset) => `    ${offset}U,`).join("\n")}
};
constexpr uint32_t k${asset.constantPrefix}CompressedSizes[k${asset.constantPrefix}Count] = {
${asset.frameSizes.map((size) => `    ${size}U,`).join("\n")}
};
constexpr uint16_t k${asset.constantPrefix}Palette[256] = {
${asset.palette.map((color) => `    0x${color.toString(16).padStart(4, "0")}U,`).join("\n")}
};
` : ""}
`).join("\n")}
}  // namespace stopwatch_target
`;

fs.writeFileSync(headerPath, header);
console.log(`generated ${path.relative(repoRoot, headerPath)}`);
