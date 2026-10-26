import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { crc32, deflateSync } from "node:zlib";

const dir = path.resolve(import.meta.dirname, "../assets");
mkdirSync(dir, { recursive: true });
const chunk = (type: string, data: Buffer) => {
  const name = Buffer.from(type);
  const output = Buffer.alloc(data.length + 12);
  output.writeUInt32BE(data.length, 0);
  name.copy(output, 4);
  data.copy(output, 8);
  output.writeUInt32BE(crc32(Buffer.concat([name, data])), data.length + 8);
  return output;
};
const png = (size: number) => {
  const raw = Buffer.alloc((size * 4 + 1) * size);
  const distance = (x: number, y: number, ax: number, ay: number, bx: number, by: number) => {
    const t = Math.max(
      0,
      Math.min(
        1,
        ((x - ax) * (bx - ax) + (y - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2),
      ),
    );
    return Math.hypot(x - ax - t * (bx - ax), y - ay - t * (by - ay));
  };
  for (let y = 0; y < size; y++)
    for (let x = 0; x < size; x++) {
      const u = x / size,
        v = y / size;
      const shield =
        v > 0.08 &&
        v < 0.91 &&
        u > 0.16 &&
        u < 0.84 &&
        v > 0.08 + Math.abs(u - 0.5) * 0.38 &&
        (v < 0.55 || Math.abs(u - 0.5) < (0.93 - v) * 0.87);
      const check =
        distance(u, v, 0.32, 0.47, 0.46, 0.61) < 0.039 ||
        distance(u, v, 0.46, 0.61, 0.7, 0.35) < 0.039;
      const offset = y * (size * 4 + 1) + 1 + x * 4;
      const color = check ? [255, 255, 255, 255] : shield ? [20, 130, 108, 255] : [0, 0, 0, 0];
      raw.set(color, offset);
    }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8;
  header[9] = 6;
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw)),
    chunk("IEND", Buffer.alloc(0)),
  ]);
};
writeFileSync(path.join(dir, "tray.png"), png(32));
const data = png(256),
  ico = Buffer.alloc(22);
ico.writeUInt16LE(1, 2);
ico.writeUInt16LE(1, 4);
ico.writeUInt16LE(1, 10);
ico.writeUInt16LE(32, 12);
ico.writeUInt32LE(data.length, 14);
ico.writeUInt32LE(22, 18);
writeFileSync(path.join(dir, "icon.ico"), Buffer.concat([ico, data]));
