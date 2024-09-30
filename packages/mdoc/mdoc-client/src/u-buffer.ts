export function concat(...buffers: Uint8Array[]): Uint8Array {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  buffers.forEach(buffer => {
    buf.set(buffer, i);
    i += buffer.length;
  });
  return buf;
}

export function areEqual(buf1: Uint8Array, buf2: Uint8Array): boolean {
  if (buf1 === buf2) {
    return true;
  }

  if (buf1.byteLength !== buf2.byteLength) {
    return false;
  }

  for (let i = 0; i < buf1.byteLength; i++) {
    if (buf1[i] !== buf2[i]) {
      return false;
    }
  }

  return true;
}

// this was added to Hermes
export const encoder = new TextEncoder();
export const stringToUint8Array = (input: string): Uint8Array =>
  encoder.encode(input);

// this must be polyfilled in Hermes
export const decoder = new TextDecoder();
export const uint8ArrayToString = (input: Uint8Array): string =>
  decoder.decode(input);
