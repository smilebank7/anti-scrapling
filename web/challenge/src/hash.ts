const encoder = new TextEncoder();

export function utf8(input: string): Uint8Array {
  return encoder.encode(input);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function sha256Bytes(data: BufferSource): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

export async function sha256Hex(data: string | BufferSource): Promise<string> {
  const input = typeof data === 'string' ? utf8(data) : data;
  return bytesToHex(await sha256Bytes(input));
}

export function leadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;

  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }

  return bits;
}

export function uniqueCount(values: readonly string[]): number {
  return new Set(values).size;
}
