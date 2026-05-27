import { sha256Hex, uniqueCount } from '../hash';
import type { AudioProbe } from '../types';

interface AudioGlobal {
  webkitOfflineAudioContext?: typeof OfflineAudioContext;
}

const SAMPLE_RATE = 44100;
const FRAME_COUNT = 4096;

export async function collectAudio(): Promise<AudioProbe> {
  const Context = globalThis.OfflineAudioContext || (globalThis as AudioGlobal).webkitOfflineAudioContext;

  if (!Context) {
    return { hashes: [], variance: 0 };
  }

  try {
    const hashes: string[] = [];
    for (let index = 0; index < 3; index += 1) {
      hashes.push(await renderAudioHash(Context));
    }
    return { hashes, variance: uniqueCount(hashes) };
  } catch {
    return { hashes: [], variance: 0 };
  }
}

async function renderAudioHash(Context: typeof OfflineAudioContext): Promise<string> {
  const context = new Context(1, FRAME_COUNT, SAMPLE_RATE);
  const oscillator = context.createOscillator();
  const compressor = context.createDynamicsCompressor();

  oscillator.type = 'triangle';
  oscillator.frequency.value = 997;
  compressor.threshold.value = -42;
  compressor.knee.value = 30;
  compressor.ratio.value = 12;
  compressor.attack.value = 0.003;
  compressor.release.value = 0.25;

  oscillator.connect(compressor);
  compressor.connect(context.destination);
  oscillator.start(0);
  oscillator.stop(FRAME_COUNT / SAMPLE_RATE);

  const buffer = await context.startRendering();
  const samples = buffer.getChannelData(0);
  const compressed = new Int16Array(samples.length);

  for (let index = 0; index < samples.length; index += 1) {
    const sample = Math.max(-1, Math.min(1, samples[index]));
    compressed[index] = Math.round(sample * 32767);
  }

  return sha256Hex(compressed.buffer);
}
