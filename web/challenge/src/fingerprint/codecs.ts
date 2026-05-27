import type { CodecsProbe } from '../types';

const COMMON_CODECS: Record<string, string> = {
  mp4: 'video/mp4',
  webm: 'video/webm',
  h264: 'video/mp4; codecs="avc1.42E01E"',
  vp9: 'video/webm; codecs="vp09.00.10.08"'
};

const RARE_CODECS: Record<string, string> = {
  hevc: 'video/mp4; codecs="hvc1.1.6.L93.B0"',
  'av1.0.04M.08': 'video/mp4; codecs="av01.0.04M.08"',
  'dvhe.05.06': 'video/mp4; codecs="dvhe.05.06"'
};

export function collectCodecs(): CodecsProbe {
  const video = document.createElement('video');
  return {
    common: probeCodecs(video, COMMON_CODECS),
    rare: probeCodecs(video, RARE_CODECS)
  };
}

function probeCodecs(video: HTMLVideoElement, codecs: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, mime] of Object.entries(codecs)) {
    result[name] = video.canPlayType(mime);
  }
  return result;
}
