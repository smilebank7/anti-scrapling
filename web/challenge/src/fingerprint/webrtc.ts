import type { WebRTCProbe } from '../types';

const ICE_TIMEOUT_MS = 1000;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g;

export async function collectWebRTC(): Promise<WebRTCProbe> {
  if (!globalThis.RTCPeerConnection) {
    return { local_ips: [], public_ip: '' };
  }

  const ips = new Set<string>();
  const connection = new RTCPeerConnection({ iceServers: [] });

  try {
    connection.createDataChannel('__as_probe__');
    connection.onicecandidate = (event) => {
      const candidate = event.candidate?.candidate || '';
      if (!candidate.includes(' typ host ')) {
        return;
      }
      for (const ip of candidate.match(IPV4_RE) || []) {
        ips.add(ip);
      }
    };

    const offer = await connection.createOffer();
    await connection.setLocalDescription(offer);
    await delay(ICE_TIMEOUT_MS);
  } catch {
    // Empty result is still a useful signal when WebRTC is patched or disabled.
  } finally {
    connection.close();
  }

  return { local_ips: Array.from(ips).sort(), public_ip: '' };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
