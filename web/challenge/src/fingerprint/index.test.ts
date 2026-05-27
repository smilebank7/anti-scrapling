// @vitest-environment jsdom
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { collectFingerprintReport } from './index';

describe('fingerprint report', () => {
  let originalGetContext: typeof HTMLCanvasElement.prototype.getContext;

  beforeAll(() => {
    originalGetContext = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = () => null;
  });

  afterAll(() => {
    HTMLCanvasElement.prototype.getContext = originalGetContext;
  });

  it('returns a Go-compatible report shape', async () => {
    const report = await collectFingerprintReport();

    expect(report.version).toBe(1);
    expect(report.navigator.user_agent).toEqual(expect.any(String));
    expect(report.webgl.extensions).toEqual(expect.any(Array));
    expect(report.canvas.hashes).toEqual(expect.any(Array));
    expect(report.audio.hashes).toEqual(expect.any(Array));
    expect(report.codecs.common).toEqual(expect.any(Object));
    expect(report.fonts.missing_os_bundled).toEqual(expect.any(Array));
    expect(report.window.inner_width).toEqual(expect.any(Number));
    expect(report.chrome.present).toEqual(expect.any(Boolean));
    expect(report.permissions.notifications_state).toEqual(expect.any(String));
    expect(report.webrtc.local_ips).toEqual(expect.any(Array));
    expect(report.dom.document_element_keys).toEqual(expect.any(Array));
    expect(report.runtime.eval_length).toEqual(expect.any(Number));
    expect(report.speech.voices).toEqual(expect.any(Array));
    expect(report.service_worker.registered).toEqual(expect.any(Boolean));
    expect(report.hairline.non_modernizr_result).toEqual(expect.any(Number));
    expect(report.timing.collection_duration_ms).toBeGreaterThanOrEqual(0);
  });
});
