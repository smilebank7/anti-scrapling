import type {
  AudioProbe,
  CanvasProbe,
  ChromeProbe,
  CodecsProbe,
  DOMProbe,
  FingerprintReport,
  FontsProbe,
  HairlineProbe,
  NavigatorProbe,
  PermissionsProbe,
  RuntimeProbe,
  ServiceWorkerProbe,
  SpeechProbe,
  WebGLProbe,
  WebRTCProbe,
  WindowProbe
} from '../types';
import { collectAudio } from './audio';
import { collectCanvas } from './canvas';
import { collectChrome } from './chrome';
import { collectCodecs } from './codecs';
import { collectDOM } from './dom';
import { collectFonts } from './fonts';
import { collectHairline } from './hairline';
import { collectNavigator } from './navigator';
import { collectPermissions } from './permissions';
import { collectRuntime } from './runtime';
import { collectServiceWorker } from './serviceworker';
import { collectSpeech } from './speech';
import { collectWebGL } from './webgl';
import { collectWebRTC } from './webrtc';
import { collectWindow } from './window';

export async function collectFingerprintReport(): Promise<FingerprintReport> {
  const started = performance.now();
  const [
    navigatorProbe,
    webgl,
    canvas,
    audio,
    codecs,
    fonts,
    windowProbe,
    chrome,
    permissions,
    webrtc,
    dom,
    runtime,
    speech,
    serviceWorker,
    hairline
  ] = await Promise.all([
    safe(collectNavigator, emptyNavigator()),
    safe(collectWebGL, emptyWebGL()),
    safe(collectCanvas, emptyCanvas()),
    safe(collectAudio, emptyAudio()),
    safe(collectCodecs, emptyCodecs()),
    safe(collectFonts, emptyFonts()),
    safe(collectWindow, emptyWindow()),
    safe(collectChrome, emptyChrome()),
    safe(collectPermissions, emptyPermissions()),
    safe(collectWebRTC, emptyWebRTC()),
    safe(collectDOM, emptyDOM()),
    safe(collectRuntime, emptyRuntime()),
    safe(collectSpeech, emptySpeech()),
    safe(collectServiceWorker, emptyServiceWorker()),
    safe(collectHairline, emptyHairline())
  ]);

  return {
    version: 1,
    navigator: navigatorProbe,
    webgl,
    canvas,
    audio,
    codecs,
    fonts,
    window: windowProbe,
    chrome,
    permissions,
    webrtc,
    dom,
    runtime,
    speech,
    service_worker: serviceWorker,
    hairline,
    timing: {
      collection_duration_ms: Math.round(performance.now() - started),
      navigation_start: navigationStart(),
      dom_content_loaded: domContentLoaded()
    }
  };
}

async function safe<T>(collector: () => T | Promise<T>, fallback: T): Promise<T> {
  try {
    return await collector();
  } catch {
    return fallback;
  }
}

function navigationStart(): number {
  const timing = performance.timing;
  return Math.round(performance.timeOrigin || timing?.navigationStart || Date.now());
}

function domContentLoaded(): number {
  const navigation = performance.getEntriesByType('navigation')[0] as PerformanceNavigationTiming | undefined;
  if (navigation) {
    return Math.round(navigationStart() + navigation.domContentLoadedEventEnd);
  }
  return Math.round(performance.timing?.domContentLoadedEventEnd || 0);
}

function emptyNavigator(): NavigatorProbe {
  return {
    user_agent: '',
    platform: '',
    vendor: '',
    languages: [],
    language: '',
    hardware_concurrency: 0,
    device_memory: 0,
    webdriver: false,
    plugins: [],
    mime_types: [],
    product: '',
    product_sub: ''
  };
}

function emptyWebGL(): WebGLProbe {
  return {
    vendor: '',
    renderer: '',
    unmasked_vendor: '',
    unmasked_renderer: '',
    version: '',
    shading_language_ver: '',
    extensions: [],
    max_texture_size: 0,
    max_anisotropy: 0
  };
}

function emptyCanvas(): CanvasProbe {
  return { hashes: [], variance: 0 };
}

function emptyAudio(): AudioProbe {
  return { hashes: [], variance: 0 };
}

function emptyCodecs(): CodecsProbe {
  return { common: {}, rare: {} };
}

function emptyFonts(): FontsProbe {
  return { detected_count: 0, detected: [], missing_os_bundled: [] };
}

function emptyWindow(): WindowProbe {
  return {
    inner_width: 0,
    inner_height: 0,
    outer_width: 0,
    outer_height: 0,
    screen_width: 0,
    screen_height: 0,
    device_pixel_ratio: 0,
    color_depth: 0,
    pixel_depth: 0
  };
}

function emptyChrome(): ChromeProbe {
  return { present: false, runtime_present: false, app_present: false, load_times_present: false, csi_present: false };
}

function emptyPermissions(): PermissionsProbe {
  return { notifications_state: 'unsupported', midi_state: 'unsupported', camera_state: 'unsupported' };
}

function emptyWebRTC(): WebRTCProbe {
  return { local_ips: [], public_ip: '' };
}

function emptyDOM(): DOMProbe {
  return { iframe_content_window_identity: false, closed_shadow_root_accessible: false, document_element_keys: [] };
}

function emptyRuntime(): RuntimeProbe {
  return {
    function_to_string_native: false,
    console_debug_arity: 0,
    console_debug_to_string: '',
    eval_length: 0,
    error_stack_contains_pw_sig: false
  };
}

function emptySpeech(): SpeechProbe {
  return { voices_count: 0, voices: [] };
}

function emptyServiceWorker(): ServiceWorkerProbe {
  return { registered: false, controller: false, error: 'unsupported' };
}

function emptyHairline(): HairlineProbe {
  return { non_modernizr_result: 0 };
}
