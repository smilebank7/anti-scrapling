export interface FingerprintReport {
  version: number;
  navigator: NavigatorProbe;
  webgl: WebGLProbe;
  canvas: CanvasProbe;
  audio: AudioProbe;
  codecs: CodecsProbe;
  fonts: FontsProbe;
  window: WindowProbe;
  chrome: ChromeProbe;
  permissions: PermissionsProbe;
  webrtc: WebRTCProbe;
  dom: DOMProbe;
  runtime: RuntimeProbe;
  speech: SpeechProbe;
  service_worker: ServiceWorkerProbe;
  hairline: HairlineProbe;
  timing: TimingProbe;
}

export interface NavigatorProbe {
  user_agent: string;
  platform: string;
  vendor: string;
  languages: string[];
  language: string;
  hardware_concurrency: number;
  device_memory: number;
  webdriver: boolean;
  plugins: string[];
  mime_types: string[];
  oscpu?: string;
  product: string;
  product_sub: string;
}

export interface WebGLProbe {
  vendor: string;
  renderer: string;
  unmasked_vendor: string;
  unmasked_renderer: string;
  version: string;
  shading_language_ver: string;
  extensions: string[];
  max_texture_size: number;
  max_anisotropy: number;
}

export interface CanvasProbe {
  hashes: string[];
  variance: number;
}

export interface AudioProbe {
  hashes: string[];
  variance: number;
}

export interface CodecsProbe {
  common: Record<string, string>;
  rare: Record<string, string>;
}

export interface FontsProbe {
  detected_count: number;
  detected: string[];
  missing_os_bundled: string[];
}

export interface WindowProbe {
  inner_width: number;
  inner_height: number;
  outer_width: number;
  outer_height: number;
  screen_width: number;
  screen_height: number;
  device_pixel_ratio: number;
  color_depth: number;
  pixel_depth: number;
}

export interface ChromeProbe {
  present: boolean;
  runtime_present: boolean;
  app_present: boolean;
  load_times_present: boolean;
  csi_present: boolean;
  runtime_connect_error?: string;
}

export interface PermissionsProbe {
  notifications_state: string;
  midi_state: string;
  camera_state: string;
}

export interface WebRTCProbe {
  local_ips: string[];
  public_ip: string;
}

export interface DOMProbe {
  iframe_content_window_identity: boolean;
  closed_shadow_root_accessible: boolean;
  document_element_keys: string[];
}

export interface RuntimeProbe {
  function_to_string_native: boolean;
  console_debug_arity: number;
  console_debug_to_string: string;
  eval_length: number;
  error_stack_contains_pw_sig: boolean;
}

export interface SpeechProbe {
  voices_count: number;
  voices: string[];
}

export interface ServiceWorkerProbe {
  registered: boolean;
  controller: boolean;
  error?: string;
}

export interface HairlineProbe {
  non_modernizr_result: number;
}

export interface TimingProbe {
  collection_duration_ms: number;
  navigation_start: number;
  dom_content_loaded: number;
}

export interface BehaviorBeacon {
  session_id: string;
  timestamp: number;
  mouse: MouseMetrics;
  scroll: ScrollMetrics;
  visibility: VisibilityMetrics;
  resource_fetches: ResourceMetrics;
}

export interface MouseMetrics {
  move_count: number;
  path_length: number;
  avg_velocity: number;
  jitter_index: number;
  clicks: number;
  click_intervals_ms: number[];
}

export interface ScrollMetrics {
  events: number;
  max_y: number;
}

export interface VisibilityMetrics {
  hidden_ms: number;
  visible_ms: number;
}

export interface ResourceMetrics {
  css: number;
  image: number;
  font: number;
  script: number;
  xhr: number;
}

export interface PowSolution {
  nonce: number;
  hash: string;
  difficulty: number;
  duration_ms: number;
}

export interface ChallengeParams {
  challenge_id: string;
  difficulty: number;
  beacon_interval_ms?: number;
}

export interface VerifyPayload {
  pow_solution: PowSolution;
  fingerprint_report: FingerprintReport;
  challenge_id: string;
}
