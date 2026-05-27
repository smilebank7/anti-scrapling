package types

// FingerprintReport is collected by the client-side challenge bundle and POSTed to /__as/verify.
// MUST stay in sync with web/challenge/src/types.ts.
type FingerprintReport struct {
	Version int `json:"version"`

	Navigator     NavigatorProbe     `json:"navigator"`
	WebGL         WebGLProbe         `json:"webgl"`
	Canvas        CanvasProbe        `json:"canvas"`
	Audio         AudioProbe         `json:"audio"`
	Codecs        CodecsProbe        `json:"codecs"`
	Fonts         FontsProbe         `json:"fonts"`
	Window        WindowProbe        `json:"window"`
	Chrome        ChromeProbe        `json:"chrome"`
	Permissions   PermissionsProbe   `json:"permissions"`
	WebRTC        WebRTCProbe        `json:"webrtc"`
	DOM           DOMProbe           `json:"dom"`
	Runtime       RuntimeProbe       `json:"runtime"`
	Speech        SpeechProbe        `json:"speech"`
	ServiceWorker ServiceWorkerProbe `json:"service_worker"`
	Hairline      HairlineProbe      `json:"hairline"`
	Timing        TimingProbe        `json:"timing"`
}

// NavigatorProbe captures navigator.* properties.
type NavigatorProbe struct {
	UserAgent           string   `json:"user_agent"`
	Platform            string   `json:"platform"`
	Vendor              string   `json:"vendor"`
	Languages           []string `json:"languages"`
	Language            string   `json:"language"`
	HardwareConcurrency int      `json:"hardware_concurrency"`
	DeviceMemory        float64  `json:"device_memory"`
	Webdriver           bool     `json:"webdriver"`
	Plugins             []string `json:"plugins"`
	MimeTypes           []string `json:"mime_types"`
	Oscpu               string   `json:"oscpu,omitempty"`
	Product             string   `json:"product"`
	ProductSub          string   `json:"product_sub"`
}

// WebGLProbe captures WebGL renderer and extension information.
type WebGLProbe struct {
	Vendor             string   `json:"vendor"`
	Renderer           string   `json:"renderer"`
	UnmaskedVendor     string   `json:"unmasked_vendor"`
	UnmaskedRenderer   string   `json:"unmasked_renderer"`
	Version            string   `json:"version"`
	ShadingLanguageVer string   `json:"shading_language_ver"`
	Extensions         []string `json:"extensions"`
	MaxTextureSize     int      `json:"max_texture_size"`
	MaxAnisotropy      float64  `json:"max_anisotropy"`
}

// CanvasProbe captures multiple canvas renders to detect seeded noise injection.
type CanvasProbe struct {
	// Hashes holds 3 renders of the same canvas; identical values indicate no noise.
	Hashes []string `json:"hashes"`
	// Variance is the count of unique hashes (1=stable, 2-3=seeded noise injected).
	Variance int `json:"variance"`
}

// AudioProbe captures multiple AudioContext renders to detect seeded noise injection.
type AudioProbe struct {
	// Hashes holds 3 renders of the same audio context; identical values indicate no noise.
	Hashes []string `json:"hashes"`
	// Variance is the count of unique hashes (1=stable, 2-3=seeded noise injected).
	Variance int `json:"variance"`
}

// CodecsProbe maps codec strings to their MediaCapabilities support level.
type CodecsProbe struct {
	Common map[string]string `json:"common"` // mp4, webm, h264, vp9 -> "probably"/"maybe"/""
	Rare   map[string]string `json:"rare"`   // hevc, av1 profile 1, dolby vision
}

// FontsProbe reports which system fonts were detected via font-measurement technique.
type FontsProbe struct {
	DetectedCount    int      `json:"detected_count"`
	Detected         []string `json:"detected"`
	MissingOSBundled []string `json:"missing_os_bundled"` // OS-bundled fonts that should exist but weren't detected
}

// WindowProbe captures window and screen geometry.
type WindowProbe struct {
	InnerWidth       int     `json:"inner_width"`
	InnerHeight      int     `json:"inner_height"`
	OuterWidth       int     `json:"outer_width"`
	OuterHeight      int     `json:"outer_height"`
	ScreenWidth      int     `json:"screen_width"`
	ScreenHeight     int     `json:"screen_height"`
	DevicePixelRatio float64 `json:"device_pixel_ratio"`
	ColorDepth       int     `json:"color_depth"`
	PixelDepth       int     `json:"pixel_depth"`
}

// ChromeProbe detects presence of chrome.* extension APIs, which scrapers often spoof incorrectly.
type ChromeProbe struct {
	Present             bool   `json:"present"`                         // window.chrome exists
	RuntimePresent      bool   `json:"runtime_present"`                 // window.chrome.runtime exists
	AppPresent          bool   `json:"app_present"`                     // window.chrome.app exists
	LoadTimesPresent    bool   `json:"load_times_present"`              // legacy chrome.loadTimes
	CsiPresent          bool   `json:"csi_present"`                     // chrome.csi
	RuntimeConnectError string `json:"runtime_connect_error,omitempty"` // result of chrome.runtime.connect()
}

// PermissionsProbe checks the Permissions API state for key permission types.
type PermissionsProbe struct {
	NotificationsState string `json:"notifications_state"` // "granted"/"denied"/"prompt"
	MidiState          string `json:"midi_state"`
	CameraState        string `json:"camera_state"`
}

// WebRTCProbe leaks local IPs via STUN; the server compares PublicIP against socket IP.
type WebRTCProbe struct {
	LocalIPs []string `json:"local_ips"`
	PublicIP string   `json:"public_ip"`
}

// DOMProbe runs structural tests that expose automation framework patches.
type DOMProbe struct {
	IframeContentWindowIdentity bool     `json:"iframe_content_window_identity"` // detects playwright-stealth iframe patch
	ClosedShadowRootAccessible  bool     `json:"closed_shadow_root_accessible"`  // patchright leaks here
	DocumentElementKeys         []string `json:"document_element_keys"`
}

// RuntimeProbe checks for native function integrity and automation signatures.
type RuntimeProbe struct {
	FunctionToStringNative  bool   `json:"function_to_string_native"`
	ConsoleDebugArity       int    `json:"console_debug_arity"` // patched if 0
	ConsoleDebugToString    string `json:"console_debug_to_string"`
	EvalLength              int    `json:"eval_length"`
	ErrorStackContainsPwSig bool   `json:"error_stack_contains_pw_sig"` // looks for __playwright/__pwInitScripts
}

// SpeechProbe captures the speech synthesis voice list.
type SpeechProbe struct {
	VoicesCount int      `json:"voices_count"`
	Voices      []string `json:"voices"`
}

// ServiceWorkerProbe tests whether a service worker can be registered and activates.
type ServiceWorkerProbe struct {
	Registered bool   `json:"registered"`
	Controller bool   `json:"controller"`
	Error      string `json:"error,omitempty"`
}

// HairlineProbe runs a non-Modernizr sub-pixel detection trap.
type HairlineProbe struct {
	// NonModernizrResult should be 0 for real browsers.
	NonModernizrResult int `json:"non_modernizr_result"`
}

// TimingProbe records collection performance and page load milestones.
type TimingProbe struct {
	CollectionDurationMs int   `json:"collection_duration_ms"`
	NavigationStart      int64 `json:"navigation_start"`
	DomContentLoaded     int64 `json:"dom_content_loaded"`
}
