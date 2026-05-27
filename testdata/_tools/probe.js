/**
 * probe.js — Developer fingerprint probe tool.
 * Runs every detection probe from docs/01-threat-model.md.
 * Output matches FingerprintReport schema (internal/types/fingerprint.go).
 * No build step required. Vanilla JS. Open probe.html in target browser.
 */

async function runAllProbes() {
    const t0 = performance.now();

    const report = {
        version: 1,
        navigator: probeNavigator(),
        webgl: probeWebGL(),
        canvas: await probeCanvas(),
        audio: await probeAudio(),
        codecs: probeCodecs(),
        fonts: await probeFonts(),
        window: probeWindow(),
        chrome: probeChrome(),
        permissions: await probePermissions(),
        webrtc: await probeWebRTC(),
        dom: probeDom(),
        runtime: probeRuntime(),
        speech: await probeSpeech(),
        service_worker: await probeServiceWorker(),
        hairline: probeHairline(),
        timing: {
            collection_duration_ms: 0,
            navigation_start: performance.timing ? performance.timing.navigationStart : 0,
            dom_content_loaded: performance.timing ? performance.timing.domContentLoadedEventEnd : 0,
        },
    };

    report.timing.collection_duration_ms = Math.round(performance.now() - t0);
    return report;
}

function probeNavigator() {
    const nav = navigator;
    const plugins = [];
    for (let i = 0; i < nav.plugins.length; i++) {
        plugins.push(nav.plugins[i].name);
    }
    const mimeTypes = [];
    for (let i = 0; i < nav.mimeTypes.length; i++) {
        mimeTypes.push(nav.mimeTypes[i].type);
    }
    return {
        user_agent: nav.userAgent || '',
        platform: nav.platform || '',
        vendor: nav.vendor || '',
        languages: Array.from(nav.languages || [nav.language]),
        language: nav.language || '',
        hardware_concurrency: nav.hardwareConcurrency || 0,
        device_memory: nav.deviceMemory || 0,
        webdriver: !!nav.webdriver,
        plugins: plugins,
        mime_types: mimeTypes,
        oscpu: nav.oscpu || '',
        product: nav.product || '',
        product_sub: nav.productSub || '',
    };
}

function probeWebGL() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return { vendor: '', renderer: '', unmasked_vendor: '', unmasked_renderer: '', version: '', shading_language_ver: '', extensions: [], max_texture_size: 0, max_anisotropy: 0 };
    const dbgInfo = gl.getExtension('WEBGL_debug_renderer_info');
    const anisoExt = gl.getExtension('EXT_texture_filter_anisotropic') || gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic');
    const exts = gl.getSupportedExtensions() || [];
    return {
        vendor: gl.getParameter(gl.VENDOR) || '',
        renderer: gl.getParameter(gl.RENDERER) || '',
        unmasked_vendor: dbgInfo ? (gl.getParameter(dbgInfo.UNMASKED_VENDOR_WEBGL) || '') : '',
        unmasked_renderer: dbgInfo ? (gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL) || '') : '',
        version: gl.getParameter(gl.VERSION) || '',
        shading_language_ver: gl.getParameter(gl.SHADING_LANGUAGE_VERSION) || '',
        extensions: exts,
        max_texture_size: gl.getParameter(gl.MAX_TEXTURE_SIZE) || 0,
        max_anisotropy: anisoExt ? (gl.getParameter(anisoExt.MAX_TEXTURE_MAX_ANISOTROPY_EXT) || 0) : 0,
    };
}

async function probeCanvas() {
    const hashes = [];
    for (let i = 0; i < 3; i++) {
        const c = document.createElement('canvas');
        c.width = 200; c.height = 50;
        const ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('Anti-Scrapling probe ' + i, 2, 15);
        ctx.fillStyle = 'rgba(102,204,0,0.7)';
        ctx.fillText('Canvas fingerprint', 4, 17);
        hashes.push(c.toDataURL().slice(-32));
    }
    const uniqueHashes = new Set(hashes).size;
    return { hashes: hashes, variance: uniqueHashes };
}

async function probeAudio() {
    const hashes = [];
    try {
        for (let i = 0; i < 3; i++) {
            const ctx = new (window.AudioContext || window.webkitAudioContext)({ sampleRate: 44100 });
            const osc = ctx.createOscillator();
            const analyser = ctx.createAnalyser();
            const gain = ctx.createGain();
            gain.gain.value = 0;
            osc.connect(analyser);
            analyser.connect(gain);
            gain.connect(ctx.destination);
            osc.start(0);
            await new Promise(r => setTimeout(r, 100));
            const buf = new Float32Array(analyser.frequencyBinCount);
            analyser.getFloatFrequencyData(buf);
            const sample = Array.from(buf.slice(0, 8)).map(v => v.toFixed(4)).join(',');
            hashes.push(sample);
            osc.stop();
            ctx.close();
        }
    } catch (e) {
        hashes.push('error:' + e.message, 'error:' + e.message, 'error:' + e.message);
    }
    const uniqueHashes = new Set(hashes).size;
    return { hashes: hashes, variance: uniqueHashes };
}

function probeCodecs() {
    const v = document.createElement('video');
    const a = document.createElement('audio');
    return {
        common: {
            mp4: v.canPlayType('video/mp4; codecs="avc1.42E01E"'),
            webm: v.canPlayType('video/webm; codecs="vp8, vorbis"'),
            h264: v.canPlayType('video/mp4; codecs="avc1.42E01E, mp4a.40.2"'),
            vp9: v.canPlayType('video/webm; codecs="vp9"'),
        },
        rare: {
            hevc: v.canPlayType('video/mp4; codecs="hev1.1.6.L93.B0"'),
            av1_p1: v.canPlayType('video/webm; codecs="av01.0.05M.08"'),
            dolby_vision: v.canPlayType('video/mp4; codecs="dvhe.05.06"'),
        },
    };
}

async function probeFonts() {
    const testFonts = [
        'Arial', 'Verdana', 'Helvetica', 'Times New Roman', 'Courier New',
        'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
        'Trebuchet MS', 'Arial Black', 'Impact', 'Lucida Console',
        'Tahoma', 'Geneva', 'Optima', 'Futura', 'Gill Sans',
        'Baskerville', 'Didot', 'American Typewriter',
        'Ubuntu', 'Noto Sans', 'Liberation Sans', 'DejaVu Sans',
    ];
    const detected = [];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const baseWidths = {};
    for (const base of baseFonts) {
        ctx.font = `${testSize} ${base}`;
        baseWidths[base] = ctx.measureText(testString).width;
    }
    for (const font of testFonts) {
        for (const base of baseFonts) {
            ctx.font = `${testSize} '${font}', ${base}`;
            const w = ctx.measureText(testString).width;
            if (w !== baseWidths[base]) {
                detected.push(font);
                break;
            }
        }
    }
    const osExpected = ['Arial', 'Verdana', 'Helvetica', 'Times New Roman', 'Courier New'];
    const missing = osExpected.filter(f => !detected.includes(f));
    return { detected_count: detected.length, detected: detected, missing_os_bundled: missing };
}

function probeWindow() {
    return {
        inner_width: window.innerWidth,
        inner_height: window.innerHeight,
        outer_width: window.outerWidth,
        outer_height: window.outerHeight,
        screen_width: screen.width,
        screen_height: screen.height,
        device_pixel_ratio: window.devicePixelRatio || 1,
        color_depth: screen.colorDepth || 0,
        pixel_depth: screen.pixelDepth || 0,
    };
}

function probeChrome() {
    const present = typeof window.chrome !== 'undefined';
    let runtimePresent = false;
    let appPresent = false;
    let loadTimesPresent = false;
    let csiPresent = false;
    let runtimeConnectError = '';

    if (present) {
        runtimePresent = !!(window.chrome && window.chrome.runtime);
        appPresent = !!(window.chrome && window.chrome.app);
        loadTimesPresent = typeof window.chrome.loadTimes === 'function';
        csiPresent = typeof window.chrome.csi === 'function';
        if (runtimePresent) {
            try {
                window.chrome.runtime.connect('nonexistent_extension_id_probe');
            } catch (e) {
                runtimeConnectError = e.toString();
            }
        }
    }
    return { present, runtime_present: runtimePresent, app_present: appPresent, load_times_present: loadTimesPresent, csi_present: csiPresent, runtime_connect_error: runtimeConnectError };
}

async function probePermissions() {
    async function queryState(name) {
        try {
            const r = await navigator.permissions.query({ name });
            return r.state;
        } catch (e) {
            return 'error:' + e.message;
        }
    }
    return {
        notifications_state: await queryState('notifications'),
        midi_state: await queryState('midi'),
        camera_state: await queryState('camera'),
    };
}

async function probeWebRTC() {
    const ips = [];
    let publicIp = '';
    try {
        const pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
        pc.createDataChannel('');
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        await new Promise(resolve => {
            const timeout = setTimeout(resolve, 3000);
            pc.onicecandidate = e => {
                if (!e || !e.candidate) { clearTimeout(timeout); resolve(); return; }
                const m = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
                if (m) m.forEach(ip => { if (!ips.includes(ip)) ips.push(ip); });
            };
        });
        pc.close();
    } catch (e) { }
    return { local_ips: ips, public_ip: publicIp };
}

function probeDom() {
    let iframeIdentity = false;
    let closedShadowAccessible = false;
    const keys = Object.keys(document.documentElement).slice(0, 20);

    try {
        const iframe = document.createElement('iframe');
        document.body.appendChild(iframe);
        iframeIdentity = iframe.contentWindow === iframe;
        document.body.removeChild(iframe);
    } catch (e) { }

    try {
        const host = document.createElement('div');
        const shadow = host.attachShadow({ mode: 'closed' });
        const inner = document.createElement('span');
        inner.textContent = 'probe';
        shadow.appendChild(inner);
        closedShadowAccessible = host.shadowRoot !== null;
    } catch (e) { }

    return { iframe_content_window_identity: iframeIdentity, closed_shadow_root_accessible: closedShadowAccessible, document_element_keys: keys };
}

function probeRuntime() {
    let fnToStringNative = false;
    let consoleDebugArity = -1;
    let consoleDebugToString = '';
    let evalLength = -1;
    let errorStackContainsPwSig = false;

    try {
        fnToStringNative = Function.prototype.toString.call(Array.prototype.push).includes('[native code]');
    } catch (e) { }

    try {
        consoleDebugArity = console.debug.length;
        consoleDebugToString = console.debug.toString();
    } catch (e) { }

    try {
        evalLength = eval.length;
    } catch (e) { }

    try {
        throw new Error('probe');
    } catch (e) {
        const stack = e.stack || '';
        errorStackContainsPwSig = stack.includes('playwright') || stack.includes('patchright') || stack.includes('puppeteer');
    }

    return {
        function_to_string_native: fnToStringNative,
        console_debug_arity: consoleDebugArity,
        console_debug_to_string: consoleDebugToString,
        eval_length: evalLength,
        error_stack_contains_pw_sig: errorStackContainsPwSig,
    };
}

async function probeSpeech() {
    return new Promise(resolve => {
        const synth = window.speechSynthesis;
        if (!synth) return resolve({ voices_count: 0, voices: [] });
        const getVoices = () => {
            const voices = synth.getVoices();
            resolve({ voices_count: voices.length, voices: voices.slice(0, 5).map(v => ({ name: v.name, lang: v.lang, local: v.localService })) });
        };
        const voices = synth.getVoices();
        if (voices.length > 0) {
            getVoices();
        } else {
            synth.onvoiceschanged = getVoices;
            setTimeout(() => resolve({ voices_count: 0, voices: [] }), 3000);
        }
    });
}

async function probeServiceWorker() {
    if (!('serviceWorker' in navigator)) {
        return { registered: false, controller: false, error: 'service_worker_api_absent' };
    }
    try {
        const reg = await navigator.serviceWorker.register('/probe-sw-noop.js', { scope: '/probe-sw-scope/' });
        await navigator.serviceWorker.ready;
        const hasController = !!navigator.serviceWorker.controller;
        return { registered: true, controller: hasController, error: '' };
    } catch (e) {
        return { registered: false, controller: false, error: e.toString() };
    }
}

function probeHairline() {
    let result = false;
    try {
        const el = document.createElement('canvas');
        el.id = 'non_modernizr_probe_' + Math.random().toString(36).slice(2);
        el.width = 1; el.height = 1;
        document.body.appendChild(el);
        const ctx = el.getContext('2d');
        ctx.fillRect(0, 0, 1, 0.5);
        const pixel = ctx.getImageData(0, 0, 1, 1).data;
        result = pixel[3] !== 255;
        document.body.removeChild(el);
    } catch (e) { }
    return { non_modernizr_result: result };
}

if (typeof module !== 'undefined') module.exports = { runAllProbes };
