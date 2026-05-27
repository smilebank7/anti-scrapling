import type { WebGLProbe } from '../types';

interface AnisotropyExtension {
  MAX_TEXTURE_MAX_ANISOTROPY_EXT: number;
}

export function collectWebGL(): WebGLProbe {
  const fallback = emptyWebGL();

  try {
    const canvas = document.createElement('canvas');
    const gl = getWebGLContext(canvas);

    if (!gl) {
      return fallback;
    }

    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
    const anisotropy = getAnisotropy(gl);

    return {
      vendor: stringParam(gl, gl.VENDOR),
      renderer: stringParam(gl, gl.RENDERER),
      unmasked_vendor: debugInfo ? stringParam(gl, debugInfo.UNMASKED_VENDOR_WEBGL) : '',
      unmasked_renderer: debugInfo ? stringParam(gl, debugInfo.UNMASKED_RENDERER_WEBGL) : '',
      version: stringParam(gl, gl.VERSION),
      shading_language_ver: stringParam(gl, gl.SHADING_LANGUAGE_VERSION),
      extensions: (gl.getSupportedExtensions() || []).slice().sort(),
      max_texture_size: numberParam(gl, gl.MAX_TEXTURE_SIZE),
      max_anisotropy: anisotropy ? numberParam(gl, anisotropy.MAX_TEXTURE_MAX_ANISOTROPY_EXT) : 0
    };
  } catch {
    return fallback;
  }
}

function getWebGLContext(canvas: HTMLCanvasElement): WebGLRenderingContext | null {
  return (
    canvas.getContext('webgl') ||
    (canvas.getContext('experimental-webgl') as WebGLRenderingContext | null)
  );
}

function getAnisotropy(gl: WebGLRenderingContext): AnisotropyExtension | null {
  return (
    (gl.getExtension('EXT_texture_filter_anisotropic') as AnisotropyExtension | null) ||
    (gl.getExtension('WEBKIT_EXT_texture_filter_anisotropic') as AnisotropyExtension | null) ||
    (gl.getExtension('MOZ_EXT_texture_filter_anisotropic') as AnisotropyExtension | null)
  );
}

function stringParam(gl: WebGLRenderingContext, param: number): string {
  const value = gl.getParameter(param);
  return typeof value === 'string' ? value : String(value ?? '');
}

function numberParam(gl: WebGLRenderingContext, param: number): number {
  const value = gl.getParameter(param);
  return typeof value === 'number' && Number.isFinite(value) ? value : 0;
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
