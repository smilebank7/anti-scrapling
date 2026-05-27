import type { WindowProbe } from '../types';

export function collectWindow(): WindowProbe {
  return {
    inner_width: window.innerWidth || 0,
    inner_height: window.innerHeight || 0,
    outer_width: window.outerWidth || 0,
    outer_height: window.outerHeight || 0,
    screen_width: window.screen?.width || 0,
    screen_height: window.screen?.height || 0,
    device_pixel_ratio: window.devicePixelRatio || 0,
    color_depth: window.screen?.colorDepth || 0,
    pixel_depth: window.screen?.pixelDepth || 0
  };
}
