import type { HairlineProbe } from '../types';

export function collectHairline(): HairlineProbe {
  const probe = document.createElement('div');
  probe.id = '__as_hairline_probe__';
  probe.style.cssText = [
    'position:absolute',
    'left:-9999px',
    'top:-9999px',
    'width:0',
    'height:0',
    'margin:0',
    'padding:0',
    'border-top:0.5px solid transparent'
  ].join(';');

  try {
    (document.body || document.documentElement).appendChild(probe);
    return { non_modernizr_result: probe.offsetHeight };
  } catch {
    return { non_modernizr_result: 0 };
  } finally {
    probe.remove();
  }
}
