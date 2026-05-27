import type { NavigatorProbe } from '../types';

interface NavigatorExtras extends Navigator {
  deviceMemory?: number;
  oscpu?: string;
  webdriver?: boolean;
}

export function collectNavigator(): NavigatorProbe {
  const nav = navigator as NavigatorExtras;
  const report: NavigatorProbe = {
    user_agent: nav.userAgent || '',
    platform: nav.platform || '',
    vendor: nav.vendor || '',
    languages: Array.from(nav.languages || []),
    language: nav.language || '',
    hardware_concurrency: nav.hardwareConcurrency || 0,
    device_memory: nav.deviceMemory || 0,
    webdriver: Boolean(nav.webdriver),
    plugins: pluginNames(nav.plugins),
    mime_types: mimeTypeNames(nav.mimeTypes),
    product: nav.product || '',
    product_sub: nav.productSub || ''
  };

  if (nav.oscpu) {
    report.oscpu = nav.oscpu;
  }

  return report;
}

function pluginNames(plugins: PluginArray): string[] {
  return Array.from(plugins || [], (plugin) => plugin.name).filter(Boolean);
}

function mimeTypeNames(mimeTypes: MimeTypeArray): string[] {
  return Array.from(mimeTypes || [], (mimeType) => mimeType.type).filter(Boolean);
}
