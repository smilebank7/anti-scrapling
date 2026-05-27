import type { DOMProbe } from '../types';

export function collectDOM(): DOMProbe {
  return {
    iframe_content_window_identity: iframeIdentityProbe(),
    closed_shadow_root_accessible: closedShadowRootProbe(),
    document_element_keys: document.documentElement.getAttributeNames()
  };
}

function iframeIdentityProbe(): boolean {
  const iframe = document.createElement('iframe');
  iframe.srcdoc = '<!doctype html><title>probe</title>';
  iframe.style.display = 'none';
  const parent = document.body || document.documentElement;

  try {
    parent.appendChild(iframe);
    const first = iframe.contentWindow;
    const second = iframe.contentWindow;
    return Boolean(first && first === second && first.self === first);
  } catch {
    return false;
  } finally {
    iframe.remove();
  }
}

function closedShadowRootProbe(): boolean {
  const host = document.createElement('div');
  const parent = document.body || document.documentElement;

  try {
    parent.appendChild(host);
    host.attachShadow({ mode: 'closed' }).innerHTML = '<span>probe</span>';
    return host.shadowRoot !== null;
  } catch {
    return false;
  } finally {
    host.remove();
  }
}
