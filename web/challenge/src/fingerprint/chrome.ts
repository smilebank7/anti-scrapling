import type { ChromeProbe } from '../types';

interface ChromeRuntime {
  connect?: (options?: { name?: string }) => { disconnect?: () => void };
}

interface ChromeLike {
  runtime?: ChromeRuntime;
  app?: unknown;
  loadTimes?: unknown;
  csi?: unknown;
}

interface ChromeWindow extends Window {
  chrome?: ChromeLike;
}

export function collectChrome(): ChromeProbe {
  const chrome = (window as ChromeWindow).chrome;
  const runtime = chrome?.runtime;
  let runtimeConnectError = '';

  if (runtime?.connect) {
    try {
      const port = runtime.connect({ name: '__as_probe__' });
      port?.disconnect?.();
    } catch (error) {
      runtimeConnectError = error instanceof Error ? error.message : String(error);
    }
  }

  return {
    present: Boolean(chrome),
    runtime_present: Boolean(runtime),
    app_present: Boolean(chrome?.app),
    load_times_present: Boolean(chrome?.loadTimes),
    csi_present: Boolean(chrome?.csi),
    runtime_connect_error: runtimeConnectError
  };
}
