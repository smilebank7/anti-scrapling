import type { ServiceWorkerProbe } from '../types';

const SERVICE_WORKER_URL = '/__as/sw.js';
const SERVICE_WORKER_WAIT_MS = 1000;

export async function collectServiceWorker(): Promise<ServiceWorkerProbe> {
  if (!navigator.serviceWorker) {
    return { registered: false, controller: false, error: 'unsupported' };
  }

  if (!window.isSecureContext) {
    return { registered: false, controller: false, error: 'insecure_context' };
  }

  let registration: ServiceWorkerRegistration | undefined;

  try {
    registration = await navigator.serviceWorker.register(SERVICE_WORKER_URL, { scope: '/__as/' });
    await delay(SERVICE_WORKER_WAIT_MS);
    return {
      registered: true,
      controller: Boolean(navigator.serviceWorker.controller)
    };
  } catch (error) {
    return {
      registered: false,
      controller: Boolean(navigator.serviceWorker.controller),
      error: error instanceof Error ? error.message : String(error)
    };
  } finally {
    await registration?.unregister().catch(() => undefined);
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
