import type { BehaviorBeacon, MouseMetrics, ResourceMetrics, VisibilityMetrics } from './types';

export interface BehaviorOptions {
  endpoint?: string;
  interval_ms?: number;
  session_id?: string;
}

const DEFAULT_ENDPOINT = '/__as/beacon';
const DEFAULT_INTERVAL_MS = 5000;

export class BehaviorCollector {
  private readonly endpoint: string;
  private readonly intervalMs: number;
  private readonly sessionId: string;
  private intervalId = 0;
  private lastMouse?: { x: number; y: number; t: number };
  private lastClickAt = 0;
  private readonly velocities: number[] = [];
  private readonly clickIntervals: number[] = [];
  private moveCount = 0;
  private pathLength = 0;
  private clicks = 0;
  private scrollEvents = 0;
  private maxScrollY = 0;
  private hiddenMs = 0;
  private visibleMs = 0;
  private visibilityState = document.visibilityState;
  private visibilityChangedAt = Date.now();
  private readonly resources: ResourceMetrics = { css: 0, image: 0, font: 0, script: 0, xhr: 0 };
  private observer?: PerformanceObserver;

  constructor(options: BehaviorOptions = {}) {
    this.endpoint = options.endpoint || DEFAULT_ENDPOINT;
    this.intervalMs = options.interval_ms || DEFAULT_INTERVAL_MS;
    this.sessionId = options.session_id || newSessionId();
  }

  start(): void {
    this.countExistingResources();
    this.observeResources();
    window.addEventListener('mousemove', this.onMouseMove, { passive: true });
    window.addEventListener('click', this.onClick, { passive: true });
    window.addEventListener('scroll', this.onScroll, { passive: true });
    document.addEventListener('visibilitychange', this.onVisibilityChange);
    window.addEventListener('pagehide', this.onPageHide);
    this.intervalId = window.setInterval(() => void this.send(false), this.intervalMs);
  }

  stop(): void {
    window.clearInterval(this.intervalId);
    window.removeEventListener('mousemove', this.onMouseMove);
    window.removeEventListener('click', this.onClick);
    window.removeEventListener('scroll', this.onScroll);
    document.removeEventListener('visibilitychange', this.onVisibilityChange);
    window.removeEventListener('pagehide', this.onPageHide);
    this.observer?.disconnect();
  }

  snapshot(): BehaviorBeacon {
    const visibility = this.visibilitySnapshot();
    return {
      session_id: this.sessionId,
      timestamp: Date.now(),
      mouse: this.mouseSnapshot(),
      scroll: { events: this.scrollEvents, max_y: this.maxScrollY },
      visibility,
      resource_fetches: { ...this.resources }
    };
  }

  async send(keepalive: boolean): Promise<void> {
    try {
      await fetch(this.endpoint, {
        method: 'POST',
        credentials: 'same-origin',
        keepalive,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(this.snapshot())
      });
    } catch {
      // Behavior telemetry should never block the challenge flow.
    }
  }

  private readonly onMouseMove = (event: MouseEvent): void => {
    const now = performance.now();
    this.moveCount += 1;

    if (this.lastMouse) {
      const dx = event.clientX - this.lastMouse.x;
      const dy = event.clientY - this.lastMouse.y;
      const distance = Math.hypot(dx, dy);
      const dt = now - this.lastMouse.t;
      this.pathLength += distance;
      if (dt > 0) {
        this.velocities.push((distance / dt) * 1000);
      }
    }

    this.lastMouse = { x: event.clientX, y: event.clientY, t: now };
  };

  private readonly onClick = (): void => {
    const now = Date.now();
    this.clicks += 1;
    if (this.lastClickAt > 0) {
      this.clickIntervals.push(now - this.lastClickAt);
    }
    this.lastClickAt = now;
  };

  private readonly onScroll = (): void => {
    this.scrollEvents += 1;
    this.maxScrollY = Math.max(this.maxScrollY, Math.round(window.scrollY || window.pageYOffset || 0));
  };

  private readonly onVisibilityChange = (): void => {
    this.updateVisibilityTimers();
  };

  private readonly onPageHide = (): void => {
    this.updateVisibilityTimers();
    void this.send(true);
  };

  private mouseSnapshot(): MouseMetrics {
    return {
      move_count: this.moveCount,
      path_length: round(this.pathLength),
      avg_velocity: round(average(this.velocities)),
      jitter_index: round(stddev(this.velocities)),
      clicks: this.clicks,
      click_intervals_ms: this.clickIntervals.slice(-32)
    };
  }

  private visibilitySnapshot(): VisibilityMetrics {
    const now = Date.now();
    const delta = now - this.visibilityChangedAt;
    return this.visibilityState === 'hidden'
      ? { hidden_ms: Math.round(this.hiddenMs + delta), visible_ms: Math.round(this.visibleMs) }
      : { hidden_ms: Math.round(this.hiddenMs), visible_ms: Math.round(this.visibleMs + delta) };
  }

  private updateVisibilityTimers(): void {
    const now = Date.now();
    const delta = now - this.visibilityChangedAt;
    if (this.visibilityState === 'hidden') {
      this.hiddenMs += delta;
    } else {
      this.visibleMs += delta;
    }
    this.visibilityState = document.visibilityState;
    this.visibilityChangedAt = now;
  }

  private countExistingResources(): void {
    for (const entry of performance.getEntriesByType('resource') as PerformanceResourceTiming[]) {
      this.countResource(entry);
    }
  }

  private observeResources(): void {
    if (!globalThis.PerformanceObserver) {
      return;
    }

    try {
      this.observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries() as PerformanceResourceTiming[]) {
          this.countResource(entry);
        }
      });
      this.observer.observe({ type: 'resource', buffered: true });
    } catch {
      this.observer = undefined;
    }
  }

  private countResource(entry: PerformanceResourceTiming): void {
    switch (entry.initiatorType) {
      case 'css':
      case 'link':
        this.resources.css += 1;
        break;
      case 'img':
      case 'image':
        this.resources.image += 1;
        break;
      case 'font':
        this.resources.font += 1;
        break;
      case 'script':
        this.resources.script += 1;
        break;
      case 'fetch':
      case 'xmlhttprequest':
        this.resources.xhr += 1;
        break;
    }
  }
}

export function startBehaviorCollector(options: BehaviorOptions = {}): BehaviorCollector {
  const collector = new BehaviorCollector(options);
  collector.start();
  return collector;
}

function newSessionId(): string {
  return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function average(values: readonly number[]): number {
  return values.length === 0 ? 0 : values.reduce((sum, value) => sum + value, 0) / values.length;
}

function stddev(values: readonly number[]): number {
  if (values.length < 2) {
    return 0;
  }
  const avg = average(values);
  const variance = average(values.map((value) => (value - avg) ** 2));
  return Math.sqrt(variance);
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}
