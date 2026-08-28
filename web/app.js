/*
 * Polling client for GET /api/rates.
 *
 * The server owns the rolling window, so this page holds no history: every poll
 * carries a complete, bucket-aligned series per device and the page simply
 * redraws it. Rows are reconciled by IP rather than rebuilt, so a canvas is
 * never thrown away and rows never flicker or reorder under the cursor.
 */
(() => {
  'use strict';

  // ── Constants ───────────────────────────────────────────────────────────

  /* Relative so the panel keeps working if it is ever served under a path
     prefix rather than at the site root. */
  const RATES_URL = 'api/rates';

  const POLL_INTERVAL_MS = 500;
  const MAX_BACKOFF_MS = 2000;
  const BACKOFF_FACTOR = 2;
  const REQUEST_TIMEOUT_MS = 2000;
  const STALE_IDLE_MS = 2000;
  const MS_PER_SECOND = 1000;

  /* capture.state values this page reacts to. Every other value - including
     ones a later phase invents - falls through to the warning banner, which is
     the entire reason the field carries a human-readable detail string. */
  const CAPTURE_STATE_OK = 'ok';
  const CAPTURE_STATE_MOCK = 'mock';

  const CONNECTION_CONNECTING = 'connecting';
  const CONNECTION_LIVE = 'live';
  const CONNECTION_DISCONNECTED = 'disconnected';

  /* Axis ticks as fractions across the graph column: oldest, midpoint, now. */
  const AXIS_TICK_FRACTIONS = [0, 0.5, 1];

  const GRAPH_TOP_PAD_PX = 4;
  const GRAPH_LINE_WIDTH_PX = 1;
  const MIN_Y_SCALE_PPS = 1;

  const SUBNET_PREFIX_OCTETS = 3;
  const IPV4_OCTETS = 4;

  const TEXT = Object.freeze({
    connection: Object.freeze({
      [CONNECTION_CONNECTING]: 'connecting',
      [CONNECTION_LIVE]: 'live',
      [CONNECTION_DISCONNECTED]: 'disconnected',
    }),
    deviceCount: (count) => `${count} ${count === 1 ? 'device' : 'devices'}`,
    subnet: (prefix) => `${prefix}.0/24`,
    rate: (pps) => `${formatRate(pps)} pps`,
    peak: (pps) => `peak ${formatRate(pps)}`,
    noTraffic: 'NO TRAFFIC',
    axisNow: 'now',
    axisSecondsAgo: (seconds) => `-${formatSeconds(seconds)}s`,
    graphLabel: (ip, pps) => `${ip}: ${formatRate(pps)} packets per second`,
    graphLabelStale: (ip) => `${ip}: no traffic`,
    captureFallback: (state) => `Packet capture unavailable (${state}).`,
    malformedPayload: 'Malformed /api/rates payload',
    disconnected: 'Lost contact with /api/rates; retrying.',
  });

  // ── Elements ────────────────────────────────────────────────────────────

  const els = Object.freeze({
    subnet: document.getElementById('subnet'),
    hostIp: document.getElementById('host-ip'),
    deviceCount: document.getElementById('device-count'),
    mockTag: document.getElementById('mock-tag'),
    connection: document.getElementById('connection'),
    connectionLabel: document.getElementById('connection-label'),
    banner: document.getElementById('banner'),
    emptyState: document.getElementById('empty-state'),
    rows: document.getElementById('rows'),
    axis: document.getElementById('axis'),
  });

  /* Canvas colours live in style.css so the palette has a single home. */
  const PALETTE = readPalette();

  // ── State ───────────────────────────────────────────────────────────────

  /** @type {Map<string, object>} IP to row view, in creation order. */
  const rowViews = new Map();
  /** @type {WeakMap<Element, object>} Canvas to its row view, for resize redraws. */
  const canvasOwners = new WeakMap();

  let axisWindowMs = null;
  let connectionState = CONNECTION_CONNECTING;
  let nextDelayMs = POLL_INTERVAL_MS;
  let pollTimer = null;

  // ── Formatting ──────────────────────────────────────────────────────────

  function numberOr(value, fallback) {
    return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
  }

  /** Sub-1 rates keep a decimal so a trickle does not read as a flat zero. */
  function formatRate(pps) {
    const rate = Math.max(0, numberOr(pps, 0));
    return rate > 0 && rate < 1 ? rate.toFixed(1) : String(Math.round(rate));
  }

  function formatSeconds(seconds) {
    return Number.isInteger(seconds) ? String(seconds) : seconds.toFixed(1);
  }

  function readPalette() {
    const styles = getComputedStyle(document.documentElement);
    const read = (name) => styles.getPropertyValue(name).trim();
    return Object.freeze({
      line: read('--graph-line'),
      fill: read('--graph-fill'),
      staleLine: read('--graph-line-stale'),
      staleFill: read('--graph-fill-stale'),
      baseline: read('--graph-baseline'),
    });
  }

  // ── Graph drawing ───────────────────────────────────────────────────────

  /**
   * Coerce a device's `pps` array into a plottable series.
   *
   * The contract fixes the length at `buckets`; whatever arrives is stretched
   * across the full width instead, so an off-length array degrades into a
   * slightly stretched graph rather than a thrown exception. A single sample is
   * doubled so it draws as a flat line rather than a zero-width path.
   */
  function normalizeSeries(values) {
    if (!Array.isArray(values)) return [];
    const series = values.map((value) => Math.max(0, numberOr(value, 0)));
    return series.length === 1 ? [series[0], series[0]] : series;
  }

  function drawGraph(view) {
    const canvas = view.canvas;
    const cssWidth = canvas.clientWidth;
    const cssHeight = canvas.clientHeight;
    /* Before the first layout the canvas has no box; the ResizeObserver
       redraws it as soon as it does. */
    if (cssWidth <= 0 || cssHeight <= 0) return;

    const ratio = window.devicePixelRatio || 1;
    const pixelWidth = Math.max(1, Math.round(cssWidth * ratio));
    const pixelHeight = Math.max(1, Math.round(cssHeight * ratio));
    if (canvas.width !== pixelWidth) canvas.width = pixelWidth;
    if (canvas.height !== pixelHeight) canvas.height = pixelHeight;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    ctx.clearRect(0, 0, cssWidth, cssHeight);
    ctx.lineWidth = GRAPH_LINE_WIDTH_PX;

    /* Half-pixel insets keep the 1px baseline and the end samples crisp. */
    const baselineY = cssHeight - GRAPH_LINE_WIDTH_PX / 2;
    const firstX = GRAPH_LINE_WIDTH_PX / 2;
    const lastX = Math.max(firstX, cssWidth - GRAPH_LINE_WIDTH_PX / 2);

    ctx.strokeStyle = PALETTE.baseline;
    ctx.beginPath();
    ctx.moveTo(0, baselineY);
    ctx.lineTo(cssWidth, baselineY);
    ctx.stroke();

    const series = view.series;
    if (series.length === 0) return;

    const scale = Math.max(view.peakPps, MIN_Y_SCALE_PPS);
    const plotHeight = Math.max(1, cssHeight - GRAPH_TOP_PAD_PX - GRAPH_LINE_WIDTH_PX);
    const stepX = (lastX - firstX) / (series.length - 1);
    const xAt = (index) => firstX + index * stepX;
    const yAt = (value) => baselineY - Math.min(value / scale, 1) * plotHeight;

    ctx.beginPath();
    ctx.moveTo(firstX, baselineY);
    for (let i = 0; i < series.length; i += 1) ctx.lineTo(xAt(i), yAt(series[i]));
    ctx.lineTo(lastX, baselineY);
    ctx.closePath();
    ctx.fillStyle = view.stale ? PALETTE.staleFill : PALETTE.fill;
    ctx.fill();

    ctx.beginPath();
    for (let i = 0; i < series.length; i += 1) {
      const x = xAt(i);
      const y = yAt(series[i]);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = view.stale ? PALETTE.staleLine : PALETTE.line;
    ctx.stroke();
  }

  const resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
      const view = canvasOwners.get(entry.target);
      if (view) drawGraph(view);
    }
  });

  // ── Shared time axis ────────────────────────────────────────────────────

  /**
   * Build the axis once per window duration, derived from the payload's
   * `bucket_ms * buckets` rather than hardcoded.
   */
  function renderAxis(windowMs) {
    if (windowMs === null || windowMs === axisWindowMs) return;
    axisWindowMs = windowMs;
    const windowSeconds = windowMs / MS_PER_SECOND;
    els.axis.replaceChildren(
      ...AXIS_TICK_FRACTIONS.map((fraction) => buildAxisTick(fraction, windowSeconds)),
    );
  }

  function buildAxisTick(fraction, windowSeconds) {
    const tick = document.createElement('span');
    tick.className = 'axis-tick';
    tick.style.left = `${fraction * 100}%`;
    tick.dataset.align = fraction === 0 ? 'start' : fraction === 1 ? 'end' : 'middle';

    const secondsAgo = (1 - fraction) * windowSeconds;
    const label = document.createElement('span');
    label.className = 'axis-tick-label';
    label.textContent = secondsAgo === 0 ? TEXT.axisNow : TEXT.axisSecondsAgo(secondsAgo);

    tick.appendChild(label);
    return tick;
  }

  function readWindowMs(payload) {
    const windowMs = numberOr(payload.bucket_ms, 0) * numberOr(payload.buckets, 0);
    return windowMs > 0 ? windowMs : null;
  }

  // ── Header and capture-status banner ────────────────────────────────────

  function setConnection(state) {
    if (state === connectionState) return;
    connectionState = state;
    els.connection.dataset.state = state;
    els.connectionLabel.textContent = TEXT.connection[state];
  }

  function updateHeader(payload, deviceCount) {
    const hostIp = typeof payload.host_ip === 'string' ? payload.host_ip : '';
    if (hostIp) {
      els.hostIp.textContent = hostIp;
      const octets = hostIp.split('.');
      if (octets.length === IPV4_OCTETS) {
        els.subnet.textContent = TEXT.subnet(octets.slice(0, SUBNET_PREFIX_OCTETS).join('.'));
      }
    }
    els.deviceCount.textContent = TEXT.deviceCount(deviceCount);
  }

  /**
   * Render `capture`: nothing for `ok`, a discreet tag for `mock`, and a
   * warning banner carrying `detail` verbatim for anything else. The failure
   * states are deliberately not enumerated here - an unrecognised state must
   * surface rather than be swallowed. A missing `capture` object is treated as
   * `ok`, since a payload that omits it says nothing to report.
   */
  function renderCaptureStatus(capture) {
    const status = capture && typeof capture === 'object' ? capture : {};
    const state = typeof status.state === 'string' && status.state ? status.state : CAPTURE_STATE_OK;
    const detail = typeof status.detail === 'string' ? status.detail.trim() : '';

    els.mockTag.hidden = state !== CAPTURE_STATE_MOCK;

    const degraded = state !== CAPTURE_STATE_OK && state !== CAPTURE_STATE_MOCK;
    if (degraded) {
      els.banner.textContent = detail || TEXT.captureFallback(state);
    }
    els.banner.hidden = !degraded;
  }

  // ── Row reconciliation ──────────────────────────────────────────────────

  function createRowView(ip) {
    const element = document.createElement('article');
    element.className = 'row grid-row';
    element.dataset.ip = ip;
    element.dataset.stale = 'false';

    const label = document.createElement('div');
    label.className = 'row-label';

    const ipEl = document.createElement('div');
    ipEl.className = 'row-ip';
    ipEl.textContent = ip;

    const stats = document.createElement('div');
    stats.className = 'row-stats';

    const rateEl = document.createElement('span');
    rateEl.className = 'row-rate';

    const peakEl = document.createElement('span');
    peakEl.className = 'row-peak';

    const badgeEl = document.createElement('span');
    badgeEl.className = 'row-badge';
    badgeEl.textContent = TEXT.noTraffic;

    stats.append(rateEl, peakEl, badgeEl);
    label.append(ipEl, stats);

    const graph = document.createElement('div');
    graph.className = 'row-graph';

    const canvas = document.createElement('canvas');
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', TEXT.graphLabel(ip, 0));
    graph.appendChild(canvas);

    element.append(label, graph);

    const view = { ip, element, canvas, rateEl, peakEl, series: [], peakPps: 0, stale: false };
    canvasOwners.set(canvas, view);
    resizeObserver.observe(canvas);
    return view;
  }

  function updateRowView(view, device) {
    const currentPps = numberOr(device.current_pps, 0);
    view.series = normalizeSeries(device.pps);
    view.peakPps = Math.max(0, numberOr(device.peak_pps, 0));
    view.stale = numberOr(device.idle_ms, 0) >= STALE_IDLE_MS;

    view.element.dataset.stale = String(view.stale);
    view.rateEl.textContent = TEXT.rate(currentPps);
    view.peakEl.textContent = TEXT.peak(view.peakPps);
    view.canvas.setAttribute(
      'aria-label',
      view.stale ? TEXT.graphLabelStale(view.ip) : TEXT.graphLabel(view.ip, currentPps),
    );

    drawGraph(view);
  }

  /**
   * Create rows for unseen IPs and update the rest in place, then move any
   * out-of-position element so the DOM matches the payload's numeric IP order.
   * Rows are never removed: the contract keeps a device for the process
   * lifetime, so a quiet device reads as a flatline instead of a vanished row.
   *
   * ponytail: a server restart therefore leaves its old rows on screen until
   * the page is reloaded. Ceiling accepted for Phase 1; the upgrade path is a
   * process-identity field in the payload that the client can compare against.
   */
  function reconcileRows(devices) {
    const orderedIps = [];
    for (const device of devices) {
      if (!device || typeof device.ip !== 'string' || !device.ip) continue;
      let view = rowViews.get(device.ip);
      if (!view) {
        view = createRowView(device.ip);
        rowViews.set(device.ip, view);
        els.rows.appendChild(view.element);
      }
      updateRowView(view, device);
      orderedIps.push(device.ip);
    }

    orderedIps.forEach((ip, index) => {
      const view = rowViews.get(ip);
      const occupant = els.rows.children[index];
      if (occupant !== view.element) els.rows.insertBefore(view.element, occupant || null);
    });

    els.emptyState.hidden = rowViews.size > 0;
    return orderedIps.length;
  }

  // ── Polling ─────────────────────────────────────────────────────────────

  async function fetchRates() {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(RATES_URL, { cache: 'no-store', signal: controller.signal });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.json();
    } finally {
      clearTimeout(timeout);
    }
  }

  function applyPayload(payload) {
    renderCaptureStatus(payload.capture);
    renderAxis(readWindowMs(payload));
    const devices = Array.isArray(payload.devices) ? payload.devices : [];
    const deviceCount = reconcileRows(devices);
    updateHeader(payload, deviceCount);
  }

  async function pollOnce() {
    try {
      const payload = await fetchRates();
      if (!payload || typeof payload !== 'object') throw new Error(TEXT.malformedPayload);
      applyPayload(payload);
      setConnection(CONNECTION_LIVE);
      nextDelayMs = POLL_INTERVAL_MS;
    } catch (error) {
      /* Rows, the axis, and the banner are all left standing: a dropped poll
         means the page is stale, not that the devices went away. */
      if (connectionState !== CONNECTION_DISCONNECTED) {
        console.warn(TEXT.disconnected, error);
      }
      setConnection(CONNECTION_DISCONNECTED);
      nextDelayMs = Math.min(nextDelayMs * BACKOFF_FACTOR, MAX_BACKOFF_MS);
    }
    scheduleNextPoll(nextDelayMs);
  }

  function scheduleNextPoll(delayMs) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(pollOnce, delayMs);
  }

  pollOnce();
})();
