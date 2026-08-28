/*
 * Polling client for GET /api/rates.
 *
 * The server owns the rolling window, so this page holds no history: every poll
 * carries a complete, bucket-aligned series per device and the page simply
 * redraws it. Rows are reconciled by IP rather than rebuilt, so only the rows
 * that actually appear or leave touch the DOM and the rest never flicker or
 * reorder under the cursor. The watched subnet travels the other way, from the
 * header's field up to the server as `?subnet=`.
 */
(() => {
  'use strict';

  // ── Constants ───────────────────────────────────────────────────────────

  /* Relative so the panel keeps working if it is ever served under a path
     prefix rather than at the site root. */
  const RATES_URL = 'api/rates';

  const POLL_INTERVAL_MS = 500;
  const IMMEDIATE_POLL_MS = 0;
  const MAX_BACKOFF_MS = 2000;
  const BACKOFF_FACTOR = 2;
  const REQUEST_TIMEOUT_MS = 2000;
  const STALE_IDLE_MS = 2000;
  const MS_PER_SECOND = 1000;

  /* A rejected subnet is answered with 400, which means the server is alive and
     disagreeing with the input - not a lost connection. */
  const HTTP_BAD_REQUEST = 400;

  const SUBNET_QUERY_PARAM = 'subnet';
  const SUBNET_STORAGE_KEY = 'netmon.subnet';

  /* Shape check only, used to reject junk read back out of localStorage. The
     server is the authority on what a valid subnet is, and answers anything it
     dislikes with a sentence worth showing. */
  const SUBNET_SHAPE = /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/;

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

  const TEXT = Object.freeze({
    connection: Object.freeze({
      [CONNECTION_CONNECTING]: 'connecting',
      [CONNECTION_LIVE]: 'live',
      [CONNECTION_DISCONNECTED]: 'disconnected',
    }),
    deviceCount: (count) => `${count} ${count === 1 ? 'device' : 'devices'}`,
    rate: (pps) => `${formatRate(pps)} pps`,
    peak: (pps) => `peak ${formatRate(pps)}`,
    noTraffic: 'NO TRAFFIC',
    axisNow: 'now',
    axisSecondsAgo: (seconds) => `-${formatSeconds(seconds)}s`,
    graphLabel: (ip, pps) => `${ip}: ${formatRate(pps)} packets per second`,
    graphLabelStale: (ip) => `${ip}: no traffic`,
    captureFallback: (state) => `Packet capture unavailable (${state}).`,
    subnetRejected: 'The server rejected that subnet.',
    malformedPayload: 'Malformed /api/rates payload',
    disconnected: 'Lost contact with /api/rates; retrying.',
  });

  // ── Elements ────────────────────────────────────────────────────────────

  const els = Object.freeze({
    subnet: document.getElementById('subnet'),
    subnetError: document.getElementById('subnet-error'),
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

  /** Subnet sent as `?subnet=`; `null` leaves the choice to the server. */
  let requestedSubnet = loadStoredSubnet();

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
    if (hostIp) els.hostIp.textContent = hostIp;
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

  // ── Subnet control ──────────────────────────────────────────────────────

  /**
   * Read the last committed subnet back out of storage.
   *
   * Storage can be unavailable altogether inside an iframe, and what it holds
   * is whatever a previous session or another page left there, so anything that
   * is not subnet-shaped is treated as absent: startup falls back to the
   * server's default rather than breaking.
   */
  function loadStoredSubnet() {
    try {
      const stored = window.localStorage.getItem(SUBNET_STORAGE_KEY);
      return typeof stored === 'string' && SUBNET_SHAPE.test(stored) ? stored : null;
    } catch (error) {
      return null;
    }
  }

  /** Persist only plausible values, so a reload never starts in an error state. */
  function storeSubnet(subnet) {
    try {
      if (SUBNET_SHAPE.test(subnet)) window.localStorage.setItem(SUBNET_STORAGE_KEY, subnet);
      else window.localStorage.removeItem(SUBNET_STORAGE_KEY);
    } catch (error) {
      /* Nothing to recover: the subnet still applies for this session. */
    }
  }

  /**
   * Show the field the effective subnet the payload was filtered to, so the
   * header reflects the server's normalized answer rather than what was typed.
   * Skipped while the field has focus, so a poll cannot overwrite an edit in
   * progress.
   */
  function renderSubnet(subnet) {
    if (typeof subnet !== 'string' || !subnet) return;
    if (document.activeElement !== els.subnet) els.subnet.value = subnet;
  }

  function showSubnetError(sentence) {
    els.subnetError.textContent = sentence;
    els.subnetError.hidden = false;
    els.subnet.setAttribute('aria-invalid', 'true');
  }

  function clearSubnetError() {
    if (els.subnetError.hidden) return;
    els.subnetError.textContent = '';
    els.subnetError.hidden = true;
    els.subnet.removeAttribute('aria-invalid');
  }

  /**
   * Adopt the field's value as the subnet sent on subsequent polls. Bound to
   * `change`, which fires on Enter and on a blur that followed an edit - never
   * per keystroke, so a half-typed CIDR is not polled with.
   */
  function commitSubnet() {
    const subnet = els.subnet.value.trim();
    if (subnet === requestedSubnet) return;
    requestedSubnet = subnet;
    storeSubnet(subnet);
    nextDelayMs = POLL_INTERVAL_MS;
    scheduleNextPoll(IMMEDIATE_POLL_MS);
  }

  function initSubnetControl() {
    /* A stored subnet is shown before the first poll answers, so a reload
       inside Cockpit never flashes the default it is not going to use. */
    if (requestedSubnet !== null) els.subnet.value = requestedSubnet;

    els.subnet.addEventListener('change', commitSubnet);
    els.subnet.addEventListener('keydown', (event) => {
      /* Leaving the field on Enter lets the normalized subnet render straight
         back into it, since renderSubnet holds off while it is focused. */
      if (event.key === 'Enter') els.subnet.blur();
    });
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

  /**
   * Every poll redraws, whatever the numbers say. A silent device's window
   * still scrolls, so staleness only dims the row and reveals its badge - it
   * never pauses the drawing that carries the trace along the baseline.
   */
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

  function destroyRowView(view) {
    resizeObserver.unobserve(view.canvas);
    canvasOwners.delete(view.canvas);
    view.element.remove();
  }

  /**
   * Reconcile the grid against `devices` in one pass by IP: create rows for
   * unseen IPs, update the rest in place, drop the ones the payload no longer
   * lists, and move any out-of-position element so the DOM matches the
   * payload's numeric IP order. A device that falls outside the current subnet
   * simply stops being listed and leaves through this same path, taking only
   * its own canvas with it - the surviving rows keep theirs.
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

    const listed = new Set(orderedIps);
    for (const [ip, view] of rowViews) {
      if (listed.has(ip)) continue;
      destroyRowView(view);
      rowViews.delete(ip);
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

  function ratesUrl(subnet) {
    if (subnet === null) return RATES_URL;
    return `${RATES_URL}?${new URLSearchParams({ [SUBNET_QUERY_PARAM]: subnet })}`;
  }

  /** The sentence a 400 carries, falling back if the body is not the error shape. */
  async function readRejection(response) {
    try {
      const body = await response.json();
      const sentence = body && typeof body.error === 'string' ? body.error.trim() : '';
      return sentence || TEXT.subnetRejected;
    } catch (error) {
      return TEXT.subnetRejected;
    }
  }

  /**
   * @returns {Promise<{payload: object}|{rejection: string}>} A rejection is a
   * subnet the server refused; anything else that goes wrong throws.
   */
  async function fetchRates(subnet) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(ratesUrl(subnet), {
        cache: 'no-store',
        signal: controller.signal,
      });
      if (response.status === HTTP_BAD_REQUEST) return { rejection: await readRejection(response) };
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return { payload: await response.json() };
    } finally {
      clearTimeout(timeout);
    }
  }

  function applyPayload(payload) {
    renderCaptureStatus(payload.capture);
    renderSubnet(payload.subnet);
    renderAxis(readWindowMs(payload));
    const devices = Array.isArray(payload.devices) ? payload.devices : [];
    const deviceCount = reconcileRows(devices);
    updateHeader(payload, deviceCount);
  }

  async function pollOnce() {
    const subnet = requestedSubnet;
    try {
      const result = await fetchRates(subnet);
      /* A commit landed mid-flight, so this answer describes the previous
         subnet and the commit has already scheduled the poll that replaces it. */
      if (subnet !== requestedSubnet) return;

      if (result.rejection !== undefined) {
        /* The server is answering, so the connection is healthy and the rows on
           screen stay exactly as they are - only the field is marked wrong. */
        showSubnetError(result.rejection);
      } else {
        const payload = result.payload;
        if (!payload || typeof payload !== 'object') throw new Error(TEXT.malformedPayload);
        clearSubnetError();
        applyPayload(payload);
      }
      setConnection(CONNECTION_LIVE);
      nextDelayMs = POLL_INTERVAL_MS;
    } catch (error) {
      if (subnet !== requestedSubnet) return;
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

  initSubnetControl();
  pollOnce();
})();
