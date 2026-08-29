/*
 * Polling client for GET /api/rates.
 *
 * The server owns the rolling window, so this page holds no history: every poll
 * carries a complete, bucket-aligned series per device and the page simply
 * redraws it. Rows are reconciled by IP rather than rebuilt, so only the rows
 * that actually appear or leave touch the DOM and the rest never flicker or
 * reorder under the cursor. Heading them is the combined trace, summed here
 * across whichever devices the payload listed.
 *
 * Two things travel the other way, from the header up to the server: the
 * watched subnet as `?subnet=`, and the record button as `POST /api/record`.
 * Recording is the server's own business, so the button sends an action and
 * then renders whatever the next poll says is happening rather than what it
 * asked for.
 */
(() => {
  'use strict';

  // ── Constants ───────────────────────────────────────────────────────────

  /* Relative so the panel keeps working if it is ever served under a path
     prefix rather than at the site root. */
  const RATES_URL = 'api/rates';
  const RECORD_URL = 'api/record';

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

  /* A start that lost the race to another tab. The response carries the
     recording that won, so it is a state to adopt rather than a failure. */
  const HTTP_CONFLICT = 409;

  const JSON_CONTENT_TYPE = 'application/json';
  const RECORD_ACTION_START = 'start';
  const RECORD_ACTION_STOP = 'stop';

  /* What the page holds before the first poll answers. The idle contract
     reports nulls beside a zero row count; these are the same absences in the
     types the page renders. */
  const RECORDING_IDLE = Object.freeze({
    active: false,
    file: '',
    subnet: '',
    rows: 0,
    detail: '',
  });

  /* Both, because the server reports a native absolute path. */
  const PATH_SEPARATORS = /[\\/]/;

  const SUBNET_QUERY_PARAM = 'subnet';
  const SUBNET_STORAGE_KEY = 'netmon.subnet';

  /* Comfortably past the longest real CIDR - a full IPv6 address plus its
     prefix - so only obvious junk read back out of storage is turned away. */
  const MAX_SUBNET_CHARS = 64;

  /* capture.state values this page reacts to. Every other value - including
     ones a later phase invents - falls through to the warning banner, which is
     the entire reason the field carries a human-readable detail string. */
  const CAPTURE_STATE_OK = 'ok';
  const CAPTURE_STATE_MOCK = 'mock';

  const CONNECTION_CONNECTING = 'connecting';
  const CONNECTION_LIVE = 'live';
  const CONNECTION_DISCONNECTED = 'disconnected';

  /* Axis ticks as fractions across the graph column, widest set first: oldest,
     midpoint, now. Each set keeps `now`, so the label that survives thinning is
     the one every trace is read from. */
  const AXIS_TICK_SETS = Object.freeze([
    Object.freeze([0, 0.5, 1]),
    Object.freeze([0, 1]),
    Object.freeze([1]),
  ]);

  /* Clear space wanted between neighbouring axis labels before they read as
     one run of characters. */
  const AXIS_TICK_GAP_PX = 8;

  const GRAPH_TOP_PAD_PX = 4;
  const GRAPH_LINE_WIDTH_PX = 1;
  const GRAPH_TOTAL_LINE_WIDTH_PX = 2;
  const MIN_Y_SCALE_PPS = 1;

  const TEXT = Object.freeze({
    connection: Object.freeze({
      [CONNECTION_CONNECTING]: 'connecting',
      [CONNECTION_LIVE]: 'live',
      [CONNECTION_DISCONNECTED]: 'disconnected',
    }),
    record: Object.freeze({
      idle: 'Record',
      active: 'Stop recording',
      live: 'recording',
      stopped: 'stopped',
      rows: (rows) => `${rows} ${rows === 1 ? 'row' : 'rows'}`,
      rowsWritten: (rows) => `wrote ${rows} ${rows === 1 ? 'row' : 'rows'}`,
      mismatch: (subnet) => `Recording ${subnet}, not the subnet shown here.`,
      refused: 'The server refused that recording request.',
      unreachable: 'Could not reach the server to change recording.',
    }),
    deviceCount: (count) => `${count} ${count === 1 ? 'device' : 'devices'}`,
    rate: (pps) => `${formatRate(pps)} pps`,
    peak: (pps) => `peak ${formatRate(pps)}`,
    noTraffic: 'NO TRAFFIC',
    axisNow: 'now',
    axisSecondsAgo: (seconds) => `-${formatSeconds(seconds)}s`,
    graphLabel: (ip, pps) => `${ip}: ${formatRate(pps)} packets per second`,
    graphLabelStale: (ip) => `${ip}: no traffic`,
    totalName: 'All devices',
    totalGraphLabel: (pps) =>
      `All devices combined: ${formatRate(pps)} packets per second`,
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
    record: document.getElementById('record'),
    recordLabel: document.getElementById('record-label'),
    recordStatus: document.getElementById('record-status'),
    recordState: document.getElementById('record-state'),
    recordFile: document.getElementById('record-file'),
    recordRows: document.getElementById('record-rows'),
    recordNote: document.getElementById('record-note'),
    banner: document.getElementById('banner'),
    emptyState: document.getElementById('empty-state'),
    rows: document.getElementById('rows'),
    axis: document.getElementById('axis'),
  });

  /* Canvas colours live in style.css so the palette has a single home. */
  const PALETTE = readPalette();

  /* How a card's trace is inked. The total gets its own accent and a heavier
     line so a glance never mistakes it for one more device. */
  const GRAPH_STYLE_DEVICE = Object.freeze({
    line: PALETTE.line,
    fill: PALETTE.fill,
    lineWidth: GRAPH_LINE_WIDTH_PX,
  });
  const GRAPH_STYLE_TOTAL = Object.freeze({
    line: PALETTE.totalLine,
    fill: PALETTE.totalFill,
    lineWidth: GRAPH_TOTAL_LINE_WIDTH_PX,
  });

  // ── State ───────────────────────────────────────────────────────────────

  /** @type {Map<string, object>} IP to row view, in creation order. */
  const rowViews = new Map();
  /** @type {WeakMap<Element, object>} Canvas to its card view, for resize redraws. */
  const canvasOwners = new WeakMap();

  /** @type {object|null} The combined-traffic card, present only while rows are. */
  let totalView = null;

  let axisWindowMs = null;
  /** @type {readonly number[]|null} The tick set currently laid out. */
  let axisFractions = null;
  let connectionState = CONNECTION_CONNECTING;
  let nextDelayMs = POLL_INTERVAL_MS;
  let pollTimer = null;

  /** Subnet sent as `?subnet=`; `null` leaves the choice to the server. */
  let requestedSubnet = loadStoredSubnet();

  /** Subnet the last readable payload was filtered to, so a recording of some
      other subnet can be spotted and said out loud. */
  let viewedSubnet = null;

  /** The server's own account of what it is recording - never a local guess. */
  let recordingState = RECORDING_IDLE;
  /** The recording a stop just finished, whose tally only that response carries;
      held until the next attempt, since the poll after it is rightly idle. */
  let stoppedRecording = null;
  /** A start or stop in flight, which disables the button so a double-click
      cannot fire two starts. */
  let recordRequestInFlight = false;
  /** Sentence from a refused start or stop, held until the next attempt. */
  let recordError = '';

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

  /**
   * The name at the end of a path.
   *
   * Recordings are reported by absolute path, since where they land must not
   * depend on anyone's working directory, but only the name is shown: a full
   * path is far wider than the panel this page has to survive being squeezed
   * into, and the directory is the same for every recording anyway.
   */
  function fileName(path) {
    const parts = String(path).split(PATH_SEPARATORS);
    return parts[parts.length - 1];
  }

  function readPalette() {
    const styles = getComputedStyle(document.documentElement);
    const read = (name) => styles.getPropertyValue(name).trim();
    return Object.freeze({
      line: read('--graph-line'),
      fill: read('--graph-fill'),
      totalLine: read('--graph-line-total'),
      totalFill: read('--graph-fill-total'),
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

  /**
   * Element-wise sum of the devices' `pps` arrays.
   *
   * Every array is the same fixed length and covers the same intervals, which
   * is exactly what makes adding them position by position mean anything. A
   * device carrying no array at all is skipped, and a short one is aligned to
   * the newest end rather than the oldest, so an off-length array costs the
   * oldest buckets instead of sliding that device's history sideways.
   */
  function sumSeries(devices) {
    const arrays = [];
    for (const device of devices) {
      const values = device.pps;
      if (Array.isArray(values) && values.length > 0) arrays.push(values);
    }
    if (arrays.length === 0) return [];

    const length = arrays.reduce((widest, values) => Math.max(widest, values.length), 0);
    const totals = new Array(length).fill(0);
    for (const values of arrays) {
      const offset = length - values.length;
      for (let i = 0; i < values.length; i += 1) {
        totals[offset + i] += Math.max(0, numberOr(values[i], 0));
      }
    }
    return totals;
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
    ctx.fillStyle = view.stale ? PALETTE.staleFill : view.style.fill;
    ctx.fill();

    ctx.beginPath();
    for (let i = 0; i < series.length; i += 1) {
      const x = xAt(i);
      const y = yAt(series[i]);
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.lineWidth = view.style.lineWidth;
    ctx.strokeStyle = view.stale ? PALETTE.staleLine : view.style.line;
    ctx.stroke();
  }

  /**
   * Redraw whatever changed size. The canvases need it because their backing
   * store is sized in device pixels; the axis needs it because how many labels
   * fit is a question about width, and the two share an observer so a resize
   * moves the traces and the times they are read against together.
   */
  const resizeObserver = new ResizeObserver((entries) => {
    for (const entry of entries) {
      if (entry.target === els.axis) {
        layOutAxis();
        continue;
      }
      const view = canvasOwners.get(entry.target);
      if (view) drawGraph(view);
    }
  });

  resizeObserver.observe(els.axis);

  // ── Shared time axis ────────────────────────────────────────────────────

  /**
   * Adopt a window duration, derived from the payload's `bucket_ms * buckets`
   * rather than hardcoded, and lay the axis out for it.
   */
  function renderAxis(windowMs) {
    if (windowMs === null || windowMs === axisWindowMs) return;
    axisWindowMs = windowMs;
    axisFractions = null;
    layOutAxis();
  }

  /**
   * Lay out as many ticks as the graph column has room for.
   *
   * How wide a label is comes from measuring one rather than from assumptions
   * about the font: the labels are monospace, so one rendered label gives a
   * character width, and the widest label the window will produce is the oldest
   * one. That keeps the threshold correct as the type scales with the panel,
   * with nothing about the stylesheet's own sizes restated here.
   */
  function layOutAxis() {
    if (axisWindowMs === null) return;
    const windowSeconds = axisWindowMs / MS_PER_SECOND;
    if (axisFractions === null) renderAxisTicks(AXIS_TICK_SETS[0], windowSeconds);

    const charWidth = measureAxisCharWidth();
    const available = els.axis.clientWidth;
    /* No box yet, or no label to measure: the ResizeObserver runs this again as
       soon as there is one. */
    if (charWidth <= 0 || available <= 0) return;

    const perTick = TEXT.axisSecondsAgo(windowSeconds).length * charWidth + AXIS_TICK_GAP_PX;
    const fits = Math.max(1, Math.floor(available / perTick));
    const chosen = AXIS_TICK_SETS.find((set) => set.length <= fits) ?? AXIS_TICK_SETS.at(-1);
    if (chosen !== axisFractions) renderAxisTicks(chosen, windowSeconds);
  }

  function renderAxisTicks(fractions, windowSeconds) {
    axisFractions = fractions;
    els.axis.replaceChildren(
      ...fractions.map((fraction) => buildAxisTick(fraction, windowSeconds)),
    );
  }

  /** Width of one monospace character in a rendered tick label. */
  function measureAxisCharWidth() {
    const label = els.axis.querySelector('.axis-tick-label');
    const characters = label === null ? 0 : label.textContent.length;
    return characters > 0 ? label.offsetWidth / characters : 0;
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
   * Read the last accepted subnet back out of storage.
   *
   * Storage can be unavailable altogether inside an iframe, and what it holds
   * is whatever a previous session or another page left there, so only a
   * non-empty string of sensible length is taken at all. Whether it still names
   * a usable subnet is the server's call, answered with a sentence worth
   * showing beside the field.
   */
  function loadStoredSubnet() {
    try {
      const stored = window.localStorage.getItem(SUBNET_STORAGE_KEY);
      if (typeof stored !== 'string') return null;
      const subnet = stored.trim();
      return subnet && subnet.length <= MAX_SUBNET_CHARS ? subnet : null;
    } catch (error) {
      return null;
    }
  }

  /** Remember a subnet across page loads; storage may not be available at all. */
  function storeSubnet(subnet) {
    try {
      /* Read before writing: every poll confirms the same subnet, and there is
         no reason to hand storage a value it already holds. */
      if (window.localStorage.getItem(SUBNET_STORAGE_KEY) === subnet) return;
      window.localStorage.setItem(SUBNET_STORAGE_KEY, subnet);
    } catch (error) {
      /* Nothing to recover: the subnet still applies for this session. */
    }
  }

  /**
   * Accept the effective subnet the payload was filtered to: show it in the
   * field, ask for it by name from here on, and remember it for the next load.
   * The server normalized it while answering a request it accepted, so it is
   * both canonical and known-good - a reload cannot come back up in an error
   * state, and a value the server merely reformatted is still kept.
   *
   * The field is left alone while it has focus, so a poll cannot overwrite an
   * edit in progress, and the server's own default is shown but never stored,
   * so changing that default still reaches a returning page.
   */
  function acceptSubnet(subnet) {
    if (typeof subnet !== 'string' || !subnet) return;
    viewedSubnet = subnet;
    if (document.activeElement !== els.subnet) els.subnet.value = subnet;
    if (requestedSubnet === null) return;
    requestedSubnet = subnet;
    storeSubnet(subnet);
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
         back into it, since acceptSubnet holds off while it is focused. */
      if (event.key === 'Enter') els.subnet.blur();
    });
  }

  // ── Record control ──────────────────────────────────────────────────────

  /*
   * Recording happens on the server, so the button is only a control: every
   * poll re-reads what the server says it is doing and the page renders that.
   * Nothing here remembers having pressed the button, which is what makes a
   * reload, a second tab, and a recording someone else started all read
   * correctly - and what makes a 409 nothing to argue with.
   */

  /**
   * Read the contract's `recording` object into the shapes the page renders.
   *
   * A payload with no `recording` at all - which is what a server too old to
   * record looks like - reads as not recording, exactly as a missing `capture`
   * reads as `ok`. An idle status is read out in full rather than discarded,
   * because a recording that ended in failure keeps its reason there.
   */
  function normalizeRecording(recording) {
    const status = recording && typeof recording === 'object' ? recording : {};
    return {
      active: status.active === true,
      file: typeof status.file === 'string' ? status.file : '',
      subnet: typeof status.subnet === 'string' ? status.subnet : '',
      rows: Math.max(0, Math.round(numberOr(status.rows, 0))),
      detail: typeof status.detail === 'string' ? status.detail.trim() : '',
    };
  }

  /** Write a span's text, hiding it when empty so its gap in the row goes too. */
  function setStatusText(element, text) {
    if (element.textContent !== text) element.textContent = text;
    element.hidden = text === '';
  }

  /**
   * Render the button and the strip beneath the header.
   *
   * The strip carries the file and the row count, which is the cheapest proof a
   * recording is working, and a note for the things worth saying out loud: a
   * recording fixed to a subnet other than the one on screen, whatever `detail`
   * the server reports verbatim, and a request the server refused.
   *
   * A running recording is described by the poll. A finished one is described
   * by the stop response that reported it, because the poll half a second
   * later is legitimately idle with nothing left to count - reading the tally
   * from there would show zero every time.
   */
  function renderRecording() {
    const active = recordingState.active;
    els.recordLabel.textContent = active ? TEXT.record.active : TEXT.record.idle;
    els.record.setAttribute('aria-pressed', String(active));
    els.record.disabled = recordRequestInFlight;

    const reported = active ? recordingState : stoppedRecording;
    const rows = reported === null
      ? ''
      : active
        ? TEXT.record.rows(reported.rows)
        : TEXT.record.rowsWritten(reported.rows);

    const notes = [];
    if (active && recordingState.subnet && viewedSubnet
        && recordingState.subnet !== viewedSubnet) {
      notes.push(TEXT.record.mismatch(recordingState.subnet));
    }
    /* Shown when idle too: a recording that stopped because something went
       wrong keeps its reason, and that is the moment it must not vanish. */
    if (recordingState.detail) notes.push(recordingState.detail);
    if (recordError) notes.push(recordError);
    const note = notes.join(' ');

    els.recordStatus.dataset.active = String(active);
    setStatusText(
      els.recordState,
      active ? TEXT.record.live : reported === null ? '' : TEXT.record.stopped,
    );
    setStatusText(els.recordFile, reported === null ? '' : fileName(reported.file));
    els.recordFile.title = reported === null ? '' : reported.file;
    setStatusText(els.recordRows, rows);
    setStatusText(els.recordNote, note);
    els.recordStatus.hidden = reported === null && note === '';
  }

  /**
   * @returns {Promise<{recording: object}|{error: string}>} A 409 is read as a
   * recording rather than an error, since its body is the recording that won
   * the race. Anything else the server refuses arrives as a sentence.
   */
  async function postRecord(body) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
      const response = await fetch(RECORD_URL, {
        method: 'POST',
        cache: 'no-store',
        headers: { 'Content-Type': JSON_CONTENT_TYPE },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!response.ok && response.status !== HTTP_CONFLICT) {
        return { error: await readErrorSentence(response, TEXT.record.refused) };
      }
      return { recording: normalizeRecording(await response.json()) };
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Start or stop recording, whichever the last reported state calls for, and
   * adopt whatever the server reports back.
   *
   * A start is fixed to the subnet being asked for, which is the one on screen:
   * clicking the button blurs the subnet field first, so an edit not yet
   * committed has already been by the time this reads it.
   */
  async function toggleRecording() {
    if (recordRequestInFlight) return;
    const body = recordingState.active
      ? { action: RECORD_ACTION_STOP }
      : {
          action: RECORD_ACTION_START,
          subnet: requestedSubnet !== null ? requestedSubnet : viewedSubnet,
        };

    recordRequestInFlight = true;
    recordError = '';
    stoppedRecording = null;
    renderRecording();
    try {
      const result = await postRecord(body);
      if (result.error !== undefined) {
        recordError = result.error;
      } else {
        recordingState = result.recording;
        /* A 409 answers with the recording that won the race, so only a state
           that really is finished is kept as one to report on. */
        if (!recordingState.active) stoppedRecording = recordingState;
      }
    } catch (error) {
      /* The poll reports the same server, so its own connection state already
         says whether this is a blip or a server that has gone away. */
      recordError = TEXT.record.unreachable;
      console.warn(TEXT.record.unreachable, error);
    } finally {
      recordRequestInFlight = false;
      renderRecording();
    }
  }

  function initRecordControl() {
    els.record.addEventListener('click', toggleRecording);
    renderRecording();
  }

  // ── Row reconciliation ──────────────────────────────────────────────────

  /**
   * Build the card every graph shares: a label column carrying a name, the
   * current rate and the window's peak, beside a canvas on the grid's graph
   * column. The caller names it and adds whatever else it carries.
   */
  function createCardView(style) {
    const element = document.createElement('article');
    element.className = 'row grid-row';
    element.dataset.stale = 'false';

    const label = document.createElement('div');
    label.className = 'row-label';

    const nameEl = document.createElement('div');
    nameEl.className = 'row-name';

    const stats = document.createElement('div');
    stats.className = 'row-stats';

    const rateEl = document.createElement('span');
    rateEl.className = 'row-rate';

    const peakEl = document.createElement('span');
    peakEl.className = 'row-peak';

    stats.append(rateEl, peakEl);
    label.append(nameEl, stats);

    const graph = document.createElement('div');
    graph.className = 'row-graph';

    const canvas = document.createElement('canvas');
    canvas.setAttribute('role', 'img');
    graph.appendChild(canvas);

    element.append(label, graph);

    const view = {
      element,
      canvas,
      nameEl,
      stats,
      rateEl,
      peakEl,
      style,
      series: [],
      peakPps: 0,
      stale: false,
    };
    canvasOwners.set(canvas, view);
    resizeObserver.observe(canvas);
    return view;
  }

  function createRowView(ip) {
    const view = createCardView(GRAPH_STYLE_DEVICE);
    view.ip = ip;
    view.element.dataset.ip = ip;
    view.nameEl.textContent = ip;
    view.canvas.setAttribute('aria-label', TEXT.graphLabel(ip, 0));

    const badgeEl = document.createElement('span');
    badgeEl.className = 'row-badge';
    badgeEl.textContent = TEXT.noTraffic;
    view.stats.appendChild(badgeEl);

    return view;
  }

  /** Named rather than addressed, so it cannot be read as a device that exists. */
  function createTotalView() {
    const view = createCardView(GRAPH_STYLE_TOTAL);
    view.element.classList.add('row-total');
    view.nameEl.textContent = TEXT.totalName;
    view.canvas.setAttribute('aria-label', TEXT.totalGraphLabel(0));
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

  /**
   * Redraw the total from the devices the payload actually listed, so the sum
   * covers the subnet in view rather than traffic filtered out of it, and
   * autoscale it to its own peak like every other card.
   *
   * `idle_ms` is per device and has no aggregate, so this card never goes
   * stale: everything falling quiet is already said by a trace scrolling flat
   * along the baseline, which it keeps doing because this runs every poll.
   */
  function updateTotalView(view, devices) {
    const currentPps = devices.reduce(
      (total, device) => total + Math.max(0, numberOr(device.current_pps, 0)),
      0,
    );
    view.series = normalizeSeries(sumSeries(devices));
    view.peakPps = view.series.reduce((peak, value) => Math.max(peak, value), 0);

    view.rateEl.textContent = TEXT.rate(currentPps);
    view.peakEl.textContent = TEXT.peak(view.peakPps);
    view.canvas.setAttribute('aria-label', TEXT.totalGraphLabel(currentPps));

    drawGraph(view);
  }

  function destroyCardView(view) {
    resizeObserver.unobserve(view.canvas);
    canvasOwners.delete(view.canvas);
    view.element.remove();
  }

  /**
   * Keep the total at the head of the grid for as long as anything is listed.
   * Summing an empty list is not zero traffic but no data, which the waiting
   * state already says, so the card leaves with the last row.
   */
  function reconcileTotal(devices) {
    if (devices.length === 0) {
      if (totalView !== null) {
        destroyCardView(totalView);
        totalView = null;
      }
      return;
    }
    if (totalView === null) {
      totalView = createTotalView();
      els.rows.prepend(totalView.element);
    }
    updateTotalView(totalView, devices);
  }

  /**
   * Reconcile the grid against `devices` in one pass by IP: create rows for
   * unseen IPs, update the rest in place, drop the ones the payload no longer
   * lists, and move any out-of-position element so the DOM matches the
   * payload's numeric IP order. A device that falls outside the current subnet
   * simply stops being listed and leaves through this same path, taking only
   * its own canvas with it - the surviving rows keep theirs.
   *
   * The listed devices are also what the total is summed over, so it follows
   * the same subnet the rows do, and the count returned for the header stays a
   * count of devices.
   */
  function reconcileRows(devices) {
    const listed = [];
    for (const device of devices) {
      if (!device || typeof device.ip !== 'string' || !device.ip) continue;
      let view = rowViews.get(device.ip);
      if (!view) {
        view = createRowView(device.ip);
        rowViews.set(device.ip, view);
        els.rows.appendChild(view.element);
      }
      updateRowView(view, device);
      listed.push(device);
    }

    const listedIps = new Set(listed.map((device) => device.ip));
    for (const [ip, view] of rowViews) {
      if (listedIps.has(ip)) continue;
      destroyCardView(view);
      rowViews.delete(ip);
    }

    reconcileTotal(listed);

    /* The total holds the grid's first slot while it is shown, so the device
       rows begin one position further in. */
    const firstRowIndex = totalView === null ? 0 : 1;
    listed.forEach((device, index) => {
      const view = rowViews.get(device.ip);
      const occupant = els.rows.children[firstRowIndex + index];
      if (occupant !== view.element) els.rows.insertBefore(view.element, occupant || null);
    });

    els.emptyState.hidden = rowViews.size > 0;
    return listed.length;
  }

  // ── Polling ─────────────────────────────────────────────────────────────

  function ratesUrl(subnet) {
    if (subnet === null) return RATES_URL;
    return `${RATES_URL}?${new URLSearchParams({ [SUBNET_QUERY_PARAM]: subnet })}`;
  }

  /**
   * The sentence a refusal carries, falling back if the body is not the
   * `{error}` shape both endpoints answer with.
   */
  async function readErrorSentence(response, fallback) {
    try {
      const body = await response.json();
      const sentence = body && typeof body.error === 'string' ? body.error.trim() : '';
      return sentence || fallback;
    } catch (error) {
      return fallback;
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
      if (response.status === HTTP_BAD_REQUEST) {
        return { rejection: await readErrorSentence(response, TEXT.subnetRejected) };
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return { payload: await response.json() };
    } finally {
      clearTimeout(timeout);
    }
  }

  function applyPayload(payload) {
    renderCaptureStatus(payload.capture);
    acceptSubnet(payload.subnet);
    /* After acceptSubnet, so the subnet a recording is compared against is the
       one this payload was filtered to rather than the previous poll's. */
    recordingState = normalizeRecording(payload.recording);
    renderRecording();
    renderAxis(readWindowMs(payload));
    /* An empty list is a real answer - nothing has been seen yet, or nothing in
       this subnet - and empties the grid accordingly. A `devices` that is
       missing or not a list is instead a payload this page cannot read, so the
       last good rows stay up, exactly as they do when a subnet is rejected. */
    if (!Array.isArray(payload.devices)) return;
    updateHeader(payload, reconcileRows(payload.devices));
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
  initRecordControl();
  pollOnce();
})();
