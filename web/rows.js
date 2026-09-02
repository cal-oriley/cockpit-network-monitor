/*
 * The grid of cards: one per device, headed by the combined trace. Rows are
 * reconciled by IP rather than rebuilt, so only the rows that actually appear
 * or leave touch the DOM and the rest never flicker or reorder under the
 * cursor.
 */

import { STALE_IDLE_MS, TEXT } from './constants.js';
import { els } from './elements.js';
import { numberOr } from './format.js';
import {
  GRAPH_STYLE_DEVICE,
  GRAPH_STYLE_TOTAL,
  adoptSeries,
  normalizeSeries,
  observeCanvas,
  sumSeries,
  unobserveCanvas,
} from './graph.js';

/** @type {Map<string, object>} IP to row view, in creation order. */
const rowViews = new Map();

/** @type {object|null} The combined-traffic card, present only while rows are. */
let totalView = null;

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
  observeCanvas(view);
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
 * Every poll updates the series; the graph clock paints it. A silent
 * device's window still scrolls, so staleness only dims the row and reveals
 * its badge - it never pauses the drawing that carries the trace along the
 * baseline.
 */
function updateRowView(view, device) {
  const currentPps = numberOr(device.current_pps, 0);
  adoptSeries(
    view,
    normalizeSeries(device.pps),
    Math.max(0, numberOr(device.peak_pps, 0)),
  );
  view.stale = numberOr(device.idle_ms, 0) >= STALE_IDLE_MS;

  view.element.dataset.stale = String(view.stale);
  view.rateEl.textContent = TEXT.rate(currentPps);
  view.peakEl.textContent = TEXT.peak(view.peakPps);
  view.canvas.setAttribute(
    'aria-label',
    view.stale ? TEXT.graphLabelStale(view.ip) : TEXT.graphLabel(view.ip, currentPps),
  );
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
  const series = normalizeSeries(sumSeries(devices));
  adoptSeries(
    view,
    series,
    series.reduce((peak, value) => Math.max(peak, value), 0),
  );

  view.rateEl.textContent = TEXT.rate(currentPps);
  view.peakEl.textContent = TEXT.peak(view.peakPps);
  view.canvas.setAttribute('aria-label', TEXT.totalGraphLabel(currentPps));
}

function destroyCardView(view) {
  unobserveCanvas(view);
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
export function reconcileRows(devices) {
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
