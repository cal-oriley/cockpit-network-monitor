/*
 * The canvas traces: the palette they are inked from, the series arithmetic
 * behind them, the drawing itself, the clock that slides a bucket-aligned
 * series between samples, and the observer that keeps both the canvases and
 * the axis correct as the panel is resized.
 */

import {
  GRAPH_LINE_WIDTH_PX,
  GRAPH_TOP_PAD_PX,
  GRAPH_TOTAL_LINE_WIDTH_PX,
  MIN_Y_SCALE_PPS,
} from './constants.js';
import { els } from './elements.js';
import { numberOr } from './format.js';
import { layOutAxis } from './axis.js';

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

/* Canvas colours live in style.css so the palette has a single home. */
const PALETTE = readPalette();

/* Rise with a new peak at once; ease down so a spike leaving the window
   does not yank the whole trace vertically. */
const SCALE_DOWN = 0.04;

/** @type {Set<object>} Views the graph clock paints. */
const liveViews = new Set();

let sampleBucketMs = 0;
let scrollPhase = 0;
let phaseOriginPerf = 0;
let rafId = 0;

/**
 * How far the strip has moved through the current bucket, 0..1.
 *
 * The clock is local. A pending sample is held until this wraps, so the
 * series only shifts when the draw has already slid one full bucket.
 */
export function phaseThroughBucket(elapsedMs, bucketMs, hasPending) {
  if (!(bucketMs > 0) || elapsedMs <= 0) return 0;
  if (elapsedMs >= bucketMs && !hasPending) return 1;
  return (elapsedMs % bucketMs) / bucketMs;
}

/**
 * Queue a series so the clock can swap it at a wrap, or show it at once
 * when the card has nothing to scroll yet.
 */
export function adoptSeries(view, series, peakPps) {
  if (view.series.length === 0) {
    view.series = series;
    view.peakPps = peakPps;
    return;
  }
  view.pendingSeries = series;
  view.pendingPeak = peakPps;
}

export function adoptTimeline(nowMs, bucketMs) {
  sampleBucketMs = numberOr(bucketMs, 0);
  if (phaseOriginPerf === 0) phaseOriginPerf = performance.now();
  ensureAnimating();
}

function hasPending() {
  for (const view of liveViews) {
    if (view.pendingSeries) return true;
  }
  return false;
}

function commitPending() {
  let committed = false;
  for (const view of liveViews) {
    if (!view.pendingSeries) continue;
    view.series = view.pendingSeries;
    view.peakPps = view.pendingPeak;
    view.pendingSeries = null;
    committed = true;
  }
  return committed;
}

function stepClock(now) {
  if (sampleBucketMs <= 0) {
    scrollPhase = 0;
    return;
  }
  if (phaseOriginPerf === 0) phaseOriginPerf = now;
  let elapsed = now - phaseOriginPerf;
  /* One series is queued, the latest. Swap it at a wrap and restart the
     phase so the last frame at 1 and the first frame of the new series at 0
     draw the same pixels. */
  if (elapsed >= sampleBucketMs && commitPending()) {
    phaseOriginPerf = now;
    elapsed = 0;
  }
  scrollPhase = phaseThroughBucket(elapsed, sampleBucketMs, hasPending());
}

function ensureAnimating() {
  if (rafId || liveViews.size === 0) return;
  rafId = requestAnimationFrame(paintGraphs);
}

function paintGraphs(now) {
  if (liveViews.size === 0) {
    rafId = 0;
    return;
  }
  rafId = requestAnimationFrame(paintGraphs);
  stepClock(now);
  for (const view of liveViews) drawGraph(view);
}

/* How a card's trace is inked. The total gets its own accent and a heavier
   line so a glance never mistakes it for one more device. */
export const GRAPH_STYLE_DEVICE = Object.freeze({
  line: PALETTE.line,
  fill: PALETTE.fill,
  lineWidth: GRAPH_LINE_WIDTH_PX,
});
export const GRAPH_STYLE_TOTAL = Object.freeze({
  line: PALETTE.totalLine,
  fill: PALETTE.totalFill,
  lineWidth: GRAPH_TOTAL_LINE_WIDTH_PX,
});

/** @type {WeakMap<Element, object>} Canvas to its card view, for resize redraws. */
const canvasOwners = new WeakMap();

/**
 * Coerce a device's `pps` array into a plottable series.
 *
 * The contract fixes the length at `buckets`; whatever arrives is stretched
 * across the full width instead, so an off-length array degrades into a
 * slightly stretched graph rather than a thrown exception. A single sample is
 * doubled so it draws as a flat line rather than a zero-width path.
 */
export function normalizeSeries(values) {
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
export function sumSeries(devices) {
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

export function drawGraph(view) {
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

  const targetScale = Math.max(view.peakPps, MIN_Y_SCALE_PPS);
  if (view.displayPeak === undefined || targetScale > view.displayPeak) {
    view.displayPeak = targetScale;
  } else {
    view.displayPeak += (targetScale - view.displayPeak) * SCALE_DOWN;
  }
  const scale = Math.max(view.displayPeak, MIN_Y_SCALE_PPS);
  const plotHeight = Math.max(1, cssHeight - GRAPH_TOP_PAD_PX - GRAPH_LINE_WIDTH_PX);
  const stepX = (lastX - firstX) / (series.length - 1);
  const xAt = (index) => firstX + (index - scrollPhase) * stepX;
  const yAt = (value) => baselineY - Math.min(value / scale, 1) * plotHeight;
  const lastY = yAt(series[series.length - 1]);

  ctx.beginPath();
  ctx.moveTo(xAt(0), baselineY);
  for (let i = 0; i < series.length; i += 1) ctx.lineTo(xAt(i), yAt(series[i]));
  ctx.lineTo(lastX, lastY);
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
  if (xAt(series.length - 1) < lastX) ctx.lineTo(lastX, lastY);
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

export function observeCanvas(view) {
  canvasOwners.set(view.canvas, view);
  liveViews.add(view);
  resizeObserver.observe(view.canvas);
  ensureAnimating();
}

export function unobserveCanvas(view) {
  resizeObserver.unobserve(view.canvas);
  canvasOwners.delete(view.canvas);
  liveViews.delete(view);
}
