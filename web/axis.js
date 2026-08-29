/*
 * The shared time axis beneath the rows: the one set of labels every trace is
 * read against, laid out for whatever width the panel has.
 */

import { AXIS_TICK_GAP_PX, AXIS_TICK_SETS, MS_PER_SECOND, TEXT } from './constants.js';
import { els } from './elements.js';
import { numberOr } from './format.js';

let axisWindowMs = null;
/** @type {readonly number[]|null} The tick set currently laid out. */
let axisFractions = null;

/**
 * Adopt a window duration, derived from the payload's `bucket_ms * buckets`
 * rather than hardcoded, and lay the axis out for it.
 */
export function renderAxis(windowMs) {
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
export function layOutAxis() {
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

export function readWindowMs(payload) {
  const windowMs = numberOr(payload.bucket_ms, 0) * numberOr(payload.buckets, 0);
  return windowMs > 0 ? windowMs : null;
}
