/*
 * Sub-bucket scroll clock. Pure, so the canvas clock and its check share
 * one wrap rule: the strip only advances when a new bucket is in hand.
 */

export function timelineAdvanced(paintedNowMs, latestNowMs) {
  return latestNowMs !== null && latestNowMs !== paintedNowMs;
}

/**
 * How far the strip has moved through the current bucket, 0..1.
 *
 * The clock is local. Without a new bucket the phase pins at 1 rather than
 * wrapping onto the same series, which would snap the trace backward.
 */
export function phaseThroughBucket(elapsedMs, bucketMs, hasNewBucket) {
  if (!(bucketMs > 0) || elapsedMs <= 0) return 0;
  if (elapsedMs >= bucketMs && !hasNewBucket) return 1;
  return (elapsedMs % bucketMs) / bucketMs;
}

/** Keep a size that only moved by `holdPx` so a flex jitter is not a resize. */
export function sizeHeld(current, next, holdPx) {
  if (current === 0) return next;
  return Math.abs(next - current) <= holdPx ? current : next;
}

/**
 * One sample as a fraction of the slide strip. The wrapper is one step
 * wider than the clip, so translating by this amount walks exactly one
 * bucket without needing a pixel width from layout.
 */
export function slideStepRatio(sampleCount) {
  return sampleCount > 0 ? 1 / sampleCount : 0;
}
