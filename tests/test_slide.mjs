import assert from 'node:assert/strict';
import {
  phaseThroughBucket,
  sizeHeld,
  slideStepRatio,
  timelineAdvanced,
} from '../web/slide.js';

assert.equal(phaseThroughBucket(0, 100, true), 0);
assert.equal(phaseThroughBucket(50, 100, true), 0.5);
assert.equal(phaseThroughBucket(100, 100, false), 1);
assert.equal(phaseThroughBucket(150, 100, false), 1);
assert.equal(phaseThroughBucket(150, 100, true), 0.5);
assert.equal(phaseThroughBucket(0, 0, true), 0);

assert.equal(timelineAdvanced(null, 1000), true);
assert.equal(timelineAdvanced(1000, 1000), false);
assert.equal(timelineAdvanced(1000, 1100), true);
assert.equal(timelineAdvanced(null, null), false);

assert.equal(sizeHeld(100, 100, 1), 100);
assert.equal(sizeHeld(100, 101, 1), 100);
assert.equal(sizeHeld(100, 102, 1), 102);
assert.equal(sizeHeld(0, 50, 1), 50);

assert.equal(slideStepRatio(100), 0.01);
assert.equal(slideStepRatio(0), 0);

console.log('ok');
