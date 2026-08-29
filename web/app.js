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

import {
  BACKOFF_FACTOR,
  CONNECTION_DISCONNECTED,
  CONNECTION_LIVE,
  IMMEDIATE_POLL_MS,
  MAX_BACKOFF_MS,
  POLL_INTERVAL_MS,
  TEXT,
} from './constants.js';
import { fetchRates } from './api.js';
import { readWindowMs, renderAxis } from './axis.js';
import {
  acceptSubnet,
  clearSubnetError,
  getConnectionState,
  getRequestedSubnet,
  initSubnetControl,
  renderCaptureStatus,
  setConnection,
  showSubnetError,
  updateHeader,
} from './header.js';
import { applyRecordingStatus, initRecordControl } from './record.js';
import { reconcileRows } from './rows.js';

let nextDelayMs = POLL_INTERVAL_MS;
let pollTimer = null;

function applyPayload(payload) {
  renderCaptureStatus(payload.capture);
  acceptSubnet(payload.subnet);
  /* After acceptSubnet, so the subnet a recording is compared against is the
     one this payload was filtered to rather than the previous poll's. */
  applyRecordingStatus(payload.recording);
  renderAxis(readWindowMs(payload));
  /* An empty list is a real answer - nothing has been seen yet, or nothing in
     this subnet - and empties the grid accordingly. A `devices` that is
     missing or not a list is instead a payload this page cannot read, so the
     last good rows stay up, exactly as they do when a subnet is rejected. */
  if (!Array.isArray(payload.devices)) return;
  updateHeader(payload, reconcileRows(payload.devices));
}

async function pollOnce() {
  const subnet = getRequestedSubnet();
  try {
    const result = await fetchRates(subnet);
    /* A commit landed mid-flight, so this answer describes the previous
       subnet and the commit has already scheduled the poll that replaces it. */
    if (subnet !== getRequestedSubnet()) return;

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
    if (subnet !== getRequestedSubnet()) return;
    /* Rows, the axis, and the banner are all left standing: a dropped poll
       means the page is stale, not that the devices went away. */
    if (getConnectionState() !== CONNECTION_DISCONNECTED) {
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

initSubnetControl(() => {
  nextDelayMs = POLL_INTERVAL_MS;
  scheduleNextPoll(IMMEDIATE_POLL_MS);
});
initRecordControl();
pollOnce();
