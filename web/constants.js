/*
 * The page's fixed vocabulary: the endpoints it talks to, the timings and
 * geometry it works in, the contract values it recognises, and every string it
 * puts on screen.
 */

import { formatRate, formatSeconds } from './format.js';

/* Relative so the panel keeps working if it is ever served under a path
   prefix rather than at the site root. */
export const RATES_URL = 'api/rates';
export const RECORD_URL = 'api/record';

export const POLL_INTERVAL_MS = 500;
export const IMMEDIATE_POLL_MS = 0;
export const MAX_BACKOFF_MS = 2000;
export const BACKOFF_FACTOR = 2;
export const REQUEST_TIMEOUT_MS = 2000;
export const STALE_IDLE_MS = 2000;
export const MS_PER_SECOND = 1000;

/* A rejected subnet is answered with 400, which means the server is alive and
   disagreeing with the input - not a lost connection. */
export const HTTP_BAD_REQUEST = 400;

/* A start that lost the race to another tab. The response carries the
   recording that won, so it is a state to adopt rather than a failure. */
export const HTTP_CONFLICT = 409;

export const JSON_CONTENT_TYPE = 'application/json';
export const RECORD_ACTION_START = 'start';
export const RECORD_ACTION_STOP = 'stop';

/* What the page holds before the first poll answers. The idle contract
   reports nulls beside a zero row count; these are the same absences in the
   types the page renders. */
export const RECORDING_IDLE = Object.freeze({
  active: false,
  file: '',
  subnet: '',
  rows: 0,
  detail: '',
});

export const SUBNET_QUERY_PARAM = 'subnet';
export const SUBNET_STORAGE_KEY = 'netmon.subnet';

/* Comfortably past the longest real CIDR - a full IPv6 address plus its
   prefix - so only obvious junk read back out of storage is turned away. */
export const MAX_SUBNET_CHARS = 64;

/* capture.state values this page reacts to. Every other value - including
   ones a later phase invents - falls through to the warning banner, which is
   the entire reason the field carries a human-readable detail string. */
export const CAPTURE_STATE_OK = 'ok';
export const CAPTURE_STATE_MOCK = 'mock';

export const CONNECTION_CONNECTING = 'connecting';
export const CONNECTION_LIVE = 'live';
export const CONNECTION_DISCONNECTED = 'disconnected';

/* Axis ticks as fractions across the graph column, widest set first: oldest,
   midpoint, now. Each set keeps `now`, so the label that survives thinning is
   the one every trace is read from. */
export const AXIS_TICK_SETS = Object.freeze([
  Object.freeze([0, 0.5, 1]),
  Object.freeze([0, 1]),
  Object.freeze([1]),
]);

/* Clear space wanted between neighbouring axis labels before they read as
   one run of characters. */
export const AXIS_TICK_GAP_PX = 8;

export const GRAPH_TOP_PAD_PX = 4;
export const GRAPH_LINE_WIDTH_PX = 1;
export const GRAPH_TOTAL_LINE_WIDTH_PX = 2;
export const MIN_Y_SCALE_PPS = 1;

export const TEXT = Object.freeze({
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
