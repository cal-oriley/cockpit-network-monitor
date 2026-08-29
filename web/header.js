/*
 * The header strip: what the page reports about itself - the connection, the
 * host, the device count and the capture-status banner - and the subnet field,
 * which is the one thing up there that chooses what is watched.
 */

import {
  CAPTURE_STATE_MOCK,
  CAPTURE_STATE_OK,
  CONNECTION_CONNECTING,
  MAX_SUBNET_CHARS,
  SUBNET_STORAGE_KEY,
  TEXT,
} from './constants.js';
import { els } from './elements.js';

let connectionState = CONNECTION_CONNECTING;

/** Subnet sent as `?subnet=`; `null` leaves the choice to the server. */
let requestedSubnet = loadStoredSubnet();

/** Subnet the last readable payload was filtered to, so a recording of some
    other subnet can be spotted and said out loud. */
let viewedSubnet = null;

/** Run when the field commits a subnet, to bring the next poll forward to it. */
let onSubnetCommitted = () => {};

export function getConnectionState() {
  return connectionState;
}

export function setConnection(state) {
  if (state === connectionState) return;
  connectionState = state;
  els.connection.dataset.state = state;
  els.connectionLabel.textContent = TEXT.connection[state];
}

export function updateHeader(payload, deviceCount) {
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
export function renderCaptureStatus(capture) {
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

export function getRequestedSubnet() {
  return requestedSubnet;
}

export function getViewedSubnet() {
  return viewedSubnet;
}

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
export function acceptSubnet(subnet) {
  if (typeof subnet !== 'string' || !subnet) return;
  viewedSubnet = subnet;
  if (document.activeElement !== els.subnet) els.subnet.value = subnet;
  if (requestedSubnet === null) return;
  requestedSubnet = subnet;
  storeSubnet(subnet);
}

export function showSubnetError(sentence) {
  els.subnetError.textContent = sentence;
  els.subnetError.hidden = false;
  els.subnet.setAttribute('aria-invalid', 'true');
}

export function clearSubnetError() {
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
  onSubnetCommitted();
}

export function initSubnetControl(onCommitted) {
  onSubnetCommitted = onCommitted;

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
