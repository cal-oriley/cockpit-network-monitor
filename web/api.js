/*
 * Every request the page makes, and how the answers are read. Both endpoints
 * refuse in the same `{error}` shape and both are given the same timeout, so
 * a server that has gone quiet is a failed poll rather than a page that hangs.
 */

import {
  HTTP_BAD_REQUEST,
  HTTP_CONFLICT,
  JSON_CONTENT_TYPE,
  RATES_URL,
  RECORD_URL,
  REQUEST_TIMEOUT_MS,
  SUBNET_QUERY_PARAM,
  TEXT,
} from './constants.js';
import { numberOr } from './format.js';

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
export async function fetchRates(subnet) {
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

/**
 * Read the contract's `recording` object into the shapes the page renders.
 *
 * A payload with no `recording` at all - which is what a server too old to
 * record looks like - reads as not recording, exactly as a missing `capture`
 * reads as `ok`. An idle status is read out in full rather than discarded,
 * because a recording that ended in failure keeps its reason there.
 */
export function normalizeRecording(recording) {
  const status = recording && typeof recording === 'object' ? recording : {};
  return {
    active: status.active === true,
    file: typeof status.file === 'string' ? status.file : '',
    subnet: typeof status.subnet === 'string' ? status.subnet : '',
    rows: Math.max(0, Math.round(numberOr(status.rows, 0))),
    detail: typeof status.detail === 'string' ? status.detail.trim() : '',
  };
}

/**
 * @returns {Promise<{recording: object}|{error: string}>} A 409 is read as a
 * recording rather than an error, since its body is the recording that won
 * the race. Anything else the server refuses arrives as a sentence.
 */
export async function postRecord(body) {
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
