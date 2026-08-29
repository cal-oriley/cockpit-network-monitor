/*
 * Recording happens on the server, so the button is only a control: every
 * poll re-reads what the server says it is doing and the page renders that.
 * Nothing here remembers having pressed the button, which is what makes a
 * reload, a second tab, and a recording someone else started all read
 * correctly - and what makes a 409 nothing to argue with.
 */

import { RECORDING_IDLE, RECORD_ACTION_START, RECORD_ACTION_STOP, TEXT } from './constants.js';
import { els } from './elements.js';
import { fileName } from './format.js';
import { normalizeRecording, postRecord } from './api.js';
import { getRequestedSubnet, getViewedSubnet } from './header.js';

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

/** Adopt the recording the latest payload reports and render it. */
export function applyRecordingStatus(recording) {
  recordingState = normalizeRecording(recording);
  renderRecording();
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

  const viewedSubnet = getViewedSubnet();
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
 * Start or stop recording, whichever the last reported state calls for, and
 * adopt whatever the server reports back.
 *
 * A start is fixed to the subnet being asked for, which is the one on screen:
 * clicking the button blurs the subnet field first, so an edit not yet
 * committed has already been by the time this reads it.
 */
async function toggleRecording() {
  if (recordRequestInFlight) return;
  const requestedSubnet = getRequestedSubnet();
  const body = recordingState.active
    ? { action: RECORD_ACTION_STOP }
    : {
        action: RECORD_ACTION_START,
        subnet: requestedSubnet !== null ? requestedSubnet : getViewedSubnet(),
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

export function initRecordControl() {
  els.record.addEventListener('click', toggleRecording);
  renderRecording();
}
