/*
 * The elements the document ships with, looked up once. Everything the page
 * builds while it runs - cards, canvases, axis ticks - is created and held by
 * whichever module owns it.
 */

export const els = Object.freeze({
  subnet: document.getElementById('subnet'),
  subnetError: document.getElementById('subnet-error'),
  hostIp: document.getElementById('host-ip'),
  deviceCount: document.getElementById('device-count'),
  mockTag: document.getElementById('mock-tag'),
  connection: document.getElementById('connection'),
  connectionLabel: document.getElementById('connection-label'),
  record: document.getElementById('record'),
  recordLabel: document.getElementById('record-label'),
  recordStatus: document.getElementById('record-status'),
  recordState: document.getElementById('record-state'),
  recordFile: document.getElementById('record-file'),
  recordRows: document.getElementById('record-rows'),
  recordNote: document.getElementById('record-note'),
  banner: document.getElementById('banner'),
  emptyState: document.getElementById('empty-state'),
  rows: document.getElementById('rows'),
  axis: document.getElementById('axis'),
});
