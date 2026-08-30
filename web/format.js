/*
 * How the numbers the server reports become the short strings a small panel
 * has room for. Nothing here touches the page; the strings themselves live
 * beside the rest of the page's vocabulary in constants.js.
 */

/* Both, because the server reports a native absolute path. */
const PATH_SEPARATORS = /[\\/]/;

export function numberOr(value, fallback) {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback;
}

/** Sub-1 rates keep a decimal so a trickle does not read as a flat zero. */
export function formatRate(pps) {
  const rate = Math.max(0, numberOr(pps, 0));
  return rate > 0 && rate < 1 ? rate.toFixed(1) : String(Math.round(rate));
}

export function formatSeconds(seconds) {
  return Number.isInteger(seconds) ? String(seconds) : seconds.toFixed(1);
}

/**
 * The name at the end of a path.
 *
 * Recordings are reported by absolute path, since where they land must not
 * depend on anyone's working directory, but only the name is shown: a full
 * path is far wider than the panel this page has to survive being squeezed
 * into, and the directory is the same for every recording anyway.
 */
export function fileName(path) {
  const parts = String(path).split(PATH_SEPARATORS);
  return parts[parts.length - 1];
}
