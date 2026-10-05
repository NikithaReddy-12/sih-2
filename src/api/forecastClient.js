/** Browser client for the existing forecast routes. No extra fields are added. */

async function readJson(response) {
  const text = await response.text();
  let body = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = null;
  }
  if (!response.ok) {
    throw new Error(detailMessage(body && body.detail, response.status));
  }
  return body;
}

function detailMessage(detail, status) {
  if (typeof detail === 'string' && detail.trim()) return detail;
  if (Array.isArray(detail)) {
    const parts = detail.map((item) => {
      if (typeof item === 'string') return item;
      if (item && typeof item.msg === 'string') return item.msg;
      return '';
    }).filter(Boolean);
    if (parts.length) return parts.join(' ');
  }
  return `Forecast request failed (${status}).`;
}

export function postCicidsForecast(file, horizonK) {
  const body = new FormData();
  body.append('file', file);
  return fetch(`/api/forecast/cicids?horizon_k=${encodeURIComponent(horizonK)}`, {
    method: 'POST',
    body,
  }).then(readJson);
}

export function postHostForecast(file, horizonK) {
  const body = new FormData();
  body.append('file', file);
  return fetch(`/api/forecast/netflow-v3-host?horizon_k=${encodeURIComponent(horizonK)}`, {
    method: 'POST',
    body,
  }).then(readJson);
}

export function postForecastFile(file, horizonK) {
  const name = String(file?.name || '').toLowerCase();
  if (name.endsWith('.pcap') || name.endsWith('.pcapng')) {
    return postHostForecast(file, horizonK);
  }
  return postCicidsForecast(file, horizonK);
}

export function getForecastStatus() {
  return fetch('/api/forecast/status').then(readJson);
}

export function getSamples() {
  return fetch('/api/samples').then(readJson);
}

export async function fetchSampleFile(name) {
  const response = await fetch(`/api/samples/${encodeURIComponent(name)}`);
  if (!response.ok) {
    const text = await response.text();
    let body = null;
    try { body = text ? JSON.parse(text) : null; } catch { body = null; }
    throw new Error(detailMessage(body && body.detail, response.status));
  }
  const blob = await response.blob();
  return new File([blob], name, { type: blob.type || 'application/octet-stream' });
}

export function getDemoForecast(horizonK) {
  return fetch(`/api/forecast/demo?k=${encodeURIComponent(horizonK)}`).then(readJson);
}

export function getBenchmark() {
  return fetch('/api/benchmark').then(readJson);
}
