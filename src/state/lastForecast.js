let latestForecast = null;
let latestLabels = new Map();
const listeners = new Set();

export function getLastForecast() {
  return latestForecast;
}

export function setLastForecast(forecast, labels = []) {
  latestForecast = forecast;
  latestLabels = new Map(
    (Array.isArray(labels) ? labels : [])
      .filter((row) => row?.host != null && row?.stage != null)
      .map((row) => [String(row.host).trim(), row.stage]),
  );
  listeners.forEach((listener) => listener(latestForecast));
}

export function getLastForecastLabel(host) {
  return latestLabels.get(String(host ?? '').trim()) ?? null;
}

export function subscribeLastForecast(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function flaggedHostCount(forecast = latestForecast) {
  if (!forecast) return 0;
  return new Set([
    ...(Array.isArray(forecast.current_hosts) ? forecast.current_hosts : []),
    ...(Array.isArray(forecast.hosts) ? forecast.hosts : []),
  ].map((host) => host?.host).filter(Boolean)).size;
}
